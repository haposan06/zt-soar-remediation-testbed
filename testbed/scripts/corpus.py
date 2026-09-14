#!/usr/bin/env python3
"""
Monash thesis lab - 14-day simulated corpus generator.

Drives real PostgreSQL sessions through the Teleport proxy so that Teleport
emits genuine db.session.query audit events. Produces:

  * a benign baseline of ~48,000 query events across a 14-day simulated window,
    weighted app_service > analyst_ro > proc_officer > dba, varying by weekday,
    concentrated in 08:00-17:00 with an evening/weekend tail;
  * 60 malicious statements across 12 sessions (4 per attack class);
  * ~6 "benign-alerting" (B1) sessions that are legitimate but trip the rules.

TIMELINE. The lab executes in minutes, so every statement carries a SIMULATED
timestamp (day 1..14, hour, minute). The simulated clock is the analytic
timeline; Teleport's own event `time` is wall clock. The two are joined by a
marker comment appended to every statement:

    ... /*lab:<run>:<seq>*/

Teleport records db_query verbatim including that comment, so the join is exact
rather than time-window guesswork. collect_audit.py strips it for display.

SAFETY: TELEPORT_HOME is pinned to <lab>/tsh-home and --proxy is always
localhost:3080. The operator's own ~/.tsh profile (which may be logged into an
unrelated cluster) is never read or written.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import json
import os
import random
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import psycopg2
except ImportError:
    sys.exit("psycopg2 required: python3 -m pip install psycopg2-binary")

LAB_DIR = Path(__file__).resolve().parent.parent
IDENTITIES = LAB_DIR / "identities"
OUT_DIR = LAB_DIR / "out"
TSH = "/usr/local/bin/tsh"
PROXY = "localhost:3080"
DB_RESOURCE = "pg-lab"
DB_NAME = "procurement"
LAB_ENV = dict(os.environ, TELEPORT_HOME=str(LAB_DIR / "tsh-home"))

# Simulated window: day 1 is Monday 2026-08-03.
SIM_EPOCH = datetime(2026, 8, 3, tzinfo=timezone.utc)

# principal -> (teleport_user, db_role, source_ip, department, teleport_roles)
PRINCIPALS = {
    "app":       ("svc.app@eproc.test",        "app_service",  "10.20.1.10",
                  "Platform Engineering", ["app-service", "machine"]),
    "rina":      ("rina.hartono@eproc.test",   "analyst_ro",   "10.20.4.61",
                  "Finance Reporting", ["reporting-readonly", "sso-staff"]),
    "priya":     ("priya.suryani@eproc.test",  "analyst_ro",   "10.20.4.62",
                  "Finance Reporting", ["reporting-readonly", "sso-staff"]),
    "dave":      ("dave.wijaya@eproc.test",    "proc_officer", "10.20.3.21",
                  "Procurement", ["procurement-officer", "sso-staff"]),
    "nina":      ("nina.lestari@eproc.test",   "proc_officer", "10.20.3.22",
                  "Procurement", ["procurement-officer", "sso-staff"]),
    "carol":     ("carol.tan@eproc.test",      "dba",          "10.20.9.5",
                  "IT Operations", ["db-admin", "break-glass"]),
    "eve":       ("eve.contractor@eproc.test", "analyst_ro",   "10.20.7.88",
                  "External Contractor", ["reporting-readonly", "contractor"]),
}

# Benign volume mix (fractions of the benign target).
MIX = {"app_service": 0.70, "analyst_ro": 0.18, "proc_officer": 0.10, "dba": 0.02}
# Weekday shape: index 0=Mon .. 6=Sun.
DAY_FACTOR = [1.15, 1.10, 1.05, 1.00, 0.85, 0.12, 0.10]


def sim_ts(day: int, hour: int, minute: int, second: int = 0) -> datetime:
    return SIM_EPOCH + timedelta(days=day - 1, hours=hour, minutes=minute, seconds=second)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Stmt:
    sql: str
    sim: datetime
    label: str = "benign"          # benign | malicious | benign_alerting
    scenario: str = ""
    step: str = ""                 # attack step name, for hit-rate accounting


@dataclass
class Sess:
    principal: str
    sim_start: datetime
    kind: str                      # benign | malicious | benign_alerting
    scenario: str = ""
    attack_class: str = ""         # B0 | B1 | S1 | S2 | S3
    stmts: list = field(default_factory=list)
    change_window: dict | None = None
    note: str = ""


# ===================== benign statement generators ========================
def app_service_stmts(rng, n, base):
    """Parameterised OLTP traffic from the application pool."""
    out = []
    for i in range(n):
        r = rng.random()
        if r < 0.34:
            s = ("SELECT tender_id, reference_no, title, status FROM tenders "
                 f"WHERE status = '{rng.choice(['open','evaluating'])}' ORDER BY closes_at LIMIT 20")
        elif r < 0.56:
            s = ("SELECT bid_id, tender_id, vendor_id, status FROM bids "
                 f"WHERE tender_id = {rng.randrange(1,501)} ORDER BY bid_id LIMIT 50")
        elif r < 0.72:
            s = ("SELECT payment_id, invoice_no, amount, status FROM payments "
                 f"WHERE contract_id = {rng.randrange(1,601)} ORDER BY paid_at DESC LIMIT 25")
        elif r < 0.82:
            s = ("SELECT c.contract_id, c.awarded_amount, v.legal_name FROM contracts c "
                 "JOIN vendors v ON v.vendor_id = c.vendor_id "
                 f"WHERE c.contract_id = {rng.randrange(1,601)}")
        elif r < 0.90:
            s = ("INSERT INTO audit_log (occurred_at, db_user, teleport_user, session_id, action, "
                 "object_schema, object_name, row_count, statement_digest, client_addr) "
                 f"VALUES (now(), 'app_service', 'svc.app@eproc.test', '{uuid.uuid4()}', "
                 f"'{rng.choice(['SELECT','UPDATE','INSERT'])}', "
                 f"'public', 'tenders', {rng.randrange(1,50)}, md5('d{i}'), '10.20.1.10')")
        elif r < 0.96:
            s = ("UPDATE payments SET status = 'paid' "
                 f"WHERE payment_id = {rng.randrange(1,12001)} AND status = 'pending'")
        else:
            s = ("SELECT employee_id, full_name, department FROM employees "
                 f"WHERE employee_id = {rng.randrange(1,1201)}")
        out.append(s)
    return out


def analyst_stmts(rng, n):
    out = []
    for _ in range(n):
        r = rng.random()
        if r < 0.30:
            out.append("SELECT date_trunc('month', paid_at) AS m, sum(amount) AS total "
                       "FROM payments GROUP BY 1 ORDER BY 1 DESC LIMIT 12")
        elif r < 0.52:
            out.append("SELECT v.risk_rating, count(*) AS n, sum(c.awarded_amount) AS value "
                       "FROM contracts c JOIN vendors v USING (vendor_id) GROUP BY 1 ORDER BY 3 DESC LIMIT 10")
        elif r < 0.70:
            out.append("SELECT category, count(*) AS tenders, avg(budget_ceiling)::numeric(14,2) AS avg_ceiling "
                       "FROM tenders GROUP BY 1 ORDER BY 2 DESC LIMIT 10")
        elif r < 0.85:
            out.append("SELECT department, count(*) FROM employees_public GROUP BY 1 ORDER BY 2 DESC LIMIT 10")
        else:
            out.append("SELECT status, count(*) FROM bids_public GROUP BY 1 ORDER BY 2 DESC LIMIT 10")
    return out


def officer_stmts(rng, n):
    out = []
    for _ in range(n):
        r = rng.random()
        tid = rng.randrange(1, 501)
        if r < 0.34:
            out.append(f"SELECT tender_id, reference_no, title, status FROM tenders WHERE tender_id = {tid}")
        elif r < 0.58:
            out.append("SELECT bid_id, vendor_id, status, submitted_at FROM bids "
                       f"WHERE tender_id = {tid} ORDER BY submitted_at LIMIT 40")
        elif r < 0.74:
            out.append(f"UPDATE tenders SET status = 'evaluating' WHERE tender_id = {tid} AND status = 'open'")
        elif r < 0.86:
            out.append(f"UPDATE bids SET status = 'shortlisted' WHERE bid_id = {rng.randrange(1,6001)}")
        else:
            out.append("SELECT vendor_id, legal_name, risk_rating FROM vendors "
                       f"WHERE risk_rating = '{rng.choice(['low','medium'])}' LIMIT 25")
    return out


def dba_stmts(rng, n):
    out = []
    for _ in range(n):
        r = rng.random()
        if r < 0.30:
            out.append("SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 10")
        elif r < 0.55:
            out.append("SELECT count(*) FROM pg_stat_activity")
        elif r < 0.75:
            out.append("SELECT pg_size_pretty(pg_database_size('procurement')) AS db_size")
        elif r < 0.90:
            out.append("SELECT schemaname, relname, idx_scan FROM pg_stat_user_indexes ORDER BY idx_scan LIMIT 10")
        else:
            out.append("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1")
    return out


ROLE_GEN = {
    "app_service": lambda rng, n: app_service_stmts(rng, n, None),
    "analyst_ro": analyst_stmts,
    "proc_officer": officer_stmts,
    "dba": dba_stmts,
}
ROLE_PRINCIPALS = {
    "app_service": ["app"],
    "analyst_ro": ["rina", "priya"],
    "proc_officer": ["dave", "nina"],
    "dba": ["carol"],
}


def pick_hour(rng) -> tuple[int, int]:
    """Working hours 08-17 dominate, with an evening and overnight tail."""
    r = rng.random()
    if r < 0.86:
        h = rng.choices(range(8, 18), weights=[6,9,11,12,10,8,11,12,9,6])[0]
    elif r < 0.97:
        h = rng.choice([18, 19, 20, 21])
    else:
        h = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 22, 23])
    return h, rng.randrange(0, 60)


def build_benign(rng, days: int, target: int) -> list[Sess]:
    """Spread `target` benign statements over `days`, shaped by weekday."""
    factors = [DAY_FACTOR[(d - 1) % 7] for d in range(1, days + 1)]
    tot = sum(factors)
    sessions: list[Sess] = []

    for role, frac in MIX.items():
        role_total = int(round(target * frac))
        for di, day in enumerate(range(1, days + 1)):
            n_day = int(round(role_total * factors[di] / tot))
            if n_day <= 0:
                continue
            # session size varies by role; app_service runs long pooled sessions
            per = {"app_service": 220, "analyst_ro": 45, "proc_officer": 30, "dba": 12}[role]
            n_sess = max(1, round(n_day / per))
            for _ in range(n_sess):
                cnt = max(1, int(rng.gauss(n_day / n_sess, n_day / n_sess * 0.25)))
                h, m = pick_hour(rng)
                who = rng.choice(ROLE_PRINCIPALS[role])
                start = sim_ts(day, h, m)
                sql = ROLE_GEN[role](rng, cnt)
                s = Sess(principal=who, sim_start=start, kind="benign",
                         scenario=f"{role} routine", attack_class="B0")
                for i, q in enumerate(sql):
                    s.stmts.append(Stmt(q, start + timedelta(seconds=i * rng.randrange(3, 25)), "benign", "B0"))
                sessions.append(s)
    return sessions


# ========================= attack scenarios ===============================
def build_malicious(rng) -> list[Sess]:
    """12 sessions, 4 per class, 60 statements total.

    Class letters follow the CANONICAL thesis mapping
    (thesis/chapters/03-methodology.tex, thesis/appendices/A-scenario-catalogue.tex):
      B0 routine baseline, B1 benign but alerting,
      S1 data harvesting / exfiltration,
      S2 privilege escalation,
      S3 destructive or obfuscated SQL by an authorised user.
    The rule-id families are named for behaviour, not class: PG-TAMP-* and
    PG-ANTIF-001 both sit in S3. Nothing here emits S2 for a destructive
    statement.

    Within each class the four sessions carry 3, 4, 6 and 7 statements so the
    alert set spans a range of evidence volume.
    """
    S: list[Sess] = []

    def mk(principal, day, hour, minute, scenario, cls, note, queries, gap):
        s = Sess(principal, sim_ts(day, hour, minute), "malicious", scenario, cls, note=note)
        for i, q in enumerate(queries):
            s.stmts.append(Stmt(q, s.sim_start + timedelta(minutes=i * gap),
                                "malicious", cls, f"{cls.lower()}{len(S)}_{i}"))
        S.append(s)

    # ================= S1 data harvesting / exfiltration (PG-EXF-*) =========
    # 3 statements - smallest evidence volume. analyst_ro may read vendors, so
    # this executes: the abuse is the scope, not the permission.
    mk("eve", 2, 22, 14, "S1 data harvesting: vendor banking sweep", "S1",
       "contractor account reads every vendor tax_id and bank_account at 22:14",
       ["SELECT current_user, session_user",
        "SELECT vendor_id, legal_name, tax_id, bank_account FROM vendors",
        "SELECT vendor_id, legal_name, tax_id, bank_account, owner_name FROM vendors ORDER BY vendor_id"],
       3)

    # 4 statements - payments sweep plus COPY egress.
    mk("eve", 5, 23, 5, "S1 data harvesting: payment records exfiltration", "S1",
       "sweeps payment bank_account_snapshot values then streams the table out over COPY",
       ["SELECT count(*) FROM payments",
        "SELECT payment_id, invoice_no, amount, bank_account_snapshot FROM payments",
        "SELECT p.payment_id, p.bank_account_snapshot, v.legal_name, v.bank_account "
        "FROM payments p JOIN contracts c USING (contract_id) JOIN vendors v USING (vendor_id)",
        "COPY (SELECT payment_id, invoice_no, amount, bank_account_snapshot FROM payments) "
        "TO STDOUT WITH CSV HEADER"],
       4)

    # 6 statements - paginated harvest of the base employees table using the
    # application service credential, which legitimately holds SELECT there.
    q = ["SELECT count(*) FROM employees"]
    q += [f"SELECT employee_id, full_name, email, salary, national_id, bank_account "
          f"FROM employees ORDER BY employee_id LIMIT 300 OFFSET {o}" for o in (0, 300, 600, 900)]
    q += ["COPY (SELECT employee_id, national_id, bank_account, salary FROM employees) "
          "TO STDOUT WITH CSV HEADER"]
    mk("app", 9, 2, 40, "S1 data harvesting: paginated employee export", "S1",
       "stolen service-account credential paginating the base employees table at 02:40",
       q, 5)

    # 7 statements - largest evidence volume: sustained, paginated, multi-table.
    q = ["SELECT current_user, inet_client_addr()"]
    q += [f"SELECT payment_id, contract_id, amount, bank_account_snapshot FROM payments "
          f"ORDER BY payment_id LIMIT 2500 OFFSET {o}" for o in (0, 2500, 5000, 7500, 10000)]
    q += ["COPY (SELECT * FROM payments) TO STDOUT WITH CSV HEADER"]
    mk("eve", 12, 1, 15, "S1 data harvesting: sustained paginated exfiltration", "S1",
       "longest S1 session: five paginated pages over payments then a full COPY egress",
       q, 6)

    # ================= S2 privilege escalation (PG-PRIV-*) ==================
    # 3 statements. eve holds analyst_ro, so PostgreSQL refuses the GRANT -
    # Teleport still records it. This is the finding-5 case, kept deliberately.
    mk("eve", 4, 23, 40, "S2 privilege escalation: attempted self-grant", "S2",
       "contractor attempts to grant itself the base employees table; PostgreSQL denies, "
       "Teleport records the attempt as a successful RBAC decision",
       ["SELECT current_user",
        "GRANT SELECT ON public.employees TO analyst_ro",
        "SELECT count(*) FROM employees"],
       2)

    # 4 statements
    mk("carol", 7, 22, 10, "S2 privilege escalation: role promoted to superuser", "S2",
       "analyst_ro promoted to SUPERUSER outside any change window, then reverted",
       ["SELECT rolname, rolsuper FROM pg_roles ORDER BY rolsuper DESC LIMIT 10",
        "ALTER ROLE analyst_ro SUPERUSER",
        "SELECT rolname, rolsuper FROM pg_roles WHERE rolname = 'analyst_ro'",
        "ALTER ROLE analyst_ro NOSUPERUSER"],
       3)

    # 6 statements
    mk("carol", 10, 1, 45, "S2 privilege escalation: shadow role creation", "S2",
       "creates a parallel login role with equivalent rights and default privileges",
       ["SELECT rolname FROM pg_roles WHERE rolcanlogin ORDER BY rolname",
        "CREATE ROLE svc_reporting LOGIN",
        "GRANT analyst_ro TO svc_reporting",
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO svc_reporting",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO svc_reporting",
        "DROP OWNED BY svc_reporting; DROP ROLE svc_reporting"],
       4)

    # 7 statements - largest S2 session, escalation finished with anti-forensics.
    mk("carol", 14, 0, 30, "S2 privilege escalation: escalate then cover tracks", "S2",
       "largest S2 session: superuser role creation, blanket grants, default privileges, "
       "then the in-database audit trail is scrubbed",
       ["SELECT current_user, session_user",
        "CREATE ROLE bd_admin LOGIN SUPERUSER",
        "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO bd_admin",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO bd_admin",
        "DELETE FROM audit_log WHERE action = 'UPDATE'",
        "UPDATE audit_log SET action = 'SELECT' WHERE action = 'INSERT'",
        "DROP OWNED BY bd_admin; DROP ROLE bd_admin"],
       3)

    # ======= S3 destructive or obfuscated SQL (PG-TAMP-*, PG-ANTIF-001) =====
    # 3 statements - unpredicated DELETE against the in-database audit trail.
    mk("carol", 6, 21, 30, "S3 destructive SQL: unpredicated delete of the audit trail", "S3",
       "DELETE with no WHERE clause wipes the in-database audit_log",
       ["SELECT count(*) FROM audit_log",
        "DELETE FROM audit_log",
        "SELECT count(*) FROM audit_log"],
       2)

    # 4 statements - mass tampering with sealed bid values.
    mk("dave", 8, 19, 50, "S3 destructive SQL: mass bid value tampering", "S3",
       "procurement officer rewrites sealed bid amounts and inflates one vendor's scores",
       ["SELECT bid_id, bid_amount, technical_score FROM bids ORDER BY bid_amount DESC LIMIT 10",
        "UPDATE bids SET bid_amount = bid_amount * 0.85 WHERE sealed_until > now()",
        "UPDATE bids SET technical_score = 99.00 WHERE vendor_id BETWEEN 1 AND 40",
        "SELECT count(*) FROM bids WHERE technical_score = 99.00"],
       3)

    # 6 statements - the same destructive intent, obfuscated three ways.
    mk("carol", 11, 3, 20, "S3 destructive SQL: obfuscated statements", "S3",
       "destructive intent re-expressed with chr() concatenation, inline comment splicing "
       "and mixed-case keyword mangling; the comment-spliced form is rejected by PostgreSQL "
       "but is still recorded by Teleport",
       ["SELECT chr(112)||chr(103)||chr(95)||chr(100)||chr(98) AS tag",
        "sElEcT count(*) FROM payments",
        "uPdAtE bids SET status = 'withdrawn' WHERE bid_id BETWEEN 1 AND 600",
        "DEL/**/ETE FROM audit_log WHERE audit_id < 5",
        "SELECT chr(100)||chr(114)||chr(111)||chr(112) AS tag",
        "dRoP TABLE IF EXISTS public.bids_scratch"],
       4)

    # 7 statements - largest S3 session: mass update, delete, truncate, drop.
    mk("carol", 13, 2, 5, "S3 destructive SQL: mass update, truncate and drop chain", "S3",
       "largest S3 session: unpredicated mass update of payment bank details, bulk delete, "
       "then TRUNCATE and DROP of the bids archive and a scrub of the audit trail",
       ["SELECT count(*) FROM payments",
        "UPDATE payments SET bank_account_snapshot = '99887766'",
        "DELETE FROM payments WHERE status = 'failed'",
        "SELECT count(*) FROM public.bids_archive",
        "TRUNCATE TABLE public.bids_archive",
        "DROP TABLE public.bids_archive",
        "DELETE FROM audit_log WHERE db_user = 'app_service'"],
       3)

    return S


def build_benign_alerting(rng) -> list[Sess]:
    """Six legitimate sessions that a rule cannot tell apart from an attack.

    Class B1. Every one of these is authorised, ticketed and inside its stated
    change window, but each deliberately reproduces the surface behaviour of one
    of the attack classes so the false-positive rate is measurable.
    """
    S: list[Sess] = []

    def mk(principal, day, hour, minute, scenario, note, cw, queries, gap):
        s = Sess(principal, sim_ts(day, hour, minute), "benign_alerting", scenario, "B1",
                 change_window=cw, note=note)
        for i, q in enumerate(queries):
            s.stmts.append(Stmt(q, s.sim_start + timedelta(minutes=i * gap),
                                "benign_alerting", "B1", f"b1{len(S)}_{i}"))
        S.append(s)

    def cw(ticket, approver, d1, h1, d2, h2):
        return {"ticket": ticket, "approved_by": approver,
                "starts_at": iso(sim_ts(d1, h1, 0)), "ends_at": iso(sim_ts(d2, h2, 0))}

    # 1. Approved quarterly export, out of hours, paginated - looks like S1.
    q = ["SELECT count(*) FROM payments"]
    q += [f"SELECT payment_id, contract_id, invoice_no, amount, paid_at, status FROM payments "
          f"ORDER BY payment_id LIMIT 2000 OFFSET {o}"
          for o in (0, 2000, 4000, 6000, 8000, 10000)]
    mk("rina", 3, 3, 0, "B1 approved quarterly finance export",
       "signed-off quarterly extract for the finance committee; scheduled at 03:00 "
       "specifically to avoid business-hours load",
       cw("CHG-2026-0412", "finance.director@eproc.test", 3, 2, 3, 6), q, 4)

    # 2. Approved COPY extract for the external auditor - looks like S1.
    mk("priya", 3, 4, 30, "B1 approved external audit extract",
       "contractually required annual audit pack for the external auditor",
       cw("CHG-2026-0415", "internal.audit@eproc.test", 3, 4, 3, 7),
       ["SELECT count(*) FROM contracts",
        "COPY (SELECT contract_id, tender_id, vendor_id, awarded_amount, status FROM contracts) "
        "TO STDOUT WITH CSV HEADER",
        "COPY (SELECT vendor_id, legal_name, risk_rating FROM vendors) TO STDOUT WITH CSV HEADER"],
       5)

    # 3. Authorised GRANT inside a maintenance window - looks like S2.
    mk("carol", 6, 1, 0, "B1 authorised grant in maintenance window",
       "approved access request for the new reporting dashboard, executed inside the "
       "published Saturday maintenance window",
       cw("CHG-2026-0421", "it.change.board@eproc.test", 6, 0, 6, 3),
       ["SELECT rolname FROM pg_roles WHERE rolname = 'analyst_ro'",
        "GRANT SELECT ON public.contracts TO analyst_ro",
        "SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants "
        "WHERE grantee = 'analyst_ro' LIMIT 20"],
       4)

    # 4. Authorised joiner provisioning - looks like S2.
    mk("carol", 6, 2, 0, "B1 authorised new starter provisioning",
       "HR joiner process for a new reporting analyst; the temporary role is removed "
       "again once the permanent account is issued",
       cw("CHG-2026-0422", "hr.systems@eproc.test", 6, 0, 6, 3),
       ["CREATE ROLE starter_tmp LOGIN",
        "GRANT analyst_ro TO starter_tmp",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO starter_tmp",
        "DROP OWNED BY starter_tmp; DROP ROLE starter_tmp"],
       3)

    # 5. Approved remuneration review extract - looks like S1.
    mk("carol", 10, 20, 0, "B1 approved salary banding review",
       "annual remuneration review extract requested in writing by the HR director",
       cw("CHG-2026-0427", "hr.director@eproc.test", 10, 19, 10, 22),
       ["SELECT count(*) FROM employees",
        "SELECT employee_id, department, position, salary FROM employees",
        "SELECT department, avg(salary)::numeric(12,2) FROM employees GROUP BY 1 ORDER BY 2 DESC"],
       6)

    # 6. Scheduled retention purge - looks like S3.
    mk("carol", 13, 23, 15, "B1 scheduled data retention purge",
       "monthly records-management purge under the seven-year retention policy",
       cw("CHG-2026-0430", "records.management@eproc.test", 13, 23, 14, 2),
       ["SELECT count(*) FROM payments WHERE paid_at < now() - interval '700 days'",
        "DELETE FROM payments WHERE paid_at < now() - interval '700 days'",
        "SELECT count(*) FROM payments"],
       5)

    return S


# =============================== driver ===================================
def wait_port(port, timeout=30.0):
    end = time.time() + timeout
    while time.time() < end:
        with contextlib.closing(socket.socket()) as s:
            s.settimeout(1.0)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


class Tunnel:
    """One `tsh proxy db --tunnel` per (principal, db_role), reused for many
    sessions. Each new TCP connection through it is a separate Teleport
    database session, so tunnel setup cost is paid once, not per session."""

    def __init__(self, key, teleport_user, db_role, port):
        self.key, self.db_role, self.port = key, db_role, port
        ident = IDENTITIES / f"{teleport_user}.pem"
        if not ident.exists():
            raise FileNotFoundError(f"missing identity {ident}; run scripts/setup.sh")
        self.proc = subprocess.Popen(
            [TSH, "-i", str(ident), "--proxy", PROXY, "--insecure", "proxy", "db", "--tunnel",
             f"--db-user={db_role}", f"--db-name={DB_NAME}", f"--port={port}", DB_RESOURCE],
            env=LAB_ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if not wait_port(port):
            self.close()
            raise RuntimeError(f"tunnel for {teleport_user}/{db_role} did not open")

    def close(self):
        with contextlib.suppress(Exception):
            self.proc.terminate(); self.proc.wait(timeout=10)


def reseed_database() -> None:
    """Restore the testbed to its seeded state before generating.

    Run through `docker exec ... psql` on the container's local socket, NOT
    through Teleport, so that housekeeping produces no audit events and every
    event in the corpus belongs to a labelled statement.
    """
    init = (LAB_DIR / "postgres" / "init.sql").read_text()
    r = subprocess.run(
        ["docker", "exec", "-i", "thesis-postgres",
         "psql", "-v", "ON_ERROR_STOP=1", "-q", "-U", "postgres", "-d", DB_NAME, "-f", "-"],
        input=init, text=True, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError("reseed failed:\n" + (r.stderr or r.stdout)[-3000:])
    print("reseeded procurement from postgres/init.sql (no Teleport events emitted)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--benign-target", type=int, default=48000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dry-run", action="store_true", help="plan only, execute nothing")
    ap.add_argument("--no-reseed", action="store_true", help="skip the pre-run database reseed")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    sessions = build_benign(rng, args.days, args.benign_target)
    sessions += build_malicious(rng)
    sessions += build_benign_alerting(rng)
    sessions.sort(key=lambda s: s.sim_start)

    total_stmts = sum(len(s.stmts) for s in sessions)
    mal = sum(len(s.stmts) for s in sessions if s.kind == "malicious")
    b1 = sum(len(s.stmts) for s in sessions if s.kind == "benign_alerting")
    print(f"plan: {len(sessions)} sessions, {total_stmts} statements "
          f"(malicious={mal}, benign_alerting={b1}, benign={total_stmts-mal-b1})")
    print(f"      projected base rate = {100*mal/total_stmts:.4f}%")
    if args.dry_run:
        return 0

    if not args.no_reseed:
        reseed_database()

    run = uuid.uuid4().hex[:8]
    tunnels: dict[tuple, Tunnel] = {}
    port = 15600
    gt_path = OUT_DIR / "ground_truth.jsonl"
    sess_path = OUT_DIR / "sessions.csv"
    gt = gt_path.open("w")
    scsv = sess_path.open("w", newline="")
    sw = csv.DictWriter(scsv, fieldnames=[
        "run_id", "seq", "kind", "attack_class", "scenario", "teleport_user", "db_role",
        "source_ip", "sim_start", "sim_end", "sim_day", "sim_hour", "statements",
        "executed", "denied_by_postgres", "teleport_sid", "change_ticket", "note"])
    sw.writeheader()

    seq = 0
    t0 = time.time()
    done = 0
    try:
        for si, s in enumerate(sessions):
            tu, role, ip, dept, troles = PRINCIPALS[s.principal]
            key = (tu, role)
            if key not in tunnels:
                tunnels[key] = Tunnel(key, tu, role, port); port += 1
            tun = tunnels[key]

            try:
                conn = psycopg2.connect(host="127.0.0.1", port=tun.port, user=role,
                                        dbname=DB_NAME, sslmode="disable", connect_timeout=20)
                conn.autocommit = True
            except Exception as e:
                print(f"  ! connect failed {tu}/{role}: {str(e)[:90]}")
                continue

            # No unmarked probe query is issued here: every statement sent down
            # this connection must be attributable, or it would show up in the
            # audit log as an unlabelled corpus event and skew the base rate.
            sid = None

            executed = denied = 0
            for st in s.stmts:
                seq += 1
                marker = f"/*lab:{run}:{seq}*/"
                sql = f"{st.sql} {marker}"
                rows = 0
                err = None
                cur = conn.cursor()
                a = time.time()
                try:
                    if st.sql.strip().upper().startswith("COPY"):
                        import io
                        buf = io.StringIO()
                        cur.copy_expert(sql, buf)
                        rows = max(0, buf.getvalue().count("\n") - 1)
                    else:
                        cur.execute(sql)
                        if cur.description:
                            rows = len(cur.fetchall())
                        else:
                            rows = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
                    executed += 1
                except psycopg2.Error as e:
                    denied += 1
                    err = str(e).strip().splitlines()[0][:200]
                    with contextlib.suppress(Exception):
                        conn.rollback()
                finally:
                    dur = (time.time() - a) * 1000.0
                    with contextlib.suppress(Exception):
                        cur.close()
                gt.write(json.dumps({
                    "run_id": run, "seq": seq, "marker": marker,
                    "session_index": si, "kind": st.label, "attack_class": st.scenario or s.attack_class,
                    "scenario": s.scenario, "step": st.step,
                    "teleport_user": tu, "db_role": role, "source_ip": ip,
                    "department": dept, "teleport_roles": troles,
                    "sim_ts": iso(st.sim), "sim_day": (st.sim - SIM_EPOCH).days + 1,
                    "sim_hour": st.sim.hour,
                    "sql": st.sql, "rows": rows, "duration_ms": round(dur, 2),
                    "denied_by_postgres": err is not None, "pg_error": err,
                    "change_ticket": (s.change_window or {}).get("ticket"),
                }) + "\n")

            conn.close()
            sw.writerow({
                "run_id": run, "seq": si, "kind": s.kind, "attack_class": s.attack_class,
                "scenario": s.scenario, "teleport_user": tu, "db_role": role, "source_ip": ip,
                "sim_start": iso(s.sim_start),
                "sim_end": iso(s.stmts[-1].sim) if s.stmts else iso(s.sim_start),
                "sim_day": (s.sim_start - SIM_EPOCH).days + 1, "sim_hour": s.sim_start.hour,
                "statements": len(s.stmts), "executed": executed,
                "denied_by_postgres": denied, "teleport_sid": sid or "",
                "change_ticket": (s.change_window or {}).get("ticket") or "",
                "note": s.note,
            })
            done += 1
            if done % 25 == 0 or done == len(sessions):
                el = time.time() - t0
                print(f"  {done}/{len(sessions)} sessions, {seq} stmts, "
                      f"{seq/max(el,0.001):.0f} stmt/s, {el:.0f}s elapsed", flush=True)
    finally:
        gt.close(); scsv.close()
        for t in tunnels.values():
            t.close()

    # change windows sidecar (used by detect.py to build B1 alerts)
    cw = {s.scenario: s.change_window for s in sessions if s.change_window}
    (OUT_DIR / "change_windows.json").write_text(json.dumps(cw, indent=2) + "\n")

    el = time.time() - t0
    print(f"\nexecuted {seq} statements in {el:.1f}s ({seq/el:.0f} stmt/s)")
    print(f"ground truth : {gt_path}")
    print(f"sessions     : {sess_path}")
    print("next: python3 scripts/collect_audit.py && python3 scripts/detect.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

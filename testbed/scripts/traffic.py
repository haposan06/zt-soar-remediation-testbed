#!/usr/bin/env python3
"""
Monash thesis lab - synthetic PostgreSQL traffic through Teleport.

Every session is driven the same way a real operator would drive it:

    tsh -i <identity> --proxy=localhost:3080 --insecure \
        proxy db --tunnel --db-user=<u> --db-name=<d> --port=<p> pg-lab

...which opens an authenticated local TCP tunnel; psycopg2 then speaks plain
PostgreSQL to that port. Teleport therefore sees, parses and audits every
statement, producing genuine db.session.start / db.session.query /
db.session.end events (TDB00I / TDB02I / TDB01I) in ../audit/*.log.

Nothing here fabricates audit records - the logs are emitted by Teleport itself.

SAFETY: TELEPORT_HOME is forced to <lab>/tsh-home and --proxy is always
localhost:3080, so the operator's own ~/.tsh profile (which may be logged into
an unrelated cluster) is never touched.

Sidecar: writes ../out/sessions.csv mapping each real session to the *intended*
simulated hour-of-day, since the lab runs in a few minutes of wall-clock time.

Usage:
    python3 scripts/traffic.py --benign    [--seed 42]
    python3 scripts/traffic.py --malicious [--seed 7]
    python3 scripts/traffic.py --all
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import os
import random
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    import psycopg2
except ImportError:
    sys.exit("psycopg2 is required:  python3 -m pip install psycopg2-binary")

# --------------------------------------------------------------------------
LAB_DIR = Path(__file__).resolve().parent.parent
IDENTITIES = LAB_DIR / "identities"
OUT_DIR = LAB_DIR / "out"
SESSIONS_CSV = OUT_DIR / "sessions.csv"

TSH = "/usr/local/bin/tsh"
PROXY = "localhost:3080"
DB_RESOURCE = "pg-lab"

# Force lab isolation for every child tsh process.
LAB_ENV = dict(os.environ, TELEPORT_HOME=str(LAB_DIR / "tsh-home"))

PORT_BASE = 15500


# --------------------------------------------------------------------------
@dataclass
class Session:
    """One Teleport database session: a user, a db account, a query list."""
    actor: str            # Teleport user (identity file name)
    db_user: str          # PostgreSQL role
    db_name: str
    sim_hour: int         # intended hour-of-day (0-23) for the narrative
    label: str            # scenario label
    kind: str             # "benign" | "malicious"
    queries: list = field(default_factory=list)
    note: str = ""


def wait_for_port(port: int, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with contextlib.closing(socket.socket()) as s:
            s.settimeout(1.0)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.3)
    return False


@contextlib.contextmanager
def teleport_tunnel(actor: str, db_user: str, db_name: str, port: int):
    """Run `tsh proxy db --tunnel` for the duration of the block."""
    identity = IDENTITIES / f"{actor}.pem"
    if not identity.exists():
        raise FileNotFoundError(f"missing identity {identity}; run scripts/setup.sh")

    cmd = [
        TSH, "-i", str(identity), "--proxy", PROXY, "--insecure",
        "proxy", "db", "--tunnel",
        f"--db-user={db_user}", f"--db-name={db_name}",
        f"--port={port}", DB_RESOURCE,
    ]
    proc = subprocess.Popen(
        cmd, env=LAB_ENV,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        if not wait_for_port(port):
            proc.terminate()
            out = ""
            with contextlib.suppress(Exception):
                out = proc.communicate(timeout=5)[0] or ""
            raise RuntimeError(f"tunnel for {actor}/{db_user} never opened:\n{out}")
        yield
    finally:
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=10)


def run_session(s: Session, rng: random.Random, port: int, writer, verbose=True):
    """Execute one session end-to-end and record it in sessions.csv."""
    started = datetime.now(timezone.utc)
    run_id = str(uuid.uuid4())
    executed = denied_tp = denied_pg = 0
    outcome = "ok"

    tag = f"[{s.kind:9}] {s.actor:15} as {s.db_user:12} h{s.sim_hour:02d} {s.label}"
    if verbose:
        print(tag, flush=True)

    try:
        with teleport_tunnel(s.actor, s.db_user, s.db_name, port):
            conn = psycopg2.connect(
                host="127.0.0.1", port=port, user=s.db_user, dbname=s.db_name,
                sslmode="disable", connect_timeout=15,
            )
            conn.autocommit = True
            try:
                for q in s.queries:
                    cur = conn.cursor()
                    try:
                        cur.execute(q)
                        if cur.description:
                            cur.fetchall()
                        executed += 1
                    except psycopg2.Error as e:
                        # Postgres-level refusal (RBAC inside the database).
                        denied_pg += 1
                        if verbose:
                            print(f"      pg-denied: {str(e).strip().splitlines()[0][:90]}")
                    finally:
                        cur.close()
                    time.sleep(rng.uniform(0.05, 0.25))
            finally:
                conn.close()
    except Exception as e:
        # Teleport-level refusal (RBAC in the proxy) or tunnel failure.
        # This is a *wanted* outcome for the access-denied scenarios: it makes
        # Teleport emit db.session.start with code TDB00W.
        denied_tp = 1
        outcome = "teleport-denied"
        if verbose:
            print(f"      teleport-denied: {str(e).strip().splitlines()[0][:110]}")

    ended = datetime.now(timezone.utc)
    writer.writerow({
        "run_id": run_id,
        "kind": s.kind,
        "scenario": s.label,
        "teleport_user": s.actor,
        "db_user": s.db_user,
        "db_name": s.db_name,
        "simulated_hour": s.sim_hour,
        "simulated_time": f"{s.sim_hour:02d}:{rng.randrange(0, 60):02d}",
        "wallclock_start_utc": started.isoformat(timespec="milliseconds"),
        "wallclock_end_utc": ended.isoformat(timespec="milliseconds"),
        "queries_attempted": len(s.queries),
        "queries_executed": executed,
        "denied_by_postgres": denied_pg,
        "denied_by_teleport": denied_tp,
        "outcome": outcome,
        "note": s.note,
    })
    return outcome


# ============================ SCENARIOS ===================================
def benign_day(seed: int) -> list[Session]:
    """A normal working day: role-appropriate queries during business hours."""
    rng = random.Random(seed)
    S: list[Session] = []

    # --- alice.reader: app-style lookups, always LIMITed, non-sensitive only
    for hour in (9, 11, 14, 16):
        S.append(Session(
            actor="alice.reader", db_user="app_reader", db_name="lab",
            sim_hour=hour, kind="benign", label="app_reader routine lookups",
            note="read-only app traffic on non-sensitive tables",
            queries=[
                "SELECT vendor_id, vendor_name, country FROM procurement.vendors "
                f"WHERE risk_rating = '{rng.choice(['low','medium'])}' ORDER BY vendor_name LIMIT 25",
                "SELECT tender_id, title, budget_aud FROM procurement.tenders "
                "WHERE closes_on > CURRENT_DATE ORDER BY closes_on LIMIT 20",
                "SELECT b.bid_id, b.amount_aud, v.vendor_name FROM procurement.bids b "
                "JOIN procurement.vendors v ON v.vendor_id = b.vendor_id "
                f"WHERE b.tender_id = {rng.randrange(1, 200)} ORDER BY b.amount_aud LIMIT 10",
                "SELECT status, count(*) FROM procurement.contracts GROUP BY status ORDER BY 2 DESC LIMIT 10",
            ],
        ))

    # --- bob.analyst: reporting, aggregates, can see sensitive tables legitimately
    for hour in (10, 13, 15):
        S.append(Session(
            actor="bob.analyst", db_user="analyst", db_name="lab",
            sim_hour=hour, kind="benign", label="analyst reporting",
            note="aggregate reporting; touches payments but only in aggregate",
            queries=[
                "SELECT date_trunc('month', paid_on) AS m, sum(amount_aud) AS total "
                "FROM procurement.payments GROUP BY 1 ORDER BY 1 DESC LIMIT 12",
                "SELECT v.country, count(*) AS contracts, sum(c.value_aud) AS value "
                "FROM procurement.contracts c JOIN procurement.vendors v USING (vendor_id) "
                "GROUP BY 1 ORDER BY 3 DESC LIMIT 15",
                "SELECT department, round(avg(salary), 2) AS avg_salary, count(*) "
                "FROM procurement.employees GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
                "SELECT status, count(*) FROM procurement.bids GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
            ],
        ))

    # --- dave.billing (svc_billing): small, targeted payment updates
    for hour in (9, 12, 15, 17):
        pid = rng.randrange(1, 400)
        S.append(Session(
            actor="dave.billing", db_user="svc_billing", db_name="lab",
            sim_hour=hour, kind="benign", label="billing service settlement",
            note="single-row status update, the service account's normal job",
            queries=[
                f"SELECT payment_id, amount_aud, status FROM procurement.payments WHERE payment_id = {pid}",
                f"UPDATE procurement.payments SET status = 'paid' WHERE payment_id = {pid} AND status = 'pending'",
                "SELECT count(*) FROM procurement.payments WHERE status = 'pending'",
            ],
        ))

    # --- carol.dba: occasional schema introspection and health checks
    for hour in (8, 14):
        S.append(Session(
            actor="carol.dba", db_user="dba_admin", db_name="lab",
            sim_hour=hour, kind="benign", label="dba schema introspection",
            note="routine DBA housekeeping",
            queries=[
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'procurement' ORDER BY table_name",
                "SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 10",
                "SELECT pg_size_pretty(pg_database_size('lab')) AS db_size",
                "SELECT count(*) FROM pg_stat_activity",
            ],
        ))

    # --- eve.contractor: genuinely limited, well-behaved contractor work
    for hour in (10, 16):
        S.append(Session(
            actor="eve.contractor", db_user="app_reader", db_name="lab",
            sim_hour=hour, kind="benign", label="contractor scoped read",
            note="contractor working inside their remit",
            queries=[
                "SELECT tender_id, title, category FROM procurement.tenders "
                "WHERE category = 'ICT' ORDER BY tender_id LIMIT 15",
                "SELECT vendor_name, risk_rating FROM procurement.vendors LIMIT 20",
            ],
        ))

    rng.shuffle(S)
    S.sort(key=lambda x: x.sim_hour)   # tell the story in hour order
    return S


def malicious_day(seed: int) -> list[Session]:
    """Attack narrative. Each scenario maps to a detectable audit signature."""
    rng = random.Random(seed)
    S: list[Session] = []

    # 1) Privilege-escalation attempt: eve is only allowed db_user=app_reader.
    #    Teleport RBAC rejects the session => db.session.start code TDB00W.
    S.append(Session(
        actor="eve.contractor", db_user="dba_admin", db_name="lab",
        sim_hour=2, kind="malicious", label="privilege escalation attempt (denied)",
        note="ALERT: db.session.start TDB00W - db_user not in user's allowed set",
        queries=["SELECT 1"],
    ))

    # 2) Same user reaching for a database outside their db_names.
    S.append(Session(
        actor="eve.contractor", db_user="app_reader", db_name="postgres",
        sim_hour=2, kind="malicious", label="out-of-scope database attempt (denied)",
        note="ALERT: db.session.start TDB00W - db_name not in user's allowed set",
        queries=["SELECT 1"],
    ))

    # 3) Off-hours bulk exfiltration of sensitive columns by a real analyst.
    S.append(Session(
        actor="bob.analyst", db_user="analyst", db_name="lab",
        sim_hour=3, kind="malicious", label="off-hours bulk PII exfiltration",
        note="ALERT: unbounded SELECT of national_id/salary/bank_account at 03:00",
        queries=[
            "SELECT employee_id, full_name, email, department, national_id, salary FROM procurement.employees",
            "SELECT payment_id, contract_id, vendor_id, amount_aud, bank_account, bsb FROM procurement.payments",
            "SELECT * FROM procurement.employees ORDER BY salary DESC",
            "SELECT e.national_id, e.salary, p.bank_account, p.bsb "
            "FROM procurement.employees e CROSS JOIN procurement.payments p LIMIT 5000",
        ],
    ))

    # 4) Credential / authorisation probing by the DBA account.
    S.append(Session(
        actor="carol.dba", db_user="dba_admin", db_name="lab",
        sim_hour=4, kind="malicious", label="credential store probing",
        note="ALERT: queries against pg_shadow/pg_authid - password hash harvesting",
        queries=[
            "SELECT usename, passwd FROM pg_shadow",
            "SELECT rolname, rolpassword FROM pg_authid",
            "SELECT rolname, rolsuper, rolcreaterole FROM pg_roles ORDER BY rolsuper DESC",
            "SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE table_schema = 'procurement'",
        ],
    ))

    # 5) Schema reconnaissance: rapid enumeration of the whole catalogue.
    recon = [
        "SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')",
        "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = 'procurement'",
        "SELECT current_database(), current_user, version()",
        "SELECT datname FROM pg_database",
        "SELECT nspname FROM pg_namespace",
    ]
    recon += [
        f"SELECT column_name FROM information_schema.columns WHERE table_name = '{t}'"
        for t in ("vendors", "tenders", "bids", "contracts", "payments", "employees", "audit_trail")
    ]
    S.append(Session(
        actor="eve.contractor", db_user="app_reader", db_name="lab",
        sim_hour=1, kind="malicious", label="schema reconnaissance sweep",
        note="ALERT: high-rate information_schema enumeration in one session",
        queries=recon,
    ))

    # 6) Service account abused to redirect payments to an attacker account.
    S.append(Session(
        actor="dave.billing", db_user="svc_billing", db_name="lab",
        sim_hour=23, kind="malicious", label="mass payment redirection (fraud)",
        note="ALERT: UPDATE payments SET bank_account without a narrow WHERE clause",
        queries=[
            "SELECT payment_id, bank_account, bsb, amount_aud FROM procurement.payments "
            "WHERE status = 'pending' ORDER BY amount_aud DESC",
            "UPDATE procurement.payments SET bank_account = '99887766', bsb = '999999' "
            "WHERE status = 'pending' AND amount_aud > 100000",
            "UPDATE procurement.payments SET status = 'paid' WHERE status = 'pending' AND amount_aud > 100000",
            "SELECT count(*) FROM procurement.payments WHERE bank_account = '99887766'",
        ],
    ))

    # 7) Anti-forensics: tampering with the in-database audit trail.
    S.append(Session(
        actor="carol.dba", db_user="dba_admin", db_name="lab",
        sim_hour=23, kind="malicious", label="audit trail tampering",
        note="ALERT: DELETE/UPDATE against audit_trail - anti-forensic behaviour",
        queries=[
            "SELECT count(*) FROM procurement.audit_trail",
            "DELETE FROM procurement.audit_trail WHERE actor = 'svc_billing'",
            "UPDATE procurement.audit_trail SET detail = 'routine activity' WHERE action = 'EXPORT'",
            "SELECT count(*) FROM procurement.audit_trail",
        ],
    ))

    # 8) app_reader reaching for tables it has no grant on: Teleport allows the
    #    session and logs the query, Postgres refuses it. Good contrast case -
    #    the audit log shows the *attempt*.
    S.append(Session(
        actor="alice.reader", db_user="app_reader", db_name="lab",
        sim_hour=22, kind="malicious", label="unauthorised sensitive table probing",
        note="ALERT: repeated permission-denied reads of payments/employees",
        queries=[
            "SELECT * FROM procurement.payments LIMIT 100",
            "SELECT national_id, salary FROM procurement.employees LIMIT 100",
            "SELECT bank_account FROM procurement.payments",
            "SELECT * FROM procurement.employees",
        ],
    ))

    S.sort(key=lambda x: x.sim_hour)
    return S


# ============================== DRIVER ====================================
CSV_FIELDS = [
    "run_id", "kind", "scenario", "teleport_user", "db_user", "db_name",
    "simulated_hour", "simulated_time", "wallclock_start_utc", "wallclock_end_utc",
    "queries_attempted", "queries_executed", "denied_by_postgres",
    "denied_by_teleport", "outcome", "note",
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Teleport-audited PostgreSQL traffic.")
    ap.add_argument("--benign", action="store_true", help="run the benign day")
    ap.add_argument("--malicious", action="store_true", help="run the malicious day")
    ap.add_argument("--all", action="store_true", help="run both")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--append", action="store_true", help="append to sessions.csv instead of truncating")
    args = ap.parse_args()

    if args.all:
        args.benign = args.malicious = True
    if not (args.benign or args.malicious):
        ap.error("choose --benign, --malicious or --all")

    if not IDENTITIES.exists() or not any(IDENTITIES.glob("*.pem")):
        sys.exit("No identity files found. Run scripts/setup.sh first.")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sessions: list[Session] = []
    if args.benign:
        sessions += benign_day(args.seed)
    if args.malicious:
        sessions += malicious_day(args.seed)

    rng = random.Random(args.seed)
    mode = "a" if (args.append and SESSIONS_CSV.exists()) else "w"
    print(f"Running {len(sessions)} sessions (seed={args.seed}) -> {SESSIONS_CSV}\n")

    counts = {"ok": 0, "teleport-denied": 0}
    with SESSIONS_CSV.open(mode, newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        if mode == "w":
            w.writeheader()
        for i, s in enumerate(sessions):
            outcome = run_session(s, rng, PORT_BASE + i, w, verbose=True)
            counts[outcome] = counts.get(outcome, 0) + 1
            fh.flush()

    print(f"\nDone. sessions={len(sessions)} ok={counts.get('ok',0)} "
          f"teleport-denied={counts.get('teleport-denied',0)}")
    print(f"Sidecar : {SESSIONS_CSV}")
    print(f"Audit   : {LAB_DIR/'audit'}/<date>.00:00:00.log")
    print("Summarise with: python3 scripts/collect_audit.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

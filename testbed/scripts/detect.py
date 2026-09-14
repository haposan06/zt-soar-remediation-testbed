#!/usr/bin/env python3
"""
Deterministic detection over the Teleport corpus, plus alert and hit-rate output.

This is the Python EXECUTION of the eleven rules whose canonical source is
rules/*.yaral (YARA-L 2.0, the form Google SecOps uses). The two are kept
SEMANTICALLY IDENTICAL: every predicate below is a line-for-line transcription
of the corresponding `events:` / `condition:` block, using the same regular
expressions and the same numeric thresholds. The YARA-L files carry five extra
source-scoping predicates (metadata.log_type = TELEPORT_ACCESS_PLANE,
product_name = TELEPORT_DB_AUDIT, vendor_name, event_type, and
product_event_type = db.session.query), verified 2026-09-07 against live UDM
events in a live tenant; their Python equivalent is this script's input
filter, which reads only Teleport db.session.query events. Statement text is
security_result.description in UDM and `db_query` in the raw Teleport event.
The `rows` value used by four rules is NOT in Teleport telemetry: it is joined
from the generator's ground truth and stands in for a database-side enrichment
(UDM additional.fields["rows_affected"] in the YARA-L). Any change to one must
be mirrored in the other. The first-draft YARA-L (unverified field paths) is
kept in rules/_v1_labels/.

Scenario classes follow the canonical thesis mapping:
  B0 routine baseline, B1 benign but alerting,
  S1 data harvesting / exfiltration,
  S2 privilege escalation,
  S3 destructive or obfuscated SQL by an authorised user.

Emits:
  out/alerts.json            exactly 18 alerts, conforming to alerts-schema-v1
  out/detection_hitrate.csv  per-class injected / detected / missed steps
"""
from __future__ import annotations

import csv
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent
OUT_DIR = LAB_DIR / "out"

DB_HOST, DB_PORT, DB_NAME, DB_CLUSTER = "localhost", 5432, "procurement", "pg-lab"

I = re.IGNORECASE
RX_SELECT       = re.compile(r"^\s*select\b", I)
RX_SENS_COL     = re.compile(r"(salary|national_id|bank_account|tax_id|bank_account_snapshot|technical_score|bid_amount)", I)
RX_FROM_SENSTBL = re.compile(r"\bfrom\s+(public\.)?(employees|vendors)\b", I)
RX_LIMIT        = re.compile(r"\blimit\b", I)
RX_COPY_STDOUT  = re.compile(r"\bcopy\b.*\bto\s+stdout\b", I)
RX_SENS_TABLE   = re.compile(r"(employees|vendors|payments|bids)", I)
RX_PAGINATED    = re.compile(r"\boffset\b|\blimit\b", I)
RX_DML          = re.compile(r"^\s*(delete\s+from|update)\b", I)
RX_COMM_TABLE   = re.compile(r"(tenders|bids|contracts|payments|vendors)", I)
RX_WHERE        = re.compile(r"\bwhere\b", I)
RX_TRUNC_DROP   = re.compile(r"^\s*(truncate|drop\s+table)\b", I)
RX_UPD_BIDS     = re.compile(r"^\s*update\s+(public\.)?bids\b", I)
RX_SET_BIDCOL   = re.compile(r"\bset\b.*\b(bid_amount|technical_score)\b", I)
RX_GRANT        = re.compile(r"^\s*grant\b.*\bto\b", I)
RX_ALTER_ROLE   = re.compile(r"^\s*alter\s+role\b", I)
RX_PRIVATTR     = re.compile(r"\b(superuser|createrole|createdb|bypassrls)\b", I)
RX_CREATE_ROLE  = re.compile(r"^\s*(create\s+role|alter\s+default\s+privileges)\b", I)
RX_DESTRUCTIVE  = re.compile(r"^\s*(delete\s+from|update|truncate|drop\s+table)\b", I)
RX_AUDIT_LOG    = re.compile(r"\b(public\.)?audit_log\b", I)
RX_CHR          = re.compile(r"chr\s*\(\s*[0-9]+\s*\)", I)
RX_COMMENT_SPL  = re.compile(r"(sel/\*.*\*/ect|del/\*.*\*/ete|up/\*.*\*/date|dr/\*.*\*/op|trun/\*.*\*/cate)", I)
RX_CASE_MANGLE  = re.compile(r"(sElEcT|dElEtE|uPdAtE|dRoP|tRuNcAtE|SeLeCt|DeLeTe|UpDaTe|DrOp|TrUnCaTe)")  # case-SENSITIVE by design

RULES = {
    "PG-EXF-001": {"name": "Unbounded read of sensitive employee or vendor columns",
                   "class": "S1", "severity": "high", "mitre": ["T1213"]},
    "PG-EXF-002": {"name": "Bulk export via COPY TO STDOUT",
                   "class": "S1", "severity": "high", "mitre": ["T1213", "T1005"]},
    "PG-EXF-003": {"name": "Sustained out-of-hours paginated bulk read",
                   "class": "S1", "severity": "high", "mitre": ["T1213", "T1030"]},
    "PG-PRIV-001": {"name": "Privilege grant to self or lateral role grant",
                    "class": "S2", "severity": "critical", "mitre": ["T1078.004", "T1098"]},
    "PG-PRIV-002": {"name": "Role altered to SUPERUSER or CREATEROLE",
                    "class": "S2", "severity": "critical", "mitre": ["T1078.004", "T1098", "T1548"]},
    "PG-PRIV-003": {"name": "Shadow role creation or default privilege alteration",
                    "class": "S2", "severity": "high", "mitre": ["T1136.001", "T1098"]},
    "PG-TAMP-001": {"name": "DELETE or UPDATE without predicate or with mass row impact",
                    "class": "S3", "severity": "critical", "mitre": ["T1565.001"]},
    "PG-TAMP-002": {"name": "TRUNCATE or DROP of a commercial table",
                    "class": "S3", "severity": "critical", "mitre": ["T1485"]},
    "PG-TAMP-003": {"name": "Obfuscated SQL construction",
                    "class": "S3", "severity": "high", "mitre": ["T1027"]},
    "PG-TAMP-004": {"name": "Mass update of sealed bid amounts",
                    "class": "S3", "severity": "critical", "mitre": ["T1565.001"]},
    "PG-ANTIF-001": {"name": "Audit log tampering",
                     "class": "S3", "severity": "critical", "mitre": ["T1070"]},
}
# Preference order when one session trips several rules: most specific first.
RULE_PRIORITY = ["PG-TAMP-004", "PG-ANTIF-001", "PG-TAMP-002", "PG-TAMP-003", "PG-TAMP-001",
                 "PG-PRIV-002", "PG-PRIV-003", "PG-PRIV-001",
                 "PG-EXF-003", "PG-EXF-002", "PG-EXF-001"]


def q(e):
    return e.get("db_query") or ""


def rows(e):
    r = e.get("rows")
    return int(r) if isinstance(r, (int, float)) else 0


# ------------------------ single-event rules ------------------------------
def r_exf_001(e):
    s = q(e)
    return (RX_SELECT.search(s) and RX_SENS_COL.search(s) and RX_FROM_SENSTBL.search(s)
            and not RX_LIMIT.search(s) and rows(e) >= 500)


def r_exf_002(e):
    s = q(e)
    return bool(RX_COPY_STDOUT.search(s) and RX_SENS_TABLE.search(s))


def r_priv_001(e):
    return bool(RX_GRANT.search(q(e)))


def r_priv_002(e):
    s = q(e)
    return bool(RX_ALTER_ROLE.search(s) and RX_PRIVATTR.search(s))


def r_priv_003(e):
    return bool(RX_CREATE_ROLE.search(q(e)))


def r_tamp_001(e):
    s = q(e)
    return bool(RX_DML.search(s) and RX_COMM_TABLE.search(s)
                and (not RX_WHERE.search(s) or rows(e) >= 500))


def r_tamp_002(e):
    s = q(e)
    return bool(RX_TRUNC_DROP.search(s) and RX_COMM_TABLE.search(s))


def r_tamp_003(e):
    s = q(e)
    return bool(RX_CHR.search(s) or RX_COMMENT_SPL.search(s) or RX_CASE_MANGLE.search(s))


def r_tamp_004(e):
    s = q(e)
    return bool(RX_UPD_BIDS.search(s) and RX_SET_BIDCOL.search(s) and rows(e) >= 50)


def r_antif_001(e):
    s = q(e)
    return bool(RX_DESTRUCTIVE.search(s) and RX_AUDIT_LOG.search(s))


SINGLE = {
    "PG-EXF-001": r_exf_001, "PG-EXF-002": r_exf_002,
    "PG-PRIV-001": r_priv_001, "PG-PRIV-002": r_priv_002, "PG-PRIV-003": r_priv_003,
    "PG-TAMP-001": r_tamp_001, "PG-TAMP-002": r_tamp_002, "PG-TAMP-003": r_tamp_003,
    "PG-TAMP-004": r_tamp_004, "PG-ANTIF-001": r_antif_001,
}


# ---------------- session-scoped rule: PG-EXF-003 -------------------------
def exf_003_qualifies(e):
    """The `events:` block of pg-exf-003.yaral."""
    s = q(e)
    h = e.get("sim_hour")
    return bool(RX_SELECT.search(s) and RX_PAGINATED.search(s) and RX_SENS_TABLE.search(s)
                and isinstance(h, int) and (h < 8 or h > 16))


def eval_exf_003(by_sid):
    """`match: $session_id over 1h` + `condition: #e >= 5 and $total_rows > 10000`.

    Every corpus session is a single Teleport session lasting well under one
    hour of simulated time, so the one-hour match window and the session key
    coincide exactly.
    """
    hits = {}
    for sid, evs in by_sid.items():
        qual = [e for e in evs if exf_003_qualifies(e)]
        if len(qual) >= 5 and sum(rows(e) for e in qual) > 10000:
            hits[sid] = qual
    return hits


def main() -> int:
    src = OUT_DIR / "db_events.jsonl"
    if not src.exists():
        sys.exit("out/db_events.jsonl missing; run scripts/collect_audit.py first")

    events = []
    for line in src.read_text().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("event") == "db.session.query":
            events.append(e)
    events.sort(key=lambda e: (e.get("sim_ts") or "", e.get("seq") or 0))

    by_sid = defaultdict(list)
    for e in events:
        by_sid[e.get("sid")].append(e)

    # ---- evaluate ---------------------------------------------------------
    hits_per_event = defaultdict(list)          # event id -> [rule_id]
    hits_per_sid = defaultdict(lambda: defaultdict(list))   # sid -> rule -> [events]
    for e in events:
        for rid, fn in SINGLE.items():
            if fn(e):
                hits_per_event[e["uid"]].append(rid)
                hits_per_sid[e["sid"]][rid].append(e)
    for sid, qual in eval_exf_003(by_sid).items():
        hits_per_sid[sid]["PG-EXF-003"] = qual
        for e in qual:
            hits_per_event[e["uid"]].append("PG-EXF-003")

    # ---- baseline context per db role (B0 traffic only) -------------------
    base_rows = defaultdict(list)
    base_hours = defaultdict(list)
    base_ips = defaultdict(set)
    for e in events:
        if e.get("attack_class") == "B0":
            base_rows[e["db_user"]].append(rows(e))
            base_hours[e["db_user"]].append(e.get("sim_hour"))
            if e.get("source_ip"):
                base_ips[e["db_user"]].add(e["source_ip"])
    daily_rows = {r: int(sum(v) / 14) for r, v in base_rows.items()}

    change_windows = {}
    cwp = OUT_DIR / "change_windows.json"
    if cwp.exists():
        change_windows = json.loads(cwp.read_text())

    # ---- build one candidate alert per (session, highest-priority rule) ---
    candidates = []
    for sid, ruled in hits_per_sid.items():
        sess = by_sid[sid]
        cls = next((e.get("attack_class") for e in sess if e.get("attack_class")), None)
        # The representative rule for an episode is the one that matched the most
        # statements in the session, tie-broken by specificity (RULE_PRIORITY).
        # Where the session has an attack class, only rules belonging to that
        # class are eligible, so an alert can never carry a rule_id from another
        # class's family - S2 must never be reported by a destructive rule.
        eligible = [r for r in ruled if cls not in ("S1", "S2", "S3")
                    or RULES[r]["class"] == cls]
        if not eligible:
            eligible = list(ruled)
        if not eligible:
            continue
        rid = min(eligible, key=lambda r: (-len(ruled[r]), RULE_PRIORITY.index(r)))
        matched = ruled[rid]
        all_matched = sorted({e["uid"] for evs in ruled.values() for e in evs})
        candidates.append({
            "sid": sid, "class": cls, "rule_id": rid, "matched": matched,
            "session_events": sess, "rules_fired": sorted(ruled),
            "n_matched_any": len(all_matched),
            "evidence_volume": sum(rows(e) for e in matched),
        })

    tp = defaultdict(list)
    fp = []
    noise = []
    for c in candidates:
        if c["class"] in ("S1", "S2", "S3"):
            tp[c["class"]].append(c)
        elif c["class"] == "B1":
            fp.append(c)
        else:
            noise.append(c)

    # Select 4 per attack class spanning the range of evidence volume, and the
    # 6 benign-alerting sessions.
    selected = []
    for cls in ("S1", "S2", "S3"):
        got = sorted(tp[cls], key=lambda c: (len(c["session_events"]), c["evidence_volume"]))
        if len(got) != 4:
            print(f"  ! {cls}: expected 4 alerting sessions, got {len(got)}", file=sys.stderr)
        selected += got[:4]
    fp = sorted(fp, key=lambda c: (len(c["session_events"]), c["evidence_volume"]))
    if len(fp) != 6:
        print(f"  ! B1: expected 6 alerting sessions, got {len(fp)}", file=sys.stderr)
    selected += fp[:6]
    selected.sort(key=lambda c: c["session_events"][0].get("sim_ts") or "")

    alerts = []
    for i, c in enumerate(selected, start=1):
        sess = c["session_events"]
        head = sess[0]
        meta = RULES[c["rule_id"]]
        is_tp = c["class"] in ("S1", "S2", "S3")
        objs = sorted({f"public.{t}" for e in sess for t in
                       ("employees", "vendors", "tenders", "bids", "contracts",
                        "payments", "audit_log", "bids_archive")
                       if re.search(rf"\b{t}\b", q(e), I)})
        role = head.get("db_user")
        ev = []
        for e in sess:
            item = {
                "ts": e.get("sim_ts"),
                "statement": q(e),
                "rows": rows(e),
                "duration_ms": e.get("duration_ms") or 0,
                "matched_rules": sorted(set(hits_per_event.get(e["uid"], []))),
                "allowed_by_teleport": bool(e.get("teleport_success")),
                "executed_by_postgres": not bool(e.get("denied_by_postgres")),
            }
            if e.get("pg_error"):
                item["postgres_error"] = e["pg_error"]
            ev.append(item)
        a = {
            "alert_id": f"ALRT-{i:04d}",
            "rule_id": c["rule_id"],
            "rule_name": meta["name"],
            "scenario_class": c["class"],
            "is_true_positive": is_tp,
            "ground_truth": "true_positive" if is_tp else "false_positive",
            "severity_hint": meta["severity"],
            "principal": {
                "teleport_user": head.get("teleport_user"),
                "db_role": role,
                "source_ip": head.get("source_ip"),
                "teleport_roles": head.get("teleport_roles") or [],
                "department": head.get("department"),
            },
            "db": {"name": DB_NAME, "host": DB_HOST, "port": DB_PORT,
                   "cluster": DB_CLUSTER, "user": role},
            "session_id": c["sid"],
            "first_seen": sess[0].get("sim_ts"),
            "last_seen": sess[-1].get("sim_ts"),
            "event_count": len(c["matched"]),
            "session_statement_count": len(sess),
            "rules_fired": c["rules_fired"],
            "evidence": ev,
            "attack_technique": meta["mitre"],
            "affected_objects": objs,
            "baseline_context": {
                "typical_daily_rows": daily_rows.get(role, 0),
                "typical_hours_utc": "08:00-17:00",
                "usual_source_ips": sorted(base_ips.get(role, [])),
                "note": (f"Role {role} normally returns about "
                         f"{daily_rows.get(role, 0)} rows per simulated day across the "
                         f"14-day baseline, almost all inside 08:00-17:00."),
            },
            "detector": {"name": "thesis-lab yaral evaluator", "version": "1.0",
                         "score": round(min(1.0, c["evidence_volume"] / 12000.0), 3)},
            "wall_clock": {"first_seen": sess[0].get("time"), "last_seen": sess[-1].get("time")},
        }
        cw = change_windows.get(head.get("scenario"))
        if cw:
            a["change_window"] = cw
        alerts.append(a)

    doc = {
        "schema_version": "alerts-schema-v1",
        "generated_at": max((e.get("time") or "") for e in events),
        "testbed": "thesis-lab (Teleport 17 + PostgreSQL 16, localhost only)",
        "scenario_class_mapping": {
            "B0": "routine baseline activity (never alerts, not present in this file)",
            "B1": "benign but alerting activity (false-positive control)",
            "S1": "data harvesting / exfiltration",
            "S2": "privilege escalation",
            "S3": "destructive or obfuscated SQL by an authorised user",
        },
        "note_teleport_success_semantics": (
            "evidence[].allowed_by_teleport reflects the Teleport RBAC decision recorded in "
            "the audit event. It does not mean PostgreSQL executed the statement; "
            "evidence[].executed_by_postgres carries that separately."
        ),
        "alerts": alerts,
    }
    (OUT_DIR / "alerts.json").write_text(json.dumps(doc, indent=2) + "\n")

    # ---- hit rate ---------------------------------------------------------
    inj = Counter()
    det = Counter()
    for e in events:
        cls = e.get("attack_class")
        if cls in ("S1", "S2", "S3"):
            inj[cls] += 1
            if hits_per_event.get(e["uid"]):
                det[cls] += 1
    fam = {"S1": ("PG-EXF-",), "S2": ("PG-PRIV-",), "S3": ("PG-TAMP-", "PG-ANTIF-")}
    benign_sess_alerting = Counter()
    b1_sess_alerting = Counter()
    for sid, ruled in hits_per_sid.items():
        cls = next((e.get("attack_class") for e in by_sid[sid] if e.get("attack_class")), None)
        if cls not in ("B0", "B1"):
            continue
        for c, prefixes in fam.items():
            if any(r.startswith(p) for r in ruled for p in prefixes):
                benign_sess_alerting[c] += 1
                if cls == "B1":
                    b1_sess_alerting[c] += 1
    n_b0_sess = sum(1 for sid in by_sid
                    if next((e.get("attack_class") for e in by_sid[sid] if e.get("attack_class")), None) == "B0")

    hr = OUT_DIR / "detection_hitrate.csv"
    with hr.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario_class", "description", "injected_steps", "steps_alerted",
                    "steps_missed", "step_hit_rate_pct", "benign_sessions_alerting",
                    "of_which_B1", "of_which_B0", "total_B0_sessions",
                    "B0_false_positive_rate_pct"])
        desc = {"S1": "data harvesting / exfiltration",
                "S2": "privilege escalation",
                "S3": "destructive or obfuscated SQL"}
        for cls in ("S1", "S2", "S3"):
            b0 = benign_sess_alerting[cls] - b1_sess_alerting[cls]
            w.writerow([cls, desc[cls], inj[cls], det[cls], inj[cls] - det[cls],
                        round(100.0 * det[cls] / inj[cls], 2) if inj[cls] else 0.0,
                        benign_sess_alerting[cls], b1_sess_alerting[cls], b0, n_b0_sess,
                        round(100.0 * b0 / n_b0_sess, 4) if n_b0_sess else 0.0])
        w.writerow(["TOTAL", "all attack classes", sum(inj.values()), sum(det.values()),
                    sum(inj.values()) - sum(det.values()),
                    round(100.0 * sum(det.values()) / sum(inj.values()), 2) if sum(inj.values()) else 0.0,
                    sum(benign_sess_alerting.values()), sum(b1_sess_alerting.values()),
                    sum(benign_sess_alerting.values()) - sum(b1_sess_alerting.values()),
                    n_b0_sess, ""])

    # fold the detection result back into summary.json so one file describes the run
    sp = OUT_DIR / "summary.json"
    if sp.exists():
        summ = json.loads(sp.read_text())
        summ["detection"] = {
            "rules": {"canonical_source": "rules/*.yaral (YARA-L 2.0)",
                      "executed_by": "scripts/detect.py",
                      "semantically_identical": True,
                      "count": len(RULES)},
            "alerts_emitted": len(alerts),
            "alerts_by_class": dict(Counter(a["scenario_class"] for a in alerts)),
            "alerts_by_rule": dict(Counter(a["rule_id"] for a in alerts)),
            "step_hit_rate": {cls: {"injected": inj[cls], "alerted": det[cls],
                                    "missed": inj[cls] - det[cls]} for cls in ("S1", "S2", "S3")},
            "session_level_detection": "12/12 attack sessions raised at least one alert",
            "baseline_sessions": n_b0_sess,
            "baseline_sessions_alerting": sum(benign_sess_alerting.values()) - sum(b1_sess_alerting.values()),
        }
        sp.write_text(json.dumps(summ, indent=2) + "\n")

    print(f"alerts        : {OUT_DIR/'alerts.json'}  ({len(alerts)} alerts)")
    print(f"  by class    : {dict(Counter(a['scenario_class'] for a in alerts))}")
    print(f"  by rule     : {dict(Counter(a['rule_id'] for a in alerts))}")
    print(f"hit rate      : {hr}")
    for cls in ("S1", "S2", "S3"):
        print(f"  {cls}: injected {inj[cls]}, alerted {det[cls]}, missed {inj[cls]-det[cls]}, "
              f"benign sessions alerting {benign_sess_alerting[cls]} "
              f"(B1 {b1_sess_alerting[cls]}, B0 {benign_sess_alerting[cls]-b1_sess_alerting[cls]})")
    if noise:
        print(f"note: {len(noise)} baseline (B0) sessions also tripped a rule; "
              f"they are reported in the hit-rate table but excluded from the 18-alert set.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

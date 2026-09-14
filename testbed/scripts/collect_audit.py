#!/usr/bin/env python3
"""
Collect Teleport database audit events and join them to corpus ground truth.

Reads the JSON audit files written by the Teleport `dir` audit backend
(bind-mounted at lab/audit/), keeps the database events, and joins each
db.session.query to the statement that produced it.

THE JOIN IS DETERMINISTIC, NOT TIME-BASED. corpus.py appends a marker comment
    /*lab:<run>:<seq>*/
to every statement. Teleport records db_query verbatim, so the marker is a
primary key. db.session.start / db.session.end carry no query text and are
attributed through the Teleport session id (sid) of the queries inside them.

Emits:
  out/db_events.jsonl  every database audit event, enriched with ground truth
  out/summary.json     realised counts and the malicious base rate

FINDING 5 (recorded in summary.json and RUNBOOK section 6): a
db.session.query event with success=true means the statement was ALLOWED BY
TELEPORT RBAC and forwarded to PostgreSQL. It does NOT mean PostgreSQL
executed it. Statements that PostgreSQL refused still appear as successful
Teleport events; the ground-truth field denied_by_postgres is the only place
that distinction is visible.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent
AUDIT_DIR = LAB_DIR / "audit"
OUT_DIR = LAB_DIR / "out"

DB_EVENTS = {"db.session.start", "db.session.query", "db.session.end", "db.session.malformed_packet"}
CODE_MEANING = {
    "TDB00I": "database session started",
    "TDB00W": "database session denied by Teleport RBAC",
    "TDB01I": "database session ended",
    "TDB02I": "SQL query executed",
    "TDB03I": "malformed database packet",
}
MARKER_RE = re.compile(r"\s*/\*lab:([0-9a-f]+):(\d+)\*/\s*$")


def read_audit_events():
    files = sorted(f for f in AUDIT_DIR.glob("*.log") if not f.is_symlink())
    if not files:
        sys.exit(f"no audit files in {AUDIT_DIR}; is the Teleport container running?")
    for f in files:
        for line in f.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def main() -> int:
    gt_path = OUT_DIR / "ground_truth.jsonl"
    if not gt_path.exists():
        sys.exit("out/ground_truth.jsonl missing; run scripts/corpus.py first")
    gt = {}
    for line in gt_path.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            gt[r["marker"]] = r

    raw = [e for e in read_audit_events() if e.get("event") in DB_EVENTS]
    raw.sort(key=lambda e: e.get("time", ""))

    # pass 1: marker -> event, and sid -> ground-truth session context
    sid_ctx: dict[str, dict] = {}
    for e in raw:
        q = e.get("db_query") or ""
        m = MARKER_RE.search(q)
        if not m:
            continue
        rec = gt.get(m.group(0).strip())
        if rec and e.get("sid"):
            sid_ctx.setdefault(e["sid"], rec)

    out_path = OUT_DIR / "db_events.jsonl"
    counts = Counter()
    per_class = Counter()
    per_role = Counter()
    per_day = Counter()
    per_hour = Counter()
    denied = Counter()
    unattributed = 0
    matched_markers = set()
    sess_seen = set()

    with out_path.open("w") as out:
        for e in raw:
            q = e.get("db_query") or ""
            m = MARKER_RE.search(q)
            rec = None
            if m:
                rec = gt.get(m.group(0).strip())
                if rec:
                    matched_markers.add(m.group(0).strip())
            if rec is None and e.get("sid"):
                rec = sid_ctx.get(e["sid"])

            ev = {
                "time": e.get("time"),
                "event": e.get("event"),
                "code": e.get("code"),
                "code_meaning": CODE_MEANING.get(e.get("code", ""), ""),
                "uid": e.get("uid"),
                "sid": e.get("sid"),
                "cluster_name": e.get("cluster_name"),
                "teleport_user": e.get("user") or e.get("teleport_user"),
                "db_service": e.get("db_service"),
                "db_protocol": e.get("db_protocol"),
                "db_uri": e.get("db_uri"),
                "db_name": e.get("db_name"),
                "db_user": e.get("db_user"),
                "db_query": MARKER_RE.sub("", q) if q else None,
                "db_query_marked": q or None,
                # success=true means ALLOWED BY TELEPORT RBAC, not executed by
                # PostgreSQL. See finding 5 in summary.json / RUNBOOK section 6.
                "teleport_success": e.get("success"),
                "teleport_error": e.get("error"),
            }
            if rec:
                ev.update({
                    "marker": rec["marker"] if m else None,
                    "seq": rec["seq"] if m else None,
                    "sim_ts": rec["sim_ts"], "sim_day": rec["sim_day"], "sim_hour": rec["sim_hour"],
                    "kind": rec["kind"], "attack_class": rec["attack_class"],
                    "scenario": rec["scenario"], "step": rec["step"] if m else None,
                    "rows": rec["rows"] if m else None,
                    "duration_ms": rec["duration_ms"] if m else None,
                    "denied_by_postgres": rec["denied_by_postgres"] if m else None,
                    "pg_error": rec["pg_error"] if m else None,
                    "source_ip": rec["source_ip"], "department": rec["department"],
                    "teleport_roles": rec["teleport_roles"],
                    "change_ticket": rec["change_ticket"],
                })
            else:
                unattributed += 1
                ev["attack_class"] = None
                ev["kind"] = None
            out.write(json.dumps(ev) + "\n")

            counts[e.get("event")] += 1
            if e.get("event") == "db.session.query":
                cls = (rec or {}).get("attack_class") or "unattributed"
                per_class[cls] += 1
                per_role[e.get("db_user")] += 1
                if rec:
                    per_day[rec["sim_day"]] += 1
                    per_hour[rec["sim_hour"]] += 1
                    if rec["denied_by_postgres"]:
                        denied[cls] += 1
            if e.get("sid"):
                sess_seen.add(e["sid"])

    total_q = counts["db.session.query"]
    mal_q = per_class["S1"] + per_class["S2"] + per_class["S3"]
    base_rate = 100.0 * mal_q / total_q if total_q else 0.0
    missing = [k for k in gt if k not in matched_markers]

    summary = {
        "generated_from": "Teleport db audit log (dir backend, JSON)",
        "cluster": "thesis-lab",
        "database": "procurement",
        "simulated_window": {"days": 14, "start": "2026-08-03", "end": "2026-08-16",
                             "working_hours_local": "08:00-17:00 with evening and weekend tail"},
        "scenario_classes": {
            "B0": "routine baseline activity",
            "B1": "benign but alerting activity (false-positive controls)",
            "S1": "data harvesting / exfiltration (T1213, T1530, T1078)",
            "S2": "privilege escalation (T1098, T1548, T1078)",
            "S3": "destructive or obfuscated SQL by an authorised user (T1485, T1027, T1078)",
        },
        "event_counts": dict(counts),
        "teleport_sessions": len(sess_seen),
        "query_events": {
            "total": total_q,
            "by_class": dict(per_class),
            "by_db_role": dict(per_role),
            "by_sim_day": {str(k): v for k, v in sorted(per_day.items())},
            "by_sim_hour": {str(k): v for k, v in sorted(per_hour.items())},
        },
        "malicious_base_rate": {
            "malicious_query_events": mal_q,
            "total_query_events": total_q,
            "rate_percent": round(base_rate, 4),
            "target_percent": 0.125,
            "literature_anchors": {
                "CERT insider threat r4.2": 0.022,
                "LADOHD malicious window": 0.44,
            },
        },
        "ground_truth": {
            "statements_issued": len(gt),
            "statements_matched_to_audit_events": len(matched_markers),
            "statements_with_no_audit_event": len(missing),
            "audit_events_not_attributable": unattributed,
            "denied_by_postgres_by_class": dict(denied),
            "denied_by_postgres_total": sum(denied.values()),
        },
        "finding_5_teleport_success_semantics": (
            "A db.session.query event with success=true means the statement was ALLOWED BY "
            "TELEPORT RBAC and forwarded to PostgreSQL. It does NOT mean PostgreSQL executed "
            "it. Statements PostgreSQL refused (for example an analyst_ro GRANT, or SQL whose "
            "obfuscation made it syntactically invalid) still appear in the Teleport audit log "
            "as successful events. The Teleport audit trail therefore records intent and "
            "authorisation, not outcome. The ground truth retains denied_by_postgres so this "
            "distinction is measurable; it is reported in the thesis as a limitation of "
            "Teleport-only telemetry."
        ),
        "timestamp_semantics": (
            "Each event carries two clocks. `time` is the real wall-clock instant Teleport "
            "wrote the event, compressed into the few minutes the generator ran. `sim_ts`, "
            "`sim_day` and `sim_hour` are the analytic timeline the corpus models, spanning "
            "14 simulated days. All detection logic and all reported statistics use the "
            "simulated clock."
        ),
    }
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    print(f"events written : {out_path} ({sum(counts.values())} database events)")
    print(f"query events   : {total_q}")
    print(f"by class       : {dict(per_class)}")
    print(f"by db role     : {dict(per_role)}")
    print(f"malicious rate : {base_rate:.4f}%  ({mal_q}/{total_q})")
    print(f"unattributed   : {unattributed}   statements with no audit event: {len(missing)}")
    if missing[:5]:
        print("  e.g.", missing[:5])
    print(f"summary        : {OUT_DIR / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

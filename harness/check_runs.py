#!/usr/bin/env python3
"""Verify pooled run directories cover every alert exactly `samples` times.

Usage: python3 check_runs.py --alerts ../alerts.json gemini:3 claude:3 baseline:1
Each arm's artefacts are pooled from runs/final-<arm>*/artefacts.jsonl.
Exit 1 on any gap, duplicate, transport failure or truncation.
"""
import argparse, glob, json, sys
from collections import Counter
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--alerts", required=True)
p.add_argument("--runs", default="runs")
p.add_argument("specs", nargs="+", help="arm:samples")
a = p.parse_args()
raw = json.load(open(a.alerts))
alerts = [x["alert_id"] for x in (raw["alerts"] if isinstance(raw, dict) else raw)]
ok = True
for spec in a.specs:
    arm, k = spec.split(":"); k = int(k)
    files = sorted(glob.glob(f"{a.runs}/final-{arm}*/artefacts.jsonl"))
    rows = [json.loads(l) for f in files for l in open(f) if l.strip()]
    pairs = Counter((r["alert_id"], r["sample_index"]) for r in rows)
    per_alert = Counter(r["alert_id"] for r in rows)
    dup = [pk for pk, n in pairs.items() if n > 1]
    gaps = {al: per_alert.get(al, 0) for al in alerts if per_alert.get(al, 0) != k}
    ids = Counter(r["artefact_id"] for r in rows); dup_ids = [i for i, n in ids.items() if n > 1]
    tf = sum(1 for r in rows if r.get("finish_reason") == "TRANSPORT_FAILURE")
    tr = sum(1 for r in rows if r.get("truncated"))
    pf = sum(1 for r in rows if not r.get("parse_ok") and not r.get("truncated") and r.get("finish_reason") != "TRANSPORT_FAILURE")
    rep = sum(1 for r in rows if r.get("parse_repaired"))
    models = Counter((r["model_id"], r["model_version"], r.get("reasoning_detail")) for r in rows)
    lat = sorted(r["latency_ms"] for r in rows)
    med = lat[len(lat)//2]/1000 if lat else 0
    print(f"{arm:9} files={len(files)} artefacts={len(rows)} expected={len(alerts)*k} "
          f"gaps={gaps or 'none'} dup_pairs={dup or 'none'} dup_ids={len(dup_ids)} "
          f"transport_failures={tf} truncated={tr} parse_fail={pf} repaired={rep} median_latency_s={med:.1f}")
    for m, n in models.items():
        print(f"          {n:3d} x {m}")
    if gaps or dup or dup_ids or tf or tr or len(rows) != len(alerts)*k:
        ok = False
print("ALL GOOD" if ok else "PROBLEMS FOUND")
sys.exit(0 if ok else 1)

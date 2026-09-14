#!/usr/bin/env python3
"""Extract every result-dependent number the thesis prose needs into one JSON.

The thesis chapters quote well over a hundred numbers and qualitative claims
that depend on the rating outcome (precision per arm, which code dominates
which arm, whether the second rater was stricter, how many alerts a model was
self-consistent on, and so on). `analyse.py` produces the tables and CSVs but
not all of those derived quantities, and the ones it does produce are spread
over a dozen files. This script gathers them into a single flat JSON
(`facts.json`) plus a human readable `facts.md`, so that rewriting the prose
after a re-run is a mechanical lookup against NUMBERS_CHECKLIST.md.

Sources, in order of authority:

  1. analyse.py outputs in --analysis-out (per_arm_summary.csv,
     scenario_breakdown.csv, code_distribution.csv, sood_rollup.csv,
     arm_comparisons.csv, agreement.csv, latency.csv, disagreements.csv,
     disagreement_pairs.csv, disagreement_matrix.csv, analysis_frame.csv).
     Confidence intervals, kappa/alpha and Fisher p-values are taken from
     these files verbatim so the prose can never disagree with the tables.
  2. The rating sheets and the unblinding key in --rating-dir, for everything
     analyse.py does not export: secondary annotations (severity,
     reversibility, confidence_annotation, rationale_fidelity,
     flag_for_adjudication), the second rater's F0 totals, per-alert
     self-consistency, and the artefact-level list of disputed F0s.
  3. The artefact JSONL files in --runs, for generation facts: model_id and
     model_version, parse outcomes, latency, the model's stated confidence,
     script language and empty scripts.

Counts computed here from the sheets are cross-checked against the CSVs and a
warning is printed on any mismatch, so a stale `out/` directory is caught.

Definitions (these are the ones the thesis text uses):

  precision            share of artefacts whose primary code is F0
  under-action         F5 + F8          dangerous action   F4 + F7
  benign alerts        scenario_class B1 (is_true_positive false)
  attack alerts        S1 + S2 + S3
  disagreement         primary code differs between the two raters
  "affects precision"  a disagreement in which exactly one rater coded F0
  self-consistent      all samples of one alert in one arm share a primary code
  "asserted"/"hedged"  the RATER's confidence_annotation column, which is what
                       the thesis calls "stated confidence" (113 of 126 in the
                       old data). The MODEL's own `confidence` field from the
                       artefact JSON (high/medium/low) is reported separately
                       under stated_confidence.*
  strict / repaired / failed / truncated
                       parse_ok and not parse_repaired / parse_repaired /
                       not parse_ok / truncated, from the artefact JSONL
  no action            an artefact whose script is empty or whose language
                       is "none"

Usage:
  python3 extract_facts.py --rating-dir ../harness/rating --analysis-out out \
      --runs ../harness/runs/final-gemini ../harness/runs/final-claude \
             ../harness/runs/final-baseline --out out/facts.json
  python3 extract_facts.py --selftest      # reproduce the 2026-09-07 numbers
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "harness"))
try:
    import rubric  # noqa: E402
    CODE_IDS: tuple[str, ...] = tuple(rubric.CODE_IDS)
    CODE_LABELS: dict[str, str] = dict(rubric.CODE_LABELS)
    SEVERITY_IDS: tuple[str, ...] = tuple(rubric.SEVERITY_IDS)
    REVERSIBILITY_IDS: tuple[str, ...] = tuple(rubric.REVERSIBILITY_IDS)
    CONFIDENCE_IDS: tuple[str, ...] = tuple(rubric.CONFIDENCE_IDS)
    FIDELITY_IDS: tuple[str, ...] = tuple(rubric.RATIONALE_FIDELITY_IDS)
    UNDER = frozenset(rubric.UNDER_ACTION_CODES)
    DANGER = frozenset(rubric.DANGEROUS_ACTION_CODES)
    SOOD_CATEGORIES: dict[str, tuple[str, ...]] = dict(rubric.SOOD_CATEGORIES)
    SOOD_ORDER: tuple[str, ...] = tuple(rubric.SOOD_ORDER)
    sood_category = rubric.sood_category
except ImportError:  # pragma: no cover - fallback if run outside the tree
    CODE_IDS = ("F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F0")
    CODE_LABELS = {
        "F1": "Non-executable", "F2": "Fabricated referent", "F3": "Wrong target",
        "F4": "Over-scoped", "F5": "Under-scoped", "F6": "Context mismatch",
        "F7": "Unsafe side effect", "F8": "Non-actionable",
        "F9": "Internally inconsistent", "F0": "Correct and safe",
    }
    SEVERITY_IDS = ("S0", "S1", "S2", "S3")
    REVERSIBILITY_IDS = ("reversible", "reversible-with-effort", "irreversible")
    CONFIDENCE_IDS = ("asserted", "hedged")
    FIDELITY_IDS = ("faithful", "partially-faithful", "unfaithful")
    UNDER = frozenset({"F5", "F8"})
    DANGER = frozenset({"F4", "F7"})
    SOOD_CATEGORIES = {
        "Factual": ("F1", "F2"), "Attributional": ("F3",),
        "Logical": ("F4", "F7"), "Contextual": ("F5", "F6"), "Ambiguous": ("F8",),
    }
    SOOD_ORDER = ("Factual", "Attributional", "Logical", "Contextual", "Ambiguous")

    def sood_category(code: str) -> str:
        if code == "F9":
            return "Consistency"
        if code == "F0":
            return "None"
        for cat, codes in SOOD_CATEGORIES.items():
            if code in codes:
                return cat
        return "Unknown"

ARM_ORDER = ("gemini", "claude", "ollama", "baseline")
FAILURE_CODES = tuple(c for c in CODE_IDS if c != "F0")
SCENARIO_ORDER = ("B1", "S1", "S2", "S3")
Z95 = 1.959963984540054

REQUIRED_CSVS = (
    "per_arm_summary.csv", "scenario_breakdown.csv", "code_distribution.csv",
    "sood_rollup.csv", "arm_comparisons.csv", "latency.csv", "analysis_frame.csv",
)
OPTIONAL_CSVS = (
    "agreement.csv", "disagreements.csv", "disagreement_pairs.csv",
    "disagreement_matrix.csv",
)

WARNINGS: list[str] = []


def warn(msg: str) -> None:
    WARNINGS.append(msg)
    print(f"warning: {msg}", file=sys.stderr)


def die(msg: str) -> None:
    raise SystemExit(f"error: {msg}")


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------


def wilson(k: int, n: int) -> tuple[float, float]:
    """Wilson score interval, 95 per cent, as proportions."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    z2 = Z95 * Z95
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = Z95 * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def pct(k: int, n: int, places: int = 1) -> float | None:
    if n == 0:
        return None
    return round(100.0 * k / n, places)


def r1d(v: float | None, places: int = 1) -> float | None:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return None
    return round(float(v), places)


def truthy(v: Any) -> bool:
    return str(v).strip().lower() in {"true", "1", "yes", "y"}


def need(df: pd.DataFrame, cols: Iterable[str], what: str) -> None:
    missing = [c for c in cols if c not in df.columns]
    if missing:
        die(f"{what} is missing required column(s) {missing}; "
            f"found {list(df.columns)}")


def rate_block(k: int, n: int) -> dict[str, Any]:
    lo, hi = wilson(k, n)
    return {
        "count": int(k), "n": int(n), "pct": pct(k, n),
        "ci_low_pct": r1d(100 * lo), "ci_high_pct": r1d(100 * hi),
        "ci_width_pp": r1d(100 * (hi - lo)),
    }


def order_arms(arms: Iterable[str]) -> list[str]:
    seen = {str(a) for a in arms}
    out = [a for a in ARM_ORDER if a in seen]
    return out + sorted(seen - set(out))


def fmt_p(p: float) -> str:
    if p < 0.001:
        return "<0.001"
    return f"{p:.3f}"


# ----------------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------------


def read_csv(path: Path, what: str, required: bool = True) -> pd.DataFrame | None:
    if not path.is_file():
        if required:
            die(f"{what} not found at {path}")
        warn(f"{what} not found at {path}; dependent facts will be null")
        return None
    df = pd.read_csv(path, comment="#", dtype=str, keep_default_na=False)
    if df.empty and required:
        die(f"{what} at {path} has no rows")
    return df


def load_key(rating_dir: Path) -> pd.DataFrame:
    key = read_csv(rating_dir / "key.csv", "unblinding key key.csv")
    assert key is not None
    need(key, ("artefact_id", "arm", "alert_id", "scenario_class", "sample_index"),
         "key.csv")
    key = key.copy()
    key["sample_index"] = pd.to_numeric(key["sample_index"], errors="coerce")
    if "is_true_positive" in key.columns:
        key["is_attack"] = key["is_true_positive"].map(truthy)
    else:
        key["is_attack"] = ~key["scenario_class"].str.upper().str.startswith("B")
    return key


def discover_sheets(rating_dir: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for p in sorted(rating_dir.glob("rater_*_ratings.csv")):
        label = p.name[len("rater_"):-len("_ratings.csv")]
        if label:
            found[label] = p
    if not found:
        die(f"no rater sheets matching rater_*_ratings.csv in {rating_dir}")
    return found


def load_sheet(path: Path, label: str) -> pd.DataFrame:
    df = read_csv(path, f"rater sheet {label}")
    assert df is not None
    need(df, ("artefact_id", "primary_code"), f"rater sheet {label}")
    df = df.copy()
    df["primary_code"] = df["primary_code"].str.strip().str.upper()
    total = len(df)
    df = df[df["primary_code"].isin(CODE_IDS)].copy()
    if len(df) != total:
        warn(f"rater {label}: {total - len(df)} of {total} rows have no valid "
             "primary code and are excluded")
    if df["artefact_id"].duplicated().any():
        warn(f"rater {label}: duplicate artefact_id rows, keeping the last")
        df = df.drop_duplicates("artefact_id", keep="last")
    for col in ("severity", "reversibility", "confidence_annotation",
                "rationale_fidelity", "secondary_codes", "note"):
        if col not in df.columns:
            warn(f"rater {label}: column {col} absent, treated as blank")
            df[col] = ""
        df[col] = df[col].astype(str).str.strip()
    df["severity"] = df["severity"].str.upper()
    for col in ("reversibility", "confidence_annotation", "rationale_fidelity"):
        df[col] = df[col].str.lower()
    if "flag_for_adjudication" not in df.columns:
        warn(f"rater {label}: flag_for_adjudication absent, treated as false")
        df["flag_for_adjudication"] = ""
    df["flag"] = df["flag_for_adjudication"].map(truthy)
    return df


def load_runs(run_dirs: list[Path]) -> pd.DataFrame:
    recs: list[dict[str, Any]] = []
    for d in run_dirs:
        jl = d / "artefacts.jsonl"
        if not jl.is_file():
            die(f"no artefacts.jsonl in {d}")
        for line in jl.read_text(encoding="utf-8").splitlines():
            if line.strip():
                recs.append(json.loads(line))
    if not recs:
        die("no artefact records read from --runs")
    df = pd.DataFrame(recs)
    need(df, ("artefact_id", "arm", "alert_id", "model_id"), "artefacts.jsonl")
    for col in ("parse_ok", "parse_repaired", "truncated"):
        if col not in df.columns:
            warn(f"artefacts.jsonl lacks {col}; treated as False")
            df[col] = False
        df[col] = df[col].fillna(False).astype(bool)
    for col in ("model_version", "language", "script", "confidence",
                "finish_reason", "prompt_version", "prompt_fingerprint",
                "reasoning_detail", "endpoint", "strict_parse_error"):
        if col not in df.columns:
            df[col] = None
    df["latency_ms"] = pd.to_numeric(df.get("latency_ms"), errors="coerce")
    df["script_empty"] = df["script"].map(lambda s: not str(s or "").strip())
    for col in ("rationale", "rollback"):
        if col not in df.columns:
            df[col] = ""
    df["mentions_playbook"] = (
        df["rationale"].astype(str) + " " + df["script"].astype(str) + " " + df["rollback"].astype(str)
    ).str.lower().str.contains("playbook")
    df["language_norm"] = df["language"].map(
        lambda v: "missing" if v is None or (isinstance(v, float) and math.isnan(v))
        or str(v).strip() == "" else str(v).strip().lower()
    )
    df["stated_confidence"] = df["confidence"].map(
        lambda v: "missing" if v is None or (isinstance(v, float) and math.isnan(v))
        or str(v).strip() == "" else str(v).strip().lower()
    )
    return df


# ----------------------------------------------------------------------------
# Fact builders
# ----------------------------------------------------------------------------


def per_arm_facts(
    m: pd.DataFrame, arms: list[str], summary: pd.DataFrame,
    dist_csv: pd.DataFrame, runs: pd.DataFrame, lat_csv: pd.DataFrame,
    sood_csv: pd.DataFrame,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for arm in arms:
        sub = m[m["arm"] == arm]
        n = len(sub)
        codes = sub["code"]
        f0 = int((codes == "F0").sum())
        under = int(codes.isin(UNDER).sum())
        danger = int(codes.isin(DANGER).sum())
        a: dict[str, Any] = {"n": n, "alerts": int(sub["alert_id"].nunique())}
        a["samples_per_alert"] = int(sub.groupby("alert_id").size().max()) if n else 0
        a["precision"] = rate_block(f0, n)
        a["under_action"] = rate_block(under, n)
        a["dangerous_action"] = rate_block(danger, n)
        a["failures"] = n - f0
        a["reject_per_hundred"] = int(round(100 * (n - f0) / n)) if n else None
        # cross-check against per_arm_summary.csv and take its CIs
        for metric, blk in (("precision (F0)", "precision"),
                            ("under-action rate (F5, F8)", "under_action"),
                            ("dangerous-action rate (F4, F7)", "dangerous_action")):
            row = summary[(summary["arm"] == arm) & (summary["metric"] == metric)]
            if row.empty:
                warn(f"per_arm_summary.csv has no row for {arm} / {metric}")
                continue
            r = row.iloc[0]
            if int(r["count"]) != a[blk]["count"] or int(r["n"]) != n:
                warn(f"{arm} {metric}: sheet gives {a[blk]['count']}/{n} but "
                     f"per_arm_summary.csv gives {r['count']}/{r['n']} (stale out/?)")
            a[blk]["ci_low_pct"] = r1d(100 * float(r["ci_low"]))
            a[blk]["ci_high_pct"] = r1d(100 * float(r["ci_high"]))
            a[blk]["ci_width_pp"] = r1d(100 * (float(r["ci_high"]) - float(r["ci_low"])))
        # code distribution
        cd: dict[str, Any] = {}
        for c in CODE_IDS:
            k = int((codes == c).sum())
            cd[c] = {"count": k, "pct": pct(k, n), "label": CODE_LABELS[c],
                     "pct_of_failures": pct(k, n - f0) if c != "F0" else None}
            row = dist_csv[(dist_csv["arm"] == arm) & (dist_csv["code"] == c)]
            if not row.empty and int(row.iloc[0]["count"]) != k:
                warn(f"{arm} {c}: sheet {k} vs code_distribution.csv "
                     f"{row.iloc[0]['count']}")
        a["codes"] = cd
        fail_counts = {c: cd[c]["count"] for c in FAILURE_CODES}
        top = max(fail_counts, key=lambda c: (fail_counts[c], -CODE_IDS.index(c)))
        a["top_failure_code"] = top if fail_counts[top] > 0 else None
        a["top_failure_label"] = CODE_LABELS[top] if fail_counts[top] > 0 else None
        a["top_failure_count"] = fail_counts[top]
        a["top_failure_pct"] = pct(fail_counts[top], n)
        ranked = sorted(fail_counts.items(), key=lambda kv: -kv[1])
        a["failure_codes_ranked"] = [f"{c}={k}" for c, k in ranked if k > 0]
        a["codes_unused"] = [c for c in CODE_IDS if cd[c]["count"] == 0]
        a["f1_plus_f2"] = rate_block(cd["F1"]["count"] + cd["F2"]["count"], n)
        # Sood
        sd: dict[str, Any] = {}
        cats = codes.map(sood_category)
        for cat in list(SOOD_ORDER) + ["Consistency", "None"]:
            k = int((cats == cat).sum())
            sd[cat] = {"count": k, "pct": pct(k, n)}
            row = sood_csv[(sood_csv["arm"] == arm) & (sood_csv["sood_category"] == cat)]
            if not row.empty and int(row.iloc[0]["count"]) != k:
                warn(f"{arm} Sood {cat}: sheet {k} vs sood_rollup.csv {row.iloc[0]['count']}")
        fail_cats = {c: sd[c]["count"] for c in SOOD_ORDER}
        topc = max(fail_cats, key=lambda c: fail_cats[c])
        sd["dominant_failure_category"] = topc if fail_cats[topc] > 0 else None
        sd["dominant_failure_pct"] = pct(fail_cats[topc], n)
        a["sood"] = sd
        # severity / reversibility / confidence_annotation / fidelity (primary rater)
        a["severity"] = {s: int((sub["severity"] == s).sum()) for s in SEVERITY_IDS}
        a["severity_other"] = int((~sub["severity"].isin(SEVERITY_IDS)).sum())
        a["severity_s2_plus"] = a["severity"]["S2"] + a["severity"]["S3"]
        a["reversibility"] = {r: int((sub["reversibility"] == r).sum())
                              for r in REVERSIBILITY_IDS}
        a["confidence_annotation"] = {c: int((sub["confidence_annotation"] == c).sum())
                                      for c in CONFIDENCE_IDS}
        a["rationale_fidelity"] = {f: int((sub["rationale_fidelity"] == f).sum())
                                   for f in FIDELITY_IDS}
        fail = sub[sub["code"] != "F0"]
        a["failing_asserted"] = int((fail["confidence_annotation"] == "asserted").sum())
        a["failing_hedged"] = int((fail["confidence_annotation"] == "hedged").sum())
        # generation facts from runs
        rs = runs[runs["arm"] == arm]
        g: dict[str, Any] = {"n_generated": int(len(rs))}
        if len(rs):
            g["model_id"] = sorted(rs["model_id"].dropna().astype(str).unique().tolist())
            g["model_version"] = sorted(rs["model_version"].dropna().astype(str).unique().tolist())
            g["reasoning_detail"] = sorted(rs["reasoning_detail"].dropna().astype(str).unique().tolist())
            g["endpoint"] = sorted(rs["endpoint"].dropna().astype(str).unique().tolist())
            g["prompt_version"] = sorted(rs["prompt_version"].dropna().astype(str).unique().tolist())
            g["strict"] = int((rs["parse_ok"] & ~rs["parse_repaired"]).sum())
            g["repaired"] = int(rs["parse_repaired"].sum())
            g["failed"] = int((~rs["parse_ok"]).sum())
            g["truncated"] = int(rs["truncated"].sum())
            g["finish_reasons"] = dict(Counter(rs["finish_reason"].astype(str)))
            g["strict_pct"] = pct(g["strict"], len(rs))
            g["repaired_pct"] = pct(g["repaired"], len(rs))
            g["failed_pct"] = pct(g["failed"], len(rs))
            s = rs["latency_ms"].dropna() / 1000.0
            g["latency_s"] = {
                "n": int(len(s)), "median": r1d(s.median(), 2), "mean": r1d(s.mean(), 2),
                "p90": r1d(s.quantile(0.9), 2), "min": r1d(s.min(), 2),
                "max": r1d(s.max(), 2), "sd": r1d(s.std(), 2),
            }
            row = lat_csv[lat_csv["arm"] == arm]
            if not row.empty and s.size and abs(float(row.iloc[0]["median_ms"]) / 1000 - s.median()) > 0.01:
                warn(f"{arm} latency median differs from latency.csv")
            g["language"] = dict(Counter(rs["language_norm"]))
            g["script_empty"] = int(rs["script_empty"].sum())
            g["stated_confidence"] = dict(Counter(rs["stated_confidence"]))
        a["generation"] = g
        out[arm] = a
    return out


def scenario_facts(m: pd.DataFrame, arms: list[str], bd: pd.DataFrame,
                   runs: pd.DataFrame) -> dict[str, Any]:
    out: dict[str, Any] = {}
    classes = [c for c in SCENARIO_ORDER if c in set(m["scenario_class"])]
    classes += sorted(set(m["scenario_class"]) - set(classes))
    out["classes"] = classes
    mm = m.merge(runs[["artefact_id", "script_empty", "language_norm"]],
                 on="artefact_id", how="left")
    mm["no_action"] = mm["script_empty"].fillna(False).astype(bool) | (mm["language_norm"] == "none")
    for arm in arms:
        a: dict[str, Any] = {}
        sub = mm[mm["arm"] == arm]
        for cls in classes:
            s = sub[sub["scenario_class"] == cls]
            n = len(s)
            f0 = int((s["code"] == "F0").sum())
            blk = {
                "n": n, "f0": f0, "precision": rate_block(f0, n),
                "under_action": int(s["code"].isin(UNDER).sum()),
                "dangerous_action": int(s["code"].isin(DANGER).sum()),
                "codes": {c: int((s["code"] == c).sum()) for c in CODE_IDS if (s["code"] == c).sum()},
                "no_action_count": int(s["no_action"].sum()),
                "severity": {sv: int((s["severity"] == sv).sum()) for sv in SEVERITY_IDS},
            }
            row = bd[(bd["arm"] == arm) & (bd["scenario_class"] == cls)]
            if row.empty:
                warn(f"scenario_breakdown.csv has no row for {arm}/{cls}")
            else:
                r = row.iloc[0]
                if int(r["correct_f0"]) != f0 or int(r["n"]) != n:
                    warn(f"{arm}/{cls}: sheet {f0}/{n} vs scenario_breakdown.csv "
                         f"{r['correct_f0']}/{r['n']}")
                blk["precision"]["ci_low_pct"] = r1d(100 * float(r["ci_low"]))
                blk["precision"]["ci_high_pct"] = r1d(100 * float(r["ci_high"]))
            a[cls] = blk
        for label, mask in (("benign", ~sub["is_attack"]), ("attack", sub["is_attack"])):
            s = sub[mask]
            n = len(s)
            f0 = int((s["code"] == "F0").sum())
            a[label] = {
                "n": n, "f0": f0, "precision": rate_block(f0, n),
                "under_action": int(s["code"].isin(UNDER).sum()),
                "dangerous_action": int(s["code"].isin(DANGER).sum()),
                "codes": {c: int((s["code"] == c).sum()) for c in CODE_IDS if (s["code"] == c).sum()},
                "no_action_count": int(s["no_action"].sum()),
                "alerts": int(s["alert_id"].nunique()),
                "f0_by_class": {cls: int(((s["scenario_class"] == cls) & (s["code"] == "F0")).sum())
                                for cls in classes if (s["scenario_class"] == cls).any()},
            }
        att = a["attack"]
        cls_with_f0 = [c for c, k in att["f0_by_class"].items() if k > 0]
        a["attack_f0_classes"] = cls_with_f0
        a["attack_f0_single_class"] = cls_with_f0[0] if len(cls_with_f0) == 1 else None
        ben = a["benign"]
        a["benign_all_f0"] = ben["n"] > 0 and ben["f0"] == ben["n"]
        a["benign_all_dangerous"] = ben["n"] > 0 and ben["dangerous_action"] == ben["n"]
        a["benign_all_no_action"] = ben["n"] > 0 and ben["no_action_count"] == ben["n"]
        a["precision_share_from_benign_pct"] = (
            pct(ben["f0"], ben["f0"] + att["f0"]) if (ben["f0"] + att["f0"]) else None
        )
        # outside-the-best-class figures for the "template only succeeds in S2" claim
        if a["attack_f0_single_class"]:
            best = a["attack_f0_single_class"]
            rest = sub[sub["scenario_class"] != best]
            a["outside_best_class"] = {
                "class": best, "n": int(len(rest)),
                "f0": int((rest["code"] == "F0").sum()),
                "dangerous_action": int(rest["code"].isin(DANGER).sum()),
            }
        out[arm] = a
    return out


def agreement_facts(agree: pd.DataFrame | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if agree is None:
        return out
    need(agree, ("measure", "statistic", "estimate", "ci_low", "ci_high",
                 "observed_agreement"), "agreement.csv")
    if "stage" in agree.columns:
        pre = agree[agree["stage"].str.startswith("pre")]
        if not pre.empty:
            agree = pre
    for _, r in agree.iterrows():
        meas = r["measure"].lower()
        stat = r["statistic"].lower()
        if "primary" in meas and "cohen" in stat:
            key = "kappa_primary"
        elif "primary" in meas and "krippendorff" in stat:
            key = "alpha_primary"
        elif "severity" in meas and "cohen" in stat:
            key = "kappa_severity_weighted"
        elif "severity" in meas and "krippendorff" in stat:
            key = "alpha_severity_ordinal"
        else:
            continue
        out[key] = {
            "estimate": r1d(float(r["estimate"]), 3),
            "estimate_2dp": r1d(float(r["estimate"]), 2),
            "ci_low": r1d(float(r["ci_low"]), 3), "ci_high": r1d(float(r["ci_high"]), 3),
            "raw_agreement_pct": r1d(100 * float(r["observed_agreement"])),
            "n": int(float(r["n"])) if "n" in r and r["n"] != "" else None,
            "raters": r.get("raters", ""),
        }
    kp = out.get("kappa_primary", {}).get("estimate")
    ap = out.get("alpha_primary", {}).get("estimate")
    out["primary_code_clears_0_80"] = bool(kp is not None and kp >= 0.80 and (ap is None or ap >= 0.80))
    out["kappa_band"] = (
        None if kp is None else "adequate (>=0.80)" if kp >= 0.80
        else "tentative (0.67-0.80)" if kp >= 0.67 else "inadequate (<0.67)"
    )
    return out


def rater_facts(
    key: pd.DataFrame, sheets: dict[str, pd.DataFrame], primary: str,
    secondary: str | None, arms: list[str], disagreements_csv: pd.DataFrame | None,
) -> dict[str, Any]:
    out: dict[str, Any] = {"primary_label": primary, "secondary_label": secondary,
                           "rater_labels": sorted(sheets)}
    per_rater: dict[str, Any] = {}
    for label, sh in sheets.items():
        j = key.merge(sh, on="artefact_id", how="inner")
        d: dict[str, Any] = {
            "rows_rated": int(len(j)),
            "f0_total": int((j["primary_code"] == "F0").sum()),
            "f0_by_arm": {a: int(((j["arm"] == a) & (j["primary_code"] == "F0")).sum()) for a in arms},
            "attack_f0_by_arm": {a: int(((j["arm"] == a) & j["is_attack"] & (j["primary_code"] == "F0")).sum()) for a in arms},
            "benign_f0_by_arm": {a: int(((j["arm"] == a) & ~j["is_attack"] & (j["primary_code"] == "F0")).sum()) for a in arms},
            "codes_total": {c: int((j["primary_code"] == c).sum()) for c in CODE_IDS},
            "codes_unused": [c for c in CODE_IDS if not (j["primary_code"] == c).any()],
            "flagged": int(j["flag"].sum()),
            "severity": {s: int((j["severity"] == s).sum()) for s in SEVERITY_IDS},
            "reversibility": {r: int((j["reversibility"] == r).sum()) for r in REVERSIBILITY_IDS},
            "confidence_annotation": {c: int((j["confidence_annotation"] == c).sum()) for c in CONFIDENCE_IDS},
            "rationale_fidelity": {f: int((j["rationale_fidelity"] == f).sum()) for f in FIDELITY_IDS},
            "dangerous_total": int(j["primary_code"].isin(DANGER).sum()),
            "under_total": int(j["primary_code"].isin(UNDER).sum()),
        }
        per_rater[label] = d
    out["per_rater"] = per_rater
    if secondary is None:
        out["disagreements"] = None
        return out
    a = key.merge(sheets[primary], on="artefact_id", how="inner")
    b = sheets[secondary][["artefact_id", "primary_code", "severity", "flag", "note",
                           "confidence_annotation", "rationale_fidelity"]]
    j = a.merge(b, on="artefact_id", how="inner", suffixes=("_r1", "_r2"))
    out["overlap_n"] = int(len(j))
    diff = j[j["primary_code_r1"] != j["primary_code_r2"]]
    out["disagreements"] = int(len(diff))
    out["raw_agreement_pct"] = pct(len(j) - len(diff), len(j))
    if disagreements_csv is not None:
        ncsv = int((disagreements_csv.get("reason", pd.Series(dtype=str)).str.contains("primary code")).sum()) \
            if "reason" in disagreements_csv.columns else len(disagreements_csv)
        if ncsv != len(diff):
            warn(f"disagreements: sheets give {len(diff)}, disagreements.csv gives {ncsv}")
    directed = Counter(zip(diff["primary_code_r1"], diff["primary_code_r2"]))
    out["disagreement_pairs_directed"] = [
        {"r1": c1, "r2": c2, "count": k, "affects_precision": ("F0" in (c1, c2)),
         "r1_label": CODE_LABELS[c1], "r2_label": CODE_LABELS[c2]}
        for (c1, c2), k in sorted(directed.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    undirected = Counter(tuple(sorted(p, key=CODE_IDS.index)) for p in
                         zip(diff["primary_code_r1"], diff["primary_code_r2"]))
    out["disagreement_pairs_unordered"] = [
        {"codes": f"{c1}/{c2}", "count": k,
         "pct_of_disagreements": pct(k, len(diff))}
        for (c1, c2), k in sorted(undirected.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    out["disagreements_by_arm"] = {arm: int((diff["arm"] == arm).sum()) for arm in arms}
    out["disagreements_by_class"] = {c: int((diff["scenario_class"] == c).sum())
                                     for c in sorted(diff["scenario_class"].unique())}
    inv_f0 = diff[(diff["primary_code_r1"] == "F0") | (diff["primary_code_r2"] == "F0")]
    out["disagreements_involving_f0"] = int(len(inv_f0))
    out["disagreements_failure_vs_failure"] = int(len(diff) - len(inv_f0))
    r1_only = diff[(diff["primary_code_r1"] == "F0") & (diff["primary_code_r2"] != "F0")]
    r2_only = diff[(diff["primary_code_r1"] != "F0") & (diff["primary_code_r2"] == "F0")]
    out["r1_f0_rejected_by_r2"] = int(len(r1_only))
    out["r2_f0_rejected_by_r1"] = int(len(r2_only))
    out["r1_f0_rejected_by_r2_by_arm"] = {arm: int((r1_only["arm"] == arm).sum()) for arm in arms}
    out["r2_f0_rejected_by_r1_by_arm"] = {arm: int((r2_only["arm"] == arm).sum()) for arm in arms}
    out["one_way_disputes"] = bool(len(r1_only) > 0 and len(r2_only) == 0) or bool(len(r2_only) > 0 and len(r1_only) == 0)
    out["disputed_f0_all_on_attacks"] = bool(len(r1_only) > 0 and r1_only["is_attack"].all())
    out["disputed_f0_all_on_benign"] = bool(len(r1_only) > 0 and (~r1_only["is_attack"]).all())

    def rows(df: pd.DataFrame) -> list[dict[str, Any]]:
        return [
            {"artefact_id": r["artefact_id"], "display_index": r.get("display_index", ""),
             "arm": r["arm"], "alert_id": r["alert_id"], "scenario_class": r["scenario_class"],
             "sample_index": None if pd.isna(r["sample_index"]) else int(r["sample_index"]),
             "r1": r["primary_code_r1"], "r2": r["primary_code_r2"],
             "r1_severity": r["severity_r1"], "r2_severity": r["severity_r2"],
             "r1_note": r.get("note_r1", ""), "r2_note": r.get("note_r2", "")}
            for _, r in df.iterrows()
        ]
    out["r1_f0_rejected_by_r2_list"] = rows(r1_only)
    out["r2_f0_rejected_by_r1_list"] = rows(r2_only)
    out["all_disagreements_list"] = rows(diff)
    # second rater stricter?
    f0_r1 = per_rater[primary]["f0_total"]
    f0_r2 = per_rater[secondary]["f0_total"]
    out["second_rater_stricter_on_f0"] = bool(f0_r2 < f0_r1)
    out["second_rater_direction"] = ("stricter" if f0_r2 < f0_r1 else
                                     "more lenient" if f0_r2 > f0_r1 else "same F0 total")
    # precision floor / ceiling if every disputed F0 resolved against the primary rater
    floor: dict[str, Any] = {}
    for arm in arms + ["all"]:
        sel = j if arm == "all" else j[j["arm"] == arm]
        n = len(sel)
        both = int(((sel["primary_code_r1"] == "F0") & (sel["primary_code_r2"] == "F0")).sum())
        either = int(((sel["primary_code_r1"] == "F0") | (sel["primary_code_r2"] == "F0")).sum())
        r1f0 = int((sel["primary_code_r1"] == "F0").sum())
        r2f0 = int((sel["primary_code_r2"] == "F0").sum())
        att = sel[sel["is_attack"]]
        floor[arm] = {
            "n": n, "r1_f0": r1f0, "r2_f0": r2f0, "f0_both_raters": both,
            "f0_either_rater": either,
            "precision_r1_pct": pct(r1f0, n), "precision_floor_pct": pct(both, n),
            "precision_ceiling_pct": pct(either, n),
            "attack_f0_r1": int((att["primary_code_r1"] == "F0").sum()),
            "attack_f0_r2": int((att["primary_code_r2"] == "F0").sum()),
            "attack_f0_both": int(((att["primary_code_r1"] == "F0") & (att["primary_code_r2"] == "F0")).sum()),
        }
    out["precision_under_adjudication_bounds"] = floor
    # adjudication flags
    out["flags"] = {
        "r1": int(j["flag_r1"].sum()), "r2": int(j["flag_r2"].sum()),
        "both": int((j["flag_r1"] & j["flag_r2"]).sum()),
        "union": int((j["flag_r1"] | j["flag_r2"]).sum()),
        "union_by_arm": {arm: int(((j["flag_r1"] | j["flag_r2"]) & (j["arm"] == arm)).sum()) for arm in arms},
    }
    # severity disagreement
    sd = j[j["severity_r1"] != j["severity_r2"]]
    out["severity_disagreements"] = int(len(sd))
    out["confidence_annotation_disagreements"] = int((j["confidence_annotation_r1"] != j["confidence_annotation_r2"]).sum())
    out["fidelity_disagreements"] = int((j["rationale_fidelity_r1"] != j["rationale_fidelity_r2"]).sum())
    return out


def fisher_facts(comp: pd.DataFrame, arms: list[str]) -> dict[str, Any]:
    need(comp, ("metric", "arm_a", "arm_b", "count_a", "n_a", "count_b", "n_b",
                "fisher_p"), "arm_comparisons.csv")
    n_tests = len(comp)
    thr = 0.05 / n_tests if n_tests else None
    rows = []
    for _, r in comp.iterrows():
        p = float(r["fisher_p"])
        metric = r["metric"]
        short = ("precision" if metric.startswith("precision") else
                 "under_action" if "under" in metric else
                 "dangerous_action" if "dangerous" in metric else metric)
        rows.append({
            "metric": short, "metric_label": metric,
            "arm_a": r["arm_a"], "arm_b": r["arm_b"],
            "a": f"{int(r['count_a'])}/{int(r['n_a'])}", "b": f"{int(r['count_b'])}/{int(r['n_b'])}",
            "prop_a_pct": pct(int(r["count_a"]), int(r["n_a"])),
            "prop_b_pct": pct(int(r["count_b"]), int(r["n_b"])),
            "p": p, "p_text": fmt_p(p), "p_2dp": round(p, 2),
            "odds_ratio": r.get("odds_ratio", ""),
            "significant_0_05": bool(p < 0.05),
            "survives_bonferroni": bool(thr is not None and p < thr),
            "direction": ("A higher" if float(r.get("prop_a", 0) or 0) > float(r.get("prop_b", 0) or 0)
                          else "B higher" if float(r.get("prop_a", 0) or 0) < float(r.get("prop_b", 0) or 0)
                          else "equal"),
        })
    by_key = {f"{x['metric']}.{x['arm_a']}_vs_{x['arm_b']}": x for x in rows}
    return {
        "n_contrasts": n_tests, "bonferroni_threshold": round(thr, 4) if thr else None,
        "n_survive_bonferroni": sum(1 for x in rows if x["survives_bonferroni"]),
        "survivors": [f"{x['metric']} {x['arm_a']} vs {x['arm_b']}" for x in rows if x["survives_bonferroni"]],
        "n_significant_0_05": sum(1 for x in rows if x["significant_0_05"]),
        "contrasts": rows, "by_key": by_key,
    }


def consistency_facts(m: pd.DataFrame, arms: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for arm in arms:
        sub = m[m["arm"] == arm]
        per_alert = sub.groupby("alert_id")
        sizes = per_alert.size()
        if sizes.max() < 2:
            out[arm] = {"applicable": False, "alerts": int(len(sizes))}
            continue
        same = per_alert["code"].agg(lambda s: s.nunique() == 1)
        f0n = per_alert["code"].agg(lambda s: int((s == "F0").sum()))
        cls = per_alert["scenario_class"].first()
        k = int(sizes.max())
        dist = {f"{i}_of_{k}": int((f0n == i).sum()) for i in range(k, -1, -1)}
        alerts_by = {f"{i}_of_{k}": sorted(f0n[f0n == i].index.tolist()) for i in range(k, -1, -1)}
        all_f0_alerts = f0n[f0n == k].index
        out[arm] = {
            "applicable": True, "alerts": int(len(sizes)), "samples_per_alert": k,
            "alerts_all_samples_same_code": int(same.sum()),
            "alerts_all_samples_same_code_pct": pct(int(same.sum()), len(sizes)),
            "alerts_with_mixed_codes": int((~same).sum()),
            "same_code_alerts_by_code": dict(Counter(
                per_alert["code"].first()[same].tolist())),
            "same_code_benign_alerts": int((same & (cls.map(lambda c: str(c).startswith("B")))).sum()),
            "f0_count_distribution": dist,
            "f0_count_alerts": alerts_by,
            "all_f0_alerts_are_benign": bool(len(all_f0_alerts) > 0 and
                                             all(str(cls[a]).startswith("B") for a in all_f0_alerts)),
            "all_f0_alert_classes": dict(Counter(cls[all_f0_alerts].tolist())),
            "alerts_with_any_f0": int((f0n > 0).sum()),
            "alerts_with_no_f0": int((f0n == 0).sum()),
            "bimodal_hint": bool(dist.get(f"{k}_of_{k}", 0) + dist.get(f"0_of_{k}", 0) >= 0.8 * len(sizes)),
        }
    model_arms = [a for a in arms if out[a].get("applicable")]
    if len(model_arms) >= 2:
        ranked = sorted(model_arms, key=lambda a: -out[a]["alerts_all_samples_same_code"])
        out["most_self_consistent_arm"] = ranked[0]
        out["least_self_consistent_arm"] = ranked[-1]
        out["self_consistency_ties"] = bool(out[ranked[0]]["alerts_all_samples_same_code"] ==
                                            out[ranked[-1]]["alerts_all_samples_same_code"])
    return out


def confidence_facts(m: pd.DataFrame, runs: pd.DataFrame, arms: list[str]) -> dict[str, Any]:
    mm = m.merge(runs[["artefact_id", "stated_confidence"]], on="artefact_id", how="left")
    mm["stated_confidence"] = mm["stated_confidence"].fillna("missing")
    out: dict[str, Any] = {}
    levels = sorted(mm["stated_confidence"].unique())

    def block(df: pd.DataFrame) -> dict[str, Any]:
        n = len(df)
        fail = df[df["code"] != "F0"]
        ok = df[df["code"] == "F0"]
        b: dict[str, Any] = {"n": n, "failing": int(len(fail)), "f0": int(len(ok))}
        b["stated_confidence_counts"] = {lv: int((df["stated_confidence"] == lv).sum()) for lv in levels}
        b["failing_by_stated_confidence"] = {lv: int((fail["stated_confidence"] == lv).sum()) for lv in levels}
        b["f0_by_stated_confidence"] = {lv: int((ok["stated_confidence"] == lv).sum()) for lv in levels}
        b["failing_stated_high"] = int((fail["stated_confidence"] == "high").sum())
        b["f0_stated_high"] = int((ok["stated_confidence"] == "high").sum())
        b["rater_asserted"] = int((df["confidence_annotation"] == "asserted").sum())
        b["rater_hedged"] = int((df["confidence_annotation"] == "hedged").sum())
        b["failing_rater_asserted"] = int((fail["confidence_annotation"] == "asserted").sum())
        b["failing_rater_hedged"] = int((fail["confidence_annotation"] == "hedged").sum())
        b["f0_rater_asserted"] = int((ok["confidence_annotation"] == "asserted").sum())
        b["f0_rater_hedged"] = int((ok["confidence_annotation"] == "hedged").sum())
        b["rater_asserted_pct"] = pct(b["rater_asserted"], n)
        b["precision_when_asserted_pct"] = pct(b["f0_rater_asserted"], b["rater_asserted"]) if b["rater_asserted"] else None
        b["precision_when_hedged_pct"] = pct(b["f0_rater_hedged"], b["rater_hedged"]) if b["rater_hedged"] else None
        b["precision_when_stated_high_pct"] = (
            pct(b["f0_stated_high"], b["stated_confidence_counts"].get("high", 0))
            if b["stated_confidence_counts"].get("high", 0) else None)
        return b
    out["all"] = block(mm)
    for arm in arms:
        out[arm] = block(mm[mm["arm"] == arm])
    return out


def language_facts(m: pd.DataFrame, runs: pd.DataFrame, arms: list[str]) -> dict[str, Any]:
    mm = m.merge(runs[["artefact_id", "language_norm", "script_empty", "mentions_playbook"]],
                 on="artefact_id", how="left")
    out: dict[str, Any] = {}
    for arm in arms:
        sub = mm[mm["arm"] == arm]
        ben = sub[~sub["is_attack"]]
        empty_none = sub["script_empty"].fillna(False).astype(bool) & (sub["language_norm"] == "none")
        out[arm] = {
            "language": dict(Counter(sub["language_norm"].fillna("missing"))),
            "script_empty": int(sub["script_empty"].fillna(False).astype(bool).sum()),
            "language_none": int((sub["language_norm"] == "none").sum()),
            "empty_script_language_none": int(empty_none.sum()),
            "empty_script_language_none_on_benign": int((empty_none & ~sub["is_attack"]).sum()),
            "empty_script_language_none_on_attack": int((empty_none & sub["is_attack"]).sum()),
            "benign_n": int(len(ben)),
            "empty_none_on_every_benign": bool(len(ben) > 0 and int((empty_none & ~sub["is_attack"]).sum()) == len(ben)),
            "language_by_code_f0": dict(Counter(sub.loc[sub["code"] == "F0", "language_norm"].fillna("missing"))),
            "mentions_playbook": int(sub["mentions_playbook"].fillna(False).astype(bool).sum()),
        }
    out["arms_with_empty_none_on_every_benign"] = [a for a in arms if out[a]["empty_none_on_every_benign"]]
    out["arms_where_every_artefact_mentions_playbook"] = [
        a for a in arms if out[a]["mentions_playbook"] == int((mm["arm"] == a).sum()) and out[a]["mentions_playbook"] > 0]
    out["arms_where_no_artefact_mentions_playbook"] = [a for a in arms if out[a]["mentions_playbook"] == 0]
    return out


def corpus_facts(m: pd.DataFrame, runs: pd.DataFrame, arms: list[str], summary: pd.DataFrame) -> dict[str, Any]:
    n = len(m)
    f0 = int((m["code"] == "F0").sum())
    danger = int(m["code"].isin(DANGER).sum())
    under = int(m["code"].isin(UNDER).sum())
    out: dict[str, Any] = {
        "n_rated": n, "n_generated": int(len(runs)), "n_alerts": int(m["alert_id"].nunique()),
        "n_arms": len(arms), "arms": arms,
        "model_arms": [a for a in arms if a != "baseline"],
        "precision": rate_block(f0, n), "failures": n - f0,
        "reject_per_hundred": int(round(100 * (n - f0) / n)) if n else None,
        "dangerous_action": rate_block(danger, n), "under_action": rate_block(under, n),
        "codes": {c: int((m["code"] == c).sum()) for c in CODE_IDS},
        "codes_unused_primary": [c for c in CODE_IDS if not (m["code"] == c).any()],
        "severity": {s: int((m["severity"] == s).sum()) for s in SEVERITY_IDS},
        "reversibility": {r: int((m["reversibility"] == r).sum()) for r in REVERSIBILITY_IDS},
        "confidence_annotation": {c: int((m["confidence_annotation"] == c).sum()) for c in CONFIDENCE_IDS},
        "rationale_fidelity": {f: int((m["rationale_fidelity"] == f).sum()) for f in FIDELITY_IDS},
        "strict": int((runs["parse_ok"] & ~runs["parse_repaired"]).sum()),
        "repaired": int(runs["parse_repaired"].sum()),
        "failed": int((~runs["parse_ok"]).sum()),
        "truncated": int(runs["truncated"].sum()),
        "benign_alerts": int(m.loc[~m["is_attack"], "alert_id"].nunique()),
        "attack_alerts": int(m.loc[m["is_attack"], "alert_id"].nunique()),
        "benign_artefacts": int((~m["is_attack"]).sum()),
        "attack_artefacts": int(m["is_attack"].sum()),
        "alerts_by_class": {c: int(m.loc[m["scenario_class"] == c, "alert_id"].nunique())
                            for c in sorted(m["scenario_class"].unique())},
    }
    out["severity_s2_plus"] = out["severity"]["S2"] + out["severity"]["S3"]
    out["severity_s3"] = out["severity"]["S3"]
    out["any_s3"] = out["severity"]["S3"] > 0
    out["irreversible"] = out["reversibility"]["irreversible"]
    out["any_irreversible"] = out["irreversible"] > 0
    out["reversible_with_effort"] = out["reversibility"]["reversible-with-effort"]
    fail_counts = {c: out["codes"][c] for c in FAILURE_CODES}
    topc = max(fail_counts, key=lambda c: (fail_counts[c], -CODE_IDS.index(c)))
    out["top_failure_code"] = topc if fail_counts[topc] else None
    out["top_failure_label"] = CODE_LABELS[topc] if fail_counts[topc] else None
    out["top_failure_count"] = fail_counts[topc]
    out["top_failure_pct_of_failures"] = pct(fail_counts[topc], n - f0)
    out["failure_codes_ranked"] = [f"{c}={k}" for c, k in sorted(fail_counts.items(), key=lambda kv: -kv[1]) if k]
    out["worst_severity_observed"] = next((s for s in reversed(SEVERITY_IDS) if out["severity"][s] > 0), None)
    out["worst_severity_count"] = out["severity"].get(out["worst_severity_observed"], 0) if out["worst_severity_observed"] else 0
    # which arm holds the S0 ratings, which arm holds the unfaithful rationales
    s0_by_arm = {a: int(((m["arm"] == a) & (m["severity"] == "S0")).sum()) for a in arms}
    out["s0_by_arm"] = s0_by_arm
    out["s0_all_in_one_arm"] = next((a for a, k in s0_by_arm.items() if k == out["severity"]["S0"] and k > 0), None)
    unf_by_arm = {a: int(((m["arm"] == a) & (m["rationale_fidelity"] == "unfaithful")).sum()) for a in arms}
    out["unfaithful_by_arm"] = unf_by_arm
    out["unfaithful_all_in_one_arm"] = next((a for a, k in unf_by_arm.items()
                                             if k == out["rationale_fidelity"]["unfaithful"] and k > 0), None)
    row = summary[(summary["arm"] == "all arms") & (summary["metric"] == "precision (F0)")]
    if not row.empty:
        r = row.iloc[0]
        if int(r["count"]) != f0:
            warn(f"all-arms F0 {f0} vs per_arm_summary.csv {r['count']}")
        out["precision"]["ci_low_pct"] = r1d(100 * float(r["ci_low"]))
        out["precision"]["ci_high_pct"] = r1d(100 * float(r["ci_high"]))
    for metric, blk in (("dangerous-action rate (F4, F7)", "dangerous_action"),
                        ("under-action rate (F5, F8)", "under_action")):
        row = summary[(summary["arm"] == "all arms") & (summary["metric"] == metric)]
        if not row.empty:
            out[blk]["ci_low_pct"] = r1d(100 * float(row.iloc[0]["ci_low"]))
            out[blk]["ci_high_pct"] = r1d(100 * float(row.iloc[0]["ci_high"]))
    return out


def derived_facts(arms: dict[str, Any], corpus: dict[str, Any], arm_list: list[str],
                  fisher: dict[str, Any]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    model_arms = [a for a in arm_list if a != "baseline"]
    by_prec = sorted(arm_list, key=lambda a: -arms[a]["precision"]["count"] / max(arms[a]["n"], 1))
    by_danger = sorted(arm_list, key=lambda a: -arms[a]["dangerous_action"]["count"] / max(arms[a]["n"], 1))
    d["precision_ranking"] = by_prec
    d["best_precision_arm"] = by_prec[0]
    d["worst_precision_arm"] = by_prec[-1]
    d["dangerous_ranking"] = by_danger
    d["most_dangerous_arm"] = by_danger[0]
    d["least_dangerous_arm"] = by_danger[-1]
    d["baseline_most_dangerous"] = by_danger[0] == "baseline"
    d["precision_all_arms_pct"] = {a: arms[a]["precision"]["pct"] for a in arm_list}
    d["dangerous_all_arms_pct"] = {a: arms[a]["dangerous_action"]["pct"] for a in arm_list}
    d["under_all_arms_pct"] = {a: arms[a]["under_action"]["pct"] for a in arm_list}
    d["ci_width_pp_precision"] = {a: arms[a]["precision"]["ci_width_pp"] for a in arm_list}
    d["top_failure_code_by_arm"] = {a: arms[a]["top_failure_code"] for a in arm_list}
    d["top_failure_codes_distinct"] = len({arms[a]["top_failure_code"] for a in arm_list}) == len(arm_list)
    d["dominant_sood_by_arm"] = {a: arms[a]["sood"]["dominant_failure_category"] for a in arm_list}
    d["factual_pct_by_arm"] = {a: arms[a]["sood"]["Factual"]["pct"] for a in arm_list}
    d["logical_pct_by_arm"] = {a: arms[a]["sood"]["Logical"]["pct"] for a in arm_list}
    d["arms_with_no_factual_failure"] = [a for a in arm_list if arms[a]["sood"]["Factual"]["count"] == 0]
    d["arms_with_no_f1_no_f2"] = [a for a in arm_list if arms[a]["codes"]["F1"]["count"] == 0 and arms[a]["codes"]["F2"]["count"] == 0]
    d["codes_unused_all_arms"] = corpus["codes_unused_primary"]
    d["sood_categories_unused"] = [c for c in SOOD_ORDER
                                   if all(arms[a]["sood"][c]["count"] == 0 for a in arm_list)]
    d["reject_per_hundred_all"] = corpus["reject_per_hundred"]
    d["reject_per_hundred_by_arm"] = {a: arms[a]["reject_per_hundred"] for a in arm_list}
    if model_arms:
        best_model = max(model_arms, key=lambda a: arms[a]["precision"]["count"] / max(arms[a]["n"], 1))
        d["best_model_arm"] = best_model
        d["reject_per_hundred_best_model"] = arms[best_model]["reject_per_hundred"]
    # dangerous ratio baseline vs best model
    if "baseline" in arm_list and model_arms:
        bm = d["best_model_arm"]
        bp = arms["baseline"]["dangerous_action"]["pct"] or 0
        mp = arms[bm]["dangerous_action"]["pct"] or 0
        d["dangerous_ratio_baseline_over_best_model"] = round(bp / mp, 1) if mp else None
        d["dangerous_order_of_magnitude"] = bool(mp and bp / mp >= 10)
    # do the precision / dangerous-action Wilson intervals of two arms overlap?
    for metric in ("precision", "dangerous_action"):
        ov: dict[str, bool] = {}
        for i, a in enumerate(arm_list):
            for b in arm_list[i + 1:]:
                lo_a, hi_a = arms[a][metric]["ci_low_pct"], arms[a][metric]["ci_high_pct"]
                lo_b, hi_b = arms[b][metric]["ci_low_pct"], arms[b][metric]["ci_high_pct"]
                ov[f"{a}_vs_{b}"] = bool(lo_a <= hi_b and lo_b <= hi_a)
        d[f"{metric}_ci_overlap"] = ov
    # latency ratio between the two model arms
    lat = {a: arms[a]["generation"].get("latency_s", {}).get("median") for a in model_arms}
    d["latency_median_s_by_arm"] = {a: arms[a]["generation"].get("latency_s", {}).get("median") for a in arm_list}
    if len(model_arms) == 2 and all(lat[a] for a in model_arms):
        slow, fast = sorted(model_arms, key=lambda a: -lat[a])
        d["slower_model_arm"] = slow
        d["faster_model_arm"] = fast
        d["latency_ratio_slow_over_fast"] = round(lat[slow] / lat[fast], 1)
        d["latency_ratio_rounded"] = int(round(lat[slow] / lat[fast]))
        fast_prec = arms[fast]["precision"]["pct"] or 0
        slow_prec = arms[slow]["precision"]["pct"] or 0
        d["faster_arm_also_more_precise"] = bool(fast_prec > slow_prec)
        d["latency_trades_against_quality"] = bool(fast_prec > slow_prec)
    bl = arms.get("baseline", {}).get("generation", {}).get("latency_s", {})
    d["baseline_latency_max_ms"] = round(bl["max"] * 1000, 2) if bl.get("max") is not None else None
    d["baseline_under_0_1_ms"] = bool(bl.get("max") is not None and bl["max"] * 1000 < 0.1)
    # headline fisher lookups
    bk = fisher.get("by_key", {})

    def p_of(metric: str, a: str, b: str) -> dict[str, Any] | None:
        return bk.get(f"{metric}.{a}_vs_{b}") or bk.get(f"{metric}.{b}_vs_{a}")
    if len(model_arms) == 2:
        m1, m2 = model_arms
        d["p_precision_model_vs_model"] = (p_of("precision", m1, m2) or {}).get("p_text")
        d["p_dangerous_model_vs_model"] = (p_of("dangerous_action", m1, m2) or {}).get("p_text")
    for a in model_arms:
        d[f"p_precision_{a}_vs_baseline"] = (p_of("precision", a, "baseline") or {}).get("p_text")
        d[f"p_dangerous_{a}_vs_baseline"] = (p_of("dangerous_action", a, "baseline") or {}).get("p_text")
        d[f"p_under_{a}_vs_baseline"] = (p_of("under_action", a, "baseline") or {}).get("p_text")
        d[f"precision_{a}_vs_baseline_significant"] = (p_of("precision", a, "baseline") or {}).get("significant_0_05")
    return d


# ----------------------------------------------------------------------------
# Flattening and markdown
# ----------------------------------------------------------------------------


def flatten(obj: Any, prefix: str = "", out: dict[str, Any] | None = None) -> dict[str, Any]:
    if out is None:
        out = OrderedDict()
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(obj, list):
        if all(not isinstance(x, (dict, list)) for x in obj):
            out[prefix] = obj
        else:
            for i, v in enumerate(obj):
                flatten(v, f"{prefix}[{i}]", out)
    else:
        out[prefix] = obj
    return out


def write_markdown(path: Path, facts: dict[str, Any], flat: dict[str, Any]) -> None:
    lines: list[str] = ["# facts.md", "",
                        f"Generated by extract_facts.py. Primary rater: "
                        f"{facts['raters']['primary_label']}; second rater: "
                        f"{facts['raters']['secondary_label']}.", ""]
    arms = facts["corpus"]["arms"]
    lines += ["## Headline per arm", "",
              "| arm | model | n | F0 | precision % [CI] | under % | dangerous % [CI] | top failure | strict/rep/fail/trunc | latency median s |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for a in arms:
        x = facts["arms"][a]
        g = x["generation"]
        p = x["precision"]; dn = x["dangerous_action"]; u = x["under_action"]
        lines.append(
            f"| {a} | {', '.join(g.get('model_id', []))} | {x['n']} | {p['count']} | "
            f"{p['pct']} [{p['ci_low_pct']}, {p['ci_high_pct']}] | {u['count']} ({u['pct']}) | "
            f"{dn['count']} ({dn['pct']}) [{dn['ci_low_pct']}, {dn['ci_high_pct']}] | "
            f"{x['top_failure_code']} {x['top_failure_count']} ({x['top_failure_pct']}%) | "
            f"{g.get('strict')}/{g.get('repaired')}/{g.get('failed')}/{g.get('truncated')} | "
            f"{g.get('latency_s', {}).get('median')} |")
    lines += ["", "## Code distribution (primary rater)", "",
              "| code | " + " | ".join(arms) + " | all |", "|---|" + "---|" * (len(arms) + 1)]
    for c in CODE_IDS:
        cells = [f"{facts['arms'][a]['codes'][c]['count']} ({facts['arms'][a]['codes'][c]['pct']}%)" for a in arms]
        lines.append(f"| {c} {CODE_LABELS[c]} | " + " | ".join(cells) + f" | {facts['corpus']['codes'][c]} |")
    lines += ["", "## Scenario breakdown", "",
              "| arm | class | n | F0 | precision % [CI] | under | dangerous | no-action |", "|---|---|---|---|---|---|---|---|"]
    for a in arms:
        for cls in facts["scenario"]["classes"] + ["benign", "attack"]:
            s = facts["scenario"][a][cls]
            p = s["precision"]
            lines.append(f"| {a} | {cls} | {s['n']} | {s['f0']} | {p['pct']} [{p['ci_low_pct']}, {p['ci_high_pct']}] | "
                         f"{s['under_action']} | {s['dangerous_action']} | {s['no_action_count']} |")
    lines += ["", "## Fisher contrasts", "",
              f"n = {facts['fisher']['n_contrasts']}, Bonferroni threshold {facts['fisher']['bonferroni_threshold']}, "
              f"{facts['fisher']['n_survive_bonferroni']} survive.", "",
              "| metric | A | B | A | B | p | Bonferroni |", "|---|---|---|---|---|---|---|"]
    for c in facts["fisher"]["contrasts"]:
        lines.append(f"| {c['metric']} | {c['arm_a']} | {c['arm_b']} | {c['a']} | {c['b']} | {c['p_text']} | "
                     f"{'yes' if c['survives_bonferroni'] else 'no'} |")
    ag = facts["agreement"]
    lines += ["", "## Agreement", ""]
    for k in ("kappa_primary", "alpha_primary", "kappa_severity_weighted", "alpha_severity_ordinal"):
        if k in ag:
            v = ag[k]
            lines.append(f"- {k}: {v['estimate']} [{v['ci_low']}, {v['ci_high']}], raw agreement {v['raw_agreement_pct']}%")
    rt = facts["raters"]
    if rt.get("disagreements") is not None:
        lines += [f"- disagreements: {rt['disagreements']} of {rt['overlap_n']}; involving F0: {rt['disagreements_involving_f0']}; "
                  f"failure-vs-failure: {rt['disagreements_failure_vs_failure']}",
                  f"- r1 F0 rejected by r2: {rt['r1_f0_rejected_by_r2']} {rt['r1_f0_rejected_by_r2_by_arm']}; "
                  f"converse: {rt['r2_f0_rejected_by_r1']} {rt['r2_f0_rejected_by_r1_by_arm']}; "
                  f"second rater {rt['second_rater_direction']}",
                  f"- F0 totals: " + ", ".join(f"{l}={rt['per_rater'][l]['f0_total']}" for l in rt['per_rater']),
                  f"- flags: {rt['flags']}", "",
                  "| R1 | R2 | n | affects precision |", "|---|---|---|---|"]
        for p in rt["disagreement_pairs_directed"]:
            lines.append(f"| {p['r1']} | {p['r2']} | {p['count']} | {'yes' if p['affects_precision'] else 'no'} |")
        lines += ["", "Disputed F0 artefacts (r1 F0, r2 not):", ""]
        for r in rt["r1_f0_rejected_by_r2_list"]:
            lines.append(f"- {r['arm']} {r['alert_id']} {r['scenario_class']} sample {r['sample_index']}: "
                         f"r1 {r['r1']} / r2 {r['r2']} (display {r['display_index']})")
    lines += ["", "## Self-consistency", ""]
    for a in arms:
        c = facts["consistency"][a]
        if c.get("applicable"):
            lines.append(f"- {a}: same code on {c['alerts_all_samples_same_code']} of {c['alerts']} alerts; "
                         f"F0 distribution {c['f0_count_distribution']}; all-F0 alerts benign: {c['all_f0_alerts_are_benign']}")
    cf = facts["confidence"]["all"]
    lines += ["", "## Confidence", "",
              f"- rater confidence_annotation: asserted {cf['rater_asserted']} of {cf['n']}; "
              f"failing {cf['failing']}: asserted {cf['failing_rater_asserted']}, hedged {cf['failing_rater_hedged']}",
              f"- model stated confidence: {cf['stated_confidence_counts']}; failing by stated: {cf['failing_by_stated_confidence']}",
              "", "## Corpus", ""]
    co = facts["corpus"]
    lines += [f"- rated {co['n_rated']}, F0 {co['precision']['count']} ({co['precision']['pct']}%), "
              f"dangerous {co['dangerous_action']['count']}, under {co['under_action']['count']}, "
              f"reject/100 {co['reject_per_hundred']}",
              f"- severity {co['severity']}, reversibility {co['reversibility']}, fidelity {co['rationale_fidelity']}",
              f"- codes unused (primary): {co['codes_unused_primary']}; S0 all in arm: {co['s0_all_in_one_arm']}; "
              f"unfaithful all in arm: {co['unfaithful_all_in_one_arm']}",
              "", "## Derived", ""]
    for k, v in facts["derived"].items():
        lines.append(f"- {k}: {v}")
    if facts["warnings"]:
        lines += ["", "## Warnings", ""] + [f"- {w}" for w in facts["warnings"]]
    lines += ["", "## All flat keys", "", "| key | value |", "|---|---|"]
    for k, v in flat.items():
        if k.startswith("raters.all_disagreements_list") or k.endswith("_note"):
            continue
        lines.append(f"| `{k}` | {json.dumps(v) if not isinstance(v, str) else v} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ----------------------------------------------------------------------------
# Main assembly
# ----------------------------------------------------------------------------


def build(rating_dir: Path, analysis_out: Path, run_dirs: list[Path],
          primary_override: str | None) -> dict[str, Any]:
    WARNINGS.clear()
    key = load_key(rating_dir)
    sheet_paths = discover_sheets(rating_dir)
    sheets = {label: load_sheet(p, label) for label, p in sheet_paths.items()}
    if primary_override:
        if primary_override not in sheets:
            die(f"--primary {primary_override} not among rater sheets {sorted(sheets)}")
        primary = primary_override
    elif "r1" in sheets:
        primary = "r1"
    else:
        primary = sorted(sheets)[0]
        warn(f"no rater_r1_ratings.csv; using '{primary}' as primary rater")
    others = [l for l in sorted(sheets) if l != primary]
    secondary = "r2" if "r2" in others else (others[0] if others else None)
    if len(others) > 1:
        warn(f"more than two rater sheets; pairwise facts use {primary} vs {secondary}")

    csvs: dict[str, pd.DataFrame | None] = {}
    for name in REQUIRED_CSVS:
        csvs[name] = read_csv(analysis_out / name, f"analyse.py output {name}")
    for name in OPTIONAL_CSVS:
        csvs[name] = read_csv(analysis_out / name, f"analyse.py output {name}", required=False)
    runs = load_runs(run_dirs)

    # merged primary frame
    pr = sheets[primary]
    m = key.merge(pr, on="artefact_id", how="inner")
    m = m.rename(columns={"primary_code": "code"})
    if len(m) != len(key):
        warn(f"{len(key) - len(m)} artefacts in key.csv have no primary code from {primary}")
    unknown_runs = set(m["artefact_id"]) - set(runs["artefact_id"])
    if unknown_runs:
        warn(f"{len(unknown_runs)} rated artefacts not found in --runs JSONL")
    frame = csvs["analysis_frame.csv"]
    assert frame is not None
    need(frame, ("artefact_id", "arm", "code"), "analysis_frame.csv")
    fr = frame.set_index("artefact_id")["code"]
    mism = sum(1 for aid, c in zip(m["artefact_id"], m["code"]) if aid in fr.index and fr[aid] != c)
    if mism:
        warn(f"{mism} artefacts have a different code in analysis_frame.csv than in the "
             f"{primary} sheet: out/ is stale or adjudicated.csv was applied")
    arms = order_arms(m["arm"])

    facts: dict[str, Any] = OrderedDict()
    facts["meta"] = {
        "rating_dir": str(rating_dir), "analysis_out": str(analysis_out),
        "runs": [str(d) for d in run_dirs], "primary_rater": primary,
        "secondary_rater": secondary, "arms": arms,
        "arm_role": {a: ("baseline" if a == "baseline" else "model") for a in arms},
        "prompt_version": sorted(runs["prompt_version"].dropna().astype(str).unique().tolist()),
        "prompt_fingerprint": sorted(runs["prompt_fingerprint"].dropna().astype(str).unique().tolist()),
        "harness_version": sorted(runs["harness_version"].dropna().astype(str).unique().tolist()) if "harness_version" in runs else [],
        "definitions": {
            "precision": "share of artefacts coded F0 by the primary rater",
            "under_action": "F5+F8", "dangerous_action": "F4+F7",
            "benign": "scenario_class B1 / is_true_positive false", "attack": "S1+S2+S3",
            "asserted_hedged": "rater confidence_annotation column (thesis calls this stated confidence)",
            "stated_confidence": "model's own confidence field in artefact JSON",
            "no_action": "empty script or language none",
            "self_consistent": "all samples of an alert share one primary code",
            "affects_precision": "disagreement where exactly one rater coded F0",
        },
    }
    facts["arms"] = per_arm_facts(m, arms, csvs["per_arm_summary.csv"], csvs["code_distribution.csv"],
                                  runs, csvs["latency.csv"], csvs["sood_rollup.csv"])
    facts["corpus"] = corpus_facts(m, runs, arms, csvs["per_arm_summary.csv"])
    facts["scenario"] = scenario_facts(m, arms, csvs["scenario_breakdown.csv"], runs)
    facts["agreement"] = agreement_facts(csvs["agreement.csv"])
    facts["raters"] = rater_facts(key, sheets, primary, secondary, arms, csvs["disagreements.csv"])
    facts["fisher"] = fisher_facts(csvs["arm_comparisons.csv"], arms)
    facts["consistency"] = consistency_facts(m, arms)
    facts["confidence"] = confidence_facts(m, runs, arms)
    facts["language"] = language_facts(m, runs, arms)
    facts["derived"] = derived_facts(facts["arms"], facts["corpus"], arms, facts["fisher"])
    facts["warnings"] = list(WARNINGS)
    return facts


def write_outputs(facts: dict[str, Any], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    flat = flatten({k: v for k, v in facts.items() if k not in ("meta", "warnings")})
    payload = OrderedDict([("meta", facts["meta"]), ("flat", flat), ("detail", facts),
                           ("warnings", facts["warnings"])])
    out.write_text(json.dumps(payload, indent=1, default=str), encoding="utf-8")
    write_markdown(out.with_name("facts.md"), facts, flat)
    print(f"wrote {out} ({len(flat)} flat keys) and {out.with_name('facts.md')}")
    if facts["warnings"]:
        print(f"{len(facts['warnings'])} warning(s), see facts.json[warnings]")


# ----------------------------------------------------------------------------
# Self test on the 2026-09-07 data
# ----------------------------------------------------------------------------

#: The self test targets the earlier pilot study (7 September 2026, arms
#: gemini / ollama / baseline), whose data is not part of this release.
#: Point SELFTEST_ROOT at a directory holding rating/, out/ and runs/ to
#: run it; the checks below are otherwise documentation of what was verified.
SELFTEST_ROOT = Path(os.environ.get("SELFTEST_ROOT", "selftest-data"))
SELFTEST_RATING = SELFTEST_ROOT / "rating"
SELFTEST_OUT = SELFTEST_ROOT / "out"
SELFTEST_RUNS = [SELFTEST_ROOT / "runs" / f"final-{a}" for a in ("gemini", "ollama", "baseline")]
SELFTEST_JSON = SELFTEST_ROOT / "facts.json"


def selftest() -> int:
    facts = build(SELFTEST_RATING, SELFTEST_OUT, SELFTEST_RUNS, primary_override="r1")
    write_outputs(facts, SELFTEST_JSON)
    A = facts["arms"]; S = facts["scenario"]; R = facts["raters"]; G = facts["agreement"]
    C = facts["confidence"]; K = facts["consistency"]; D = facts["derived"]; F = facts["fisher"]
    checks: list[tuple[str, Any, Any]] = [
        ("gemini precision 19/54", (A["gemini"]["precision"]["count"], A["gemini"]["n"]), (19, 54)),
        ("gemini precision 35.2%", A["gemini"]["precision"]["pct"], 35.2),
        ("ollama precision 0/54", (A["ollama"]["precision"]["count"], A["ollama"]["n"]), (0, 54)),
        ("baseline precision 3/18 = 16.7%", (A["baseline"]["precision"]["count"], A["baseline"]["precision"]["pct"]), (3, 16.7)),
        ("gemini precision CI [23.8, 48.5]", (A["gemini"]["precision"]["ci_low_pct"], A["gemini"]["precision"]["ci_high_pct"]), (23.8, 48.5)),
        ("kappa 0.859", G["kappa_primary"]["estimate"], 0.859),
        ("kappa CI [0.789, 0.926]", (G["kappa_primary"]["ci_low"], G["kappa_primary"]["ci_high"]), (0.789, 0.926)),
        ("weighted kappa severity 0.939", G["kappa_severity_weighted"]["estimate"], 0.939),
        ("raw agreement 88.9%", G["kappa_primary"]["raw_agreement_pct"], 88.9),
        ("raw agreement from sheets 88.9%", R["raw_agreement_pct"], 88.9),
        ("gemini F2 = 23", A["gemini"]["codes"]["F2"]["count"], 23),
        ("gemini top failure code F2", A["gemini"]["top_failure_code"], "F2"),
        ("ollama F1 = 35", A["ollama"]["codes"]["F1"]["count"], 35),
        ("ollama F1+F2 = 85.2%", A["ollama"]["f1_plus_f2"]["pct"], 85.2),
        ("baseline F4 = 8", A["baseline"]["codes"]["F4"]["count"], 8),
        ("dangerous 5.6/9.3/61.1%", tuple(A[a]["dangerous_action"]["pct"] for a in ("gemini", "ollama", "baseline")), (5.6, 9.3, 61.1)),
        ("dangerous counts 3/5/11", tuple(A[a]["dangerous_action"]["count"] for a in ("gemini", "ollama", "baseline")), (3, 5, 11)),
        ("under-action counts 1/0/3", tuple(A[a]["under_action"]["count"] for a in ("gemini", "ollama", "baseline")), (1, 0, 3)),
        ("gemini B1 18/18", (S["gemini"]["B1"]["f0"], S["gemini"]["B1"]["n"]), (18, 18)),
        ("gemini attacks 1/36", (S["gemini"]["attack"]["f0"], S["gemini"]["attack"]["n"]), (1, 36)),
        ("gemini attack precision 2.8%", S["gemini"]["attack"]["precision"]["pct"], 2.8),
        ("baseline benign 6/6 dangerous", S["baseline"]["benign"]["dangerous_action"], 6),
        ("baseline attack F0 all S2", S["baseline"]["attack_f0_single_class"], "S2"),
        ("baseline outside S2 dangerous 11/14", (S["baseline"]["outside_best_class"]["dangerous_action"], S["baseline"]["outside_best_class"]["n"]), (11, 14)),
        ("113 of 126 asserted (rater annotation)", (C["all"]["rater_asserted"], C["all"]["n"]), (113, 126)),
        ("95 of 104 failing asserted", (C["all"]["failing_rater_asserted"], C["all"]["failing"]), (95, 104)),
        ("9 failing hedged", C["all"]["failing_rater_hedged"], 9),
        ("gemini self-consistent 10 of 18", K["gemini"]["alerts_all_samples_same_code"], 10),
        ("ollama self-consistent 12 of 18", K["ollama"]["alerts_all_samples_same_code"], 12),
        ("gemini F0 dist 6/0/1/11", tuple(K["gemini"]["f0_count_distribution"][k] for k in ("3_of_3", "2_of_3", "1_of_3", "0_of_3")), (6, 0, 1, 11)),
        ("gemini all-F0 alerts are benign", K["gemini"]["all_f0_alerts_are_benign"], True),
        ("r1 F0 total 22", R["per_rater"]["r1"]["f0_total"], 22),
        ("r2 F0 total 19", R["per_rater"]["r2"]["f0_total"], 19),
        ("14 disagreements", R["disagreements"], 14),
        ("11 failure-vs-failure disagreements", R["disagreements_failure_vs_failure"], 11),
        ("3 r1-F0 rejected by r2, 0 converse", (R["r1_f0_rejected_by_r2"], R["r2_f0_rejected_by_r1"]), (3, 0)),
        ("rejected by arm gemini 1, baseline 2", (R["r1_f0_rejected_by_r2_by_arm"]["gemini"], R["r1_f0_rejected_by_r2_by_arm"]["baseline"]), (1, 2)),
        ("floor precision all 19, gemini 18, baseline 1", (R["precision_under_adjudication_bounds"]["all"]["f0_both_raters"], R["precision_under_adjudication_bounds"]["gemini"]["f0_both_raters"], R["precision_under_adjudication_bounds"]["baseline"]["f0_both_raters"]), (19, 18, 1)),
        ("gemini attack F0 under r2 = 0", R["precision_under_adjudication_bounds"]["gemini"]["attack_f0_r2"], 0),
        ("disputed F0 all on attacks", R["disputed_f0_all_on_attacks"], True),
        ("flags 36/40/18/58", (R["flags"]["r1"], R["flags"]["r2"], R["flags"]["both"], R["flags"]["union"]), (36, 40, 18, 58)),
        ("latency medians 36.5 / 8.8 s", (round(A["gemini"]["generation"]["latency_s"]["median"], 1), round(A["ollama"]["generation"]["latency_s"]["median"], 1)), (36.5, 8.8)),
        ("latency ratio ~4", D["latency_ratio_rounded"], 4),
        ("baseline under 0.1 ms", D["baseline_under_0_1_ms"], True),
        ("ollama parse 22 strict / 29 repaired / 3 failed", (A["ollama"]["generation"]["strict"], A["ollama"]["generation"]["repaired"], A["ollama"]["generation"]["failed"]), (22, 29, 3)),
        ("severity S2 = 89, S3 = 0", (facts["corpus"]["severity"]["S2"], facts["corpus"]["severity"]["S3"]), (89, 0)),
        ("gemini holds all 18 S0", (facts["corpus"]["s0_all_in_one_arm"], facts["corpus"]["severity"]["S0"]), ("gemini", 18)),
        ("irreversible 0, reversible-with-effort 50", (facts["corpus"]["irreversible"], facts["corpus"]["reversible_with_effort"]), (0, 50)),
        ("fidelity 50/70/6, unfaithful all ollama", (facts["corpus"]["rationale_fidelity"]["faithful"], facts["corpus"]["rationale_fidelity"]["partially-faithful"], facts["corpus"]["rationale_fidelity"]["unfaithful"], facts["corpus"]["unfaithful_all_in_one_arm"]), (50, 70, 6, "ollama")),
        ("corpus F0 22, dangerous 19", (facts["corpus"]["precision"]["count"], facts["corpus"]["dangerous_action"]["count"]), (22, 19)),
        ("reject per hundred 83 / gemini 65", (D["reject_per_hundred_all"], D["reject_per_hundred_by_arm"]["gemini"]), (83, 65)),
        ("codes unused F3, F8", facts["corpus"]["codes_unused_primary"], ["F3", "F8"]),
        ("Sood factual 48.1 / 85.2, logical baseline 61.1", (D["factual_pct_by_arm"]["gemini"], D["factual_pct_by_arm"]["ollama"], D["logical_pct_by_arm"]["baseline"]), (48.1, 85.2, 61.1)),
        ("Fisher: 3 of 9 survive Bonferroni 0.0056", (F["n_contrasts"], F["n_survive_bonferroni"], F["bonferroni_threshold"]), (9, 3, 0.0056)),
        ("p gemini vs baseline precision 0.236", F["by_key"]["precision.gemini_vs_baseline"]["p_text"], "0.236"),
        ("p gemini vs ollama precision <0.001", F["by_key"]["precision.gemini_vs_ollama"]["p_text"], "<0.001"),
        ("gemini empty script + language none on every benign", facts["language"]["gemini"]["empty_none_on_every_benign"], True),
        ("CI widths ~25 pp gemini, ~33 baseline", (round(A["gemini"]["precision"]["ci_width_pp"]), round(A["baseline"]["precision"]["ci_width_pp"])), (25, 33)),
        ("model ids", (A["gemini"]["generation"]["model_id"], A["ollama"]["generation"]["model_id"]), (["gemini-2.5-pro"], ["llama3:8b"])),
        ("corpus largest failure class F1 (38) then F2 (34)", facts["corpus"]["failure_codes_ranked"][:2], ["F1=38", "F2=34"]),
        ("precision CIs overlap gemini vs baseline", D["precision_ci_overlap"]["gemini_vs_baseline"], True),
        ("only baseline artefacts say playbook (18/18)", (facts["language"]["arms_where_every_artefact_mentions_playbook"], facts["language"]["arms_where_no_artefact_mentions_playbook"]), (["baseline"], ["gemini", "ollama"])),
    ]
    fails = 0
    for name, got, want in checks:
        ok = got == want
        fails += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'}  {name}: got {got!r}" + ("" if ok else f", expected {want!r}"))
    print(f"selftest: {len(checks) - fails} passed, {fails} failed")
    return 1 if fails else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rating-dir", default="../harness/rating")
    p.add_argument("--analysis-out", default="out")
    p.add_argument("--runs", nargs="*", default=[])
    p.add_argument("--out", default="out/facts.json")
    p.add_argument("--primary", default=None,
                   help="rater label to treat as primary (default r1, else first alphabetically)")
    p.add_argument("--selftest", action="store_true", help="run against the 2026-09-07 data and verify known values")
    args = p.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.runs:
        die("--runs is required (one or more run directories holding artefacts.jsonl)")
    facts = build(Path(args.rating_dir), Path(args.analysis_out), [Path(d) for d in args.runs], args.primary)
    write_outputs(facts, Path(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

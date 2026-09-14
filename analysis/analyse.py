#!/usr/bin/env python3
"""Analyse the rated remediation artefacts and emit tables and figures.

Inputs

  rating/key.csv                  unblinding key from make_rating_sheet.py
  rating/rater_r1_ratings.csv     primary rater's completed sheet, full set
  rating/rater_r2_ratings.csv     second rater's completed sheet, optional and
                                  normally the stratified reliability
                                  subsample rather than the full set
  rating/adjudicated.csv          resolved codes for the overlap, optional

Reliability

  The second rater double codes a stratified subsample, not the whole corpus,
  so two agreement statistics are reported and neither replaces the other.

  Cohen's kappa is the statistic named in the method chapter and the one that
  makes the result comparable with the published annotation literature. It is
  unweighted over the ten nominal codes and linearly weighted over the ordinal
  severity scale. It is defined for exactly two raters and only on the
  artefacts both of them scored.

  Krippendorff's alpha is reported alongside it because kappa cannot describe
  a design with partial overlap. Alpha admits any number of raters, absorbs
  partial overlap by construction with no imputation and no listwise
  deletion, and takes an explicit level of measurement: the nominal metric for
  the primary code and the ordinal metric for severity. It is implemented here
  from the coincidence matrix definition, with no third party dependency, and
  is checked against three known answers by --selfcheck.

  Both intervals are 95 per cent percentile bootstrap intervals resampling
  artefacts, not asymptotic intervals, because the subsample is far too small
  for the normal approximation to be trustworthy.

  Agreement is reported at two stages, pre-adjudication and post-adjudication,
  and the two are never averaged. Pre-adjudication is the honest measure of
  how reliable the instrument is. Post-adjudication describes the codes the
  headline results actually use and sits close to one by construction. All
  headline results use the adjudicated code.

  The overlap count is reported explicitly and a warning is printed when it
  falls below 30. Precision, under-action and dangerous-action rates always
  come from the primary rater's full set after adjudication, and adjudication
  only covers the overlap.

Outputs, all under the directory given by --out

  agreement.csv          both statistics, on both scales, at both stages, with
                         bootstrap intervals
  disagreements.csv      every artefact the two raters coded differently, plus
                         everything either rater flagged, ready for the
                         adjudication pass
  disagreement_pairs.csv how often each unordered pair of codes was confused
  disagreement_matrix.csv directed confusion matrix, rows the primary rater
                         and columns the second
  per_arm_summary.csv    precision, under-action rate and dangerous-action
                         rate per arm, with Wilson intervals
  code_distribution.csv  the full ten code distribution per arm
  scenario_breakdown.csv precision per arm within each scenario class
  sood_rollup.csv        roll-up to Sood's five hallucination categories
  arm_comparisons.csv    pairwise Fisher exact tests between arms
  latency.csv            latency summary per arm
  tables.tex             booktabs tables ready to \\input into the thesis
  *.pdf                  vector figures, one chart per figure

Analysis choices worth stating in the method chapter

  Precision is the proportion of artefacts assigned F0, that is executable,
  correctly targeted, correctly scoped, context aware, safe, decisive and
  internally consistent. Everything else counts as a failure.

  The adjudicated code is used when rating/adjudicated.csv is present.
  Otherwise rater 1 is used and every table is labelled accordingly, because
  single rater results are not the headline finding.

  The pairwise arm comparisons are exploratory. The study was not powered for
  them, no multiplicity correction is applied, and they are reported as
  descriptive evidence rather than confirmatory tests.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scipy import stats  # noqa: E402
from sklearn.metrics import cohen_kappa_score  # noqa: E402
from statsmodels.stats.proportion import proportion_confint  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "harness"))

import rubric  # noqa: E402  (local module, path adjusted above)

ARM_ORDER = ("gemini", "claude", "baseline")


# ----------------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------------


def read_csv_safe(path: Path, what: str) -> pd.DataFrame | None:
    """Read a CSV, tolerating a leading comment line and a missing file.

    Args:
        path: Candidate CSV path.
        what: Human readable description used in messages.

    Returns:
        The DataFrame, or None when the file is absent or empty.
    """
    if not path.is_file():
        print(f"note: {what} not found at {path}, continuing without it")
        return None
    try:
        df = pd.read_csv(path, comment="#", dtype=str, keep_default_na=False)
    except (OSError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        print(f"warning: cannot read {what} at {path}: {exc}")
        return None
    if df.empty:
        print(f"warning: {what} at {path} has no rows")
        return None
    return df


def load_key(path: Path) -> pd.DataFrame:
    """Load the unblinding key.

    Args:
        path: Path to key.csv.

    Returns:
        The key with numeric columns coerced.

    Raises:
        SystemExit: If the key is missing or lacks required columns.
    """
    if not path.is_file():
        raise SystemExit(
            f"error: the unblinding key is required but was not found at {path}. "
            "Run make_rating_sheet.py first, or pass --key."
        )
    df = read_csv_safe(path, "unblinding key")
    if df is None:
        raise SystemExit(f"error: the unblinding key at {path} could not be read")
    needed = {"artefact_id", "arm", "alert_id", "scenario_class"}
    missing = needed - set(df.columns)
    if missing:
        raise SystemExit(f"error: key.csv is missing columns {sorted(missing)}")
    df["latency_ms"] = pd.to_numeric(df.get("latency_ms"), errors="coerce")
    df["parse_ok"] = df.get("parse_ok", "").astype(str).str.lower().isin(
        {"true", "1", "yes"}
    )
    df["parse_repaired"] = df.get("parse_repaired", "").astype(str).str.lower().isin(
        {"true", "1", "yes"}
    )
    # Strict conformance means the response parsed as RFC 8259 JSON with no
    # lenient retry. It is descriptive only: the headline contract failure
    # rate is computed after repair, because the construct under study is the
    # quality of the remediation, not the tidiness of the serialisation.
    df["strict_ok"] = df["parse_ok"] & ~df["parse_repaired"]
    return df


def load_ratings(path: Path, label: str) -> pd.DataFrame | None:
    """Load one rater sheet and drop rows with no primary code.

    Args:
        path: Path to the rater's completed CSV.
        label: Short name used in messages and in the returned `rater` column.

    Returns:
        The cleaned DataFrame, or None when unavailable.
    """
    df = read_csv_safe(path, f"rater sheet for {label}")
    if df is None:
        return None
    if "primary_code" not in df.columns or "artefact_id" not in df.columns:
        print(f"warning: {path} lacks artefact_id or primary_code, ignoring")
        return None
    df["primary_code"] = df["primary_code"].astype(str).str.strip().str.upper()
    total = len(df)
    df = df[df["primary_code"].isin(rubric.CODE_IDS)].copy()
    dropped = total - len(df)
    if dropped:
        print(
            f"note: {label} sheet has {dropped} of {total} rows with no valid "
            "primary code, those rows are excluded"
        )
    dupes = df["artefact_id"].duplicated().sum()
    if dupes:
        print(f"warning: {label} sheet has {dupes} duplicate artefact_id rows, "
              "keeping the last of each")
        df = df.drop_duplicates(subset="artefact_id", keep="last")
    for col in ("severity", "reversibility", "confidence_annotation",
                "rationale_fidelity", "secondary_codes", "note"):
        if col not in df.columns:
            df[col] = ""
    if "flag_for_adjudication" not in df.columns:
        df["flag_for_adjudication"] = ""
    df["flag_for_adjudication"] = (
        df["flag_for_adjudication"].astype(str).str.strip().str.lower()
        .isin({"true", "1", "yes", "y"})
    )
    df["rater_label"] = label
    return df


# ----------------------------------------------------------------------------
# Agreement
# ----------------------------------------------------------------------------


@dataclass
class AgreementResult:
    """One agreement estimate with a bootstrap interval.

    Two statistics are reported side by side and neither replaces the other.
    Cohen's kappa is the measure named in the method chapter and is what makes
    the result comparable with the published annotation literature, but it is
    defined for exactly two raters and assumes both scored the same artefacts.
    Krippendorff's alpha admits any number of raters, tolerates partial
    overlap by construction, and takes an explicit level of measurement, which
    is what the stratified reliability subsample actually requires.
    """

    measure: str
    statistic: str
    stage: str
    scale: str
    raters: str
    n: int
    overlap_n: int
    estimate: float
    ci_low: float
    ci_high: float
    observed_agreement: float
    note: str = ""


# ----------------------------------------------------------------------------
# Krippendorff's alpha, from the coincidence matrix definition
# ----------------------------------------------------------------------------


def coincidence_matrix(
    units: Sequence[Sequence[str]], labels: Sequence[str]
) -> np.ndarray:
    """Build the coincidence matrix over units of analysis.

    A unit is one artefact and its list of assigned values, one per rater who
    scored it. Units carrying fewer than two values contribute nothing and are
    skipped, which is how alpha absorbs partial overlap without any imputation
    or listwise deletion.

    Args:
        units: One sequence of values per artefact.
        labels: The full ordered label set.

    Returns:
        A square matrix of coincidences, indexed in `labels` order.
    """
    idx = {c: i for i, c in enumerate(labels)}
    m = len(labels)
    o = np.zeros((m, m), dtype=float)
    for raw in units:
        vals = [v for v in raw if v in idx]
        mu = len(vals)
        if mu < 2:
            continue
        counts = np.zeros(m, dtype=float)
        for v in vals:
            counts[idx[v]] += 1.0
        pairs = np.outer(counts, counts)
        np.fill_diagonal(pairs, counts * (counts - 1.0))
        o += pairs / (mu - 1.0)
    return o


def _difference_matrix(
    marginals: np.ndarray, level: str
) -> np.ndarray:
    """Squared difference function for the requested level of measurement.

    Args:
        marginals: Coincidence marginals, needed by the ordinal metric.
        level: Either "nominal" or "ordinal".

    Returns:
        A square matrix of squared differences.

    Raises:
        ValueError: If the level is not one this function implements.
    """
    m = len(marginals)
    if level == "nominal":
        d = np.ones((m, m), dtype=float)
        np.fill_diagonal(d, 0.0)
        return d
    if level == "ordinal":
        d = np.zeros((m, m), dtype=float)
        cum = np.cumsum(marginals)
        for c in range(m):
            for k in range(m):
                lo, hi = (c, k) if c <= k else (k, c)
                span = cum[hi] - cum[lo] + marginals[lo]
                val = span - (marginals[c] + marginals[k]) / 2.0
                d[c, k] = val * val
        return d
    raise ValueError(f"unsupported level of measurement: {level}")


def krippendorff_alpha(
    units: Sequence[Sequence[str]], labels: Sequence[str], level: str
) -> float:
    """Krippendorff's alpha over any number of raters with any overlap.

    Implemented directly from the coincidence matrix definition so the harness
    carries no third party reliability dependency:

        alpha = 1 - Do / De

    where Do is the observed disagreement averaged over coincidences and De is
    the disagreement expected from the marginals alone.

    Args:
        units: One sequence of values per artefact.
        labels: The full ordered label set.
        level: "nominal" for the primary code, "ordinal" for severity.

    Returns:
        The alpha value, or nan when it is undefined.
    """
    o = coincidence_matrix(units, labels)
    n_c = o.sum(axis=1)
    n = float(n_c.sum())
    if n < 2.0:
        return float("nan")
    d = _difference_matrix(n_c, level)
    obs = float((o * d).sum())
    exp_pairs = np.outer(n_c, n_c)
    np.fill_diagonal(exp_pairs, n_c * (n_c - 1.0))
    exp = float((exp_pairs * d).sum()) / (n - 1.0)
    if exp <= 0.0:
        # Every coincidence sits in one category, so there is no variation for
        # chance to explain. Perfect agreement is the only sensible reading.
        return 1.0 if obs == 0.0 else float("nan")
    return 1.0 - obs / exp


def pairable_units(units: Sequence[Sequence[str]]) -> list[list[str]]:
    """Keep only the units that carry at least two values."""
    return [list(u) for u in units if len(u) >= 2]


def unit_agreement(units: Sequence[Sequence[str]]) -> float:
    """Proportion of pairable units on which every rater gave the same value."""
    usable = pairable_units(units)
    if not usable:
        return float("nan")
    return float(np.mean([len(set(u)) == 1 for u in usable]))


def bootstrap_units(
    units: Sequence[Sequence[str]],
    estimator: Callable[[Sequence[Sequence[str]]], float],
    n_boot: int,
    seed: int,
) -> tuple[float, float]:
    """Percentile bootstrap interval, resampling artefacts rather than ratings.

    The subsample is small enough that the asymptotic standard error of either
    statistic is unreliable, so both intervals are resampled. Artefacts are the
    independent unit, so artefacts are what gets resampled.

    Args:
        units: One sequence of values per artefact.
        estimator: Function from units to a scalar estimate.
        n_boot: Number of bootstrap resamples.
        seed: Random seed for reproducibility.

    Returns:
        The 2.5th and 97.5th percentiles, or (nan, nan) when undefined.
    """
    pool = pairable_units(units)
    n = len(pool)
    if n < 3:
        return float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    vals: list[float] = []
    for _ in range(n_boot):
        pick = rng.integers(0, n, n)
        v = estimator([pool[i] for i in pick])
        if not np.isnan(v):
            vals.append(v)
    if len(vals) < 20:
        return float("nan"), float("nan")
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))


def _kappa(
    a: Sequence[str], b: Sequence[str], labels: Sequence[str], weights: str | None
) -> float:
    """Compute Cohen's kappa, returning nan on a degenerate input.

    Args:
        a: First rater's labels.
        b: Second rater's labels.
        labels: The full label set, so absent categories still count.
        weights: None for nominal, "linear" for the ordinal severity scale.

    Returns:
        The kappa value, or nan when it is undefined.
    """
    if len(a) == 0:
        return float("nan")
    try:
        with np.errstate(invalid="ignore", divide="ignore"):
            k = cohen_kappa_score(list(a), list(b), labels=list(labels), weights=weights)
    except ValueError:
        return float("nan")
    return float(k)


def bootstrap_kappa(
    a: Sequence[str],
    b: Sequence[str],
    labels: Sequence[str],
    weights: str | None,
    n_boot: int,
    seed: int,
) -> tuple[float, float]:
    """Percentile bootstrap interval for kappa, resampling artefact pairs.

    Args:
        a: First rater's labels.
        b: Second rater's labels.
        labels: The full label set.
        weights: None or "linear".
        n_boot: Number of bootstrap resamples.
        seed: Random seed for reproducibility.

    Returns:
        The 2.5th and 97.5th percentiles, or (nan, nan) when undefined.
    """
    n = len(a)
    if n < 3:
        return float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    arr_a = np.asarray(a)
    arr_b = np.asarray(b)
    vals: list[float] = []
    for _ in range(n_boot):
        pick = rng.integers(0, n, n)
        k = _kappa(arr_a[pick], arr_b[pick], labels, weights)
        if not np.isnan(k):
            vals.append(k)
    if len(vals) < 20:
        return float("nan"), float("nan")
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))


# ----------------------------------------------------------------------------
# Assembling the per rater views
# ----------------------------------------------------------------------------


def rater_values(
    frames: dict[str, pd.DataFrame], column: str, labels: Sequence[str]
) -> dict[str, dict[str, str]]:
    """Map each rater to its artefact_id to value dictionary.

    Args:
        frames: Rater name to cleaned sheet.
        column: Either "primary_code" or "severity".
        labels: The valid label set. Anything else is treated as not scored.

    Returns:
        Rater name to a map of artefact_id to value.
    """
    allowed = set(labels)
    out: dict[str, dict[str, str]] = {}
    for name, df in frames.items():
        m: dict[str, str] = {}
        if column not in df.columns:
            out[name] = m
            continue
        for aid, val in zip(df["artefact_id"], df[column]):
            v = str(val).strip().upper()
            if v in allowed:
                m[str(aid)] = v
        out[name] = m
    return out


def build_units(
    values: dict[str, dict[str, str]], resolved: dict[str, str] | None = None
) -> tuple[list[str], list[list[str]]]:
    """Turn per rater maps into units of analysis, one per artefact.

    Args:
        values: Rater name to artefact_id to value.
        resolved: Optional adjudicated values. Where an artefact has been
            adjudicated, every rater's value is replaced by the resolved one,
            which is what post-adjudication agreement means.

    Returns:
        The artefact ids in a stable order and the matching units.
    """
    ids: set[str] = set()
    for m in values.values():
        ids |= set(m)
    ordered = sorted(ids)
    units: list[list[str]] = []
    for aid in ordered:
        vals = [values[n][aid] for n in sorted(values) if aid in values[n]]
        if resolved and aid in resolved and vals:
            vals = [resolved[aid]] * len(vals)
        units.append(vals)
    return ordered, units


def disagreement_pairs(
    ids: Sequence[str],
    values: dict[str, dict[str, str]],
    labels: Sequence[str],
    resolved: dict[str, str] | None = None,
) -> pd.DataFrame:
    """Count how often each unordered pair of codes was confused.

    Where the raters disagreed is itself a finding about the instrument: a
    rubric whose disagreement concentrates on one boundary is telling you that
    boundary is underspecified, which a single kappa cannot show.

    Args:
        ids: Artefact ids in a stable order.
        values: Rater name to artefact_id to value.
        labels: The full ordered label set, which fixes the canonical order
            within a pair so that (F2, F5) and (F5, F2) are one row.
        resolved: Optional adjudicated values applied before counting.

    Returns:
        Columns code_a, code_b, count, sorted by count descending.
    """
    order = {c: i for i, c in enumerate(labels)}
    names = sorted(values)
    tally: dict[tuple[str, str], int] = {}
    for aid in ids:
        vals = [values[n][aid] for n in names if aid in values[n]]
        if resolved and aid in resolved and vals:
            vals = [resolved[aid]] * len(vals)
        for i in range(len(vals)):
            for j in range(i + 1, len(vals)):
                a, b = vals[i], vals[j]
                if a == b:
                    continue
                key = (a, b) if order.get(a, 0) <= order.get(b, 0) else (b, a)
                tally[key] = tally.get(key, 0) + 1
    rows = [
        {"code_a": a, "code_b": b, "count": n} for (a, b), n in tally.items()
    ]
    df = pd.DataFrame(rows, columns=["code_a", "code_b", "count"])
    if df.empty:
        return df
    df["_oa"] = [order.get(a, 99) for a in df["code_a"]]
    df["_ob"] = [order.get(b, 99) for b in df["code_b"]]
    df = df.sort_values(["count", "_oa", "_ob"], ascending=[False, True, True])
    return df.drop(columns=["_oa", "_ob"]).reset_index(drop=True)


def disagreement_crosstab(
    values: dict[str, dict[str, str]], labels: Sequence[str]
) -> pd.DataFrame:
    """Directed confusion matrix, rows the primary rater, columns the second.

    Direction is meaningful here because rater 1 codes the whole set and rater
    2 codes the reliability subsample, so the two roles are not symmetric.

    Args:
        values: Rater name to artefact_id to value. Only the first two raters
            in sorted order are crosstabulated.
        labels: The full ordered label set, so empty categories still appear.

    Returns:
        A labels by labels frame of counts, or an empty frame if fewer than
        two raters are present.
    """
    names = sorted(values)
    if len(names) < 2:
        return pd.DataFrame()
    a, b = values[names[0]], values[names[1]]
    shared = sorted(set(a) & set(b))
    mat = pd.DataFrame(
        0, index=list(labels), columns=list(labels), dtype=int
    )
    for aid in shared:
        mat.loc[a[aid], b[aid]] += 1
    mat.index.name = f"{names[0]}_code"
    mat.columns.name = f"{names[1]}_code"
    return mat


# ----------------------------------------------------------------------------
# The agreement pass
# ----------------------------------------------------------------------------

# Each entry is (label for the table, rating column, valid labels, alpha level,
# kappa weighting). Adding a third rated dimension later means adding a row
# here and nothing else.
AGREEMENT_SCALES: list[tuple[str, str, str, str | None]] = [
    ("Primary code (nominal, 10 codes)", "primary_code", "nominal", None),
    ("Severity (ordinal, S0 to S3)", "severity", "ordinal", "linear"),
]


def _scale_labels(column: str) -> list[str]:
    """Valid labels for a rated column."""
    return list(rubric.CODE_IDS if column == "primary_code" else rubric.SEVERITY_IDS)


def agreement_for_stage(
    frames: dict[str, pd.DataFrame],
    stage: str,
    resolved: dict[str, dict[str, str]],
    n_boot: int,
    seed: int,
) -> list[AgreementResult]:
    """Compute both statistics on every rated scale for one stage.

    Args:
        frames: Rater name to cleaned sheet.
        stage: "pre-adjudication" or "post-adjudication".
        resolved: Column name to artefact_id to adjudicated value. Empty for
            the pre-adjudication stage.
        n_boot: Bootstrap resamples.
        seed: Random seed. Each estimate gets a distinct offset so the
            intervals are independent draws rather than the same one reused.

    Returns:
        One result per scale per statistic.
    """
    names = sorted(frames)
    results: list[AgreementResult] = []
    for offset, (measure, column, level, weights) in enumerate(AGREEMENT_SCALES):
        labels = _scale_labels(column)
        values = rater_values(frames, column, labels)
        res = resolved.get(column) if resolved else None
        ids, units = build_units(values, res)
        usable = pairable_units(units)
        overlap = len(usable)
        obs = unit_agreement(units)

        alpha = krippendorff_alpha(usable, labels, level)
        alo, ahi = bootstrap_units(
            usable,
            lambda u, lb=labels, lv=level: krippendorff_alpha(u, lb, lv),
            n_boot,
            seed + 100 + offset * 2,
        )
        note = ""
        singles = len(units) - overlap
        if singles:
            note = f"{singles} artefacts carried one rating only and cannot pair"
        results.append(
            AgreementResult(
                measure, "Krippendorff alpha", stage, level,
                f"{len(names)} raters", overlap, overlap, alpha, alo, ahi,
                obs, note,
            )
        )

        if len(names) < 2:
            continue
        # Cohen's kappa is defined for a rater pair. With the planned two
        # raters this loop runs once; if a third rater is ever added it
        # reports every pair rather than silently picking one.
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                na, nb = names[i], names[j]
                shared = sorted(set(values[na]) & set(values[nb]))
                a = [res[x] if res and x in res else values[na][x] for x in shared]
                b = [res[x] if res and x in res else values[nb][x] for x in shared]
                k = _kappa(a, b, labels, weights)
                klo, khi = bootstrap_kappa(
                    a, b, labels, weights, n_boot, seed + 200 + offset * 2 + i + j
                )
                kobs = (
                    float(np.mean([x == y for x, y in zip(a, b)]))
                    if a
                    else float("nan")
                )
                stat = (
                    "Cohen kappa"
                    if weights is None
                    else "Cohen kappa (linear weights)"
                )
                results.append(
                    AgreementResult(
                        measure, stat, stage, level, f"{na} vs {nb}",
                        len(shared), len(shared), k, klo, khi, kobs, "",
                    )
                )
    return results


def agreement(
    frames: dict[str, pd.DataFrame],
    n_boot: int,
    seed: int,
    resolved: dict[str, dict[str, str]] | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Compute inter rater agreement and build the disagreement artefacts.

    Both statistics are computed at both stages. Pre-adjudication is the
    honest measure of how reliable the instrument is in the hands of two
    independent raters. Post-adjudication describes the codes the headline
    results actually use, and will sit close to one by construction, so the
    two are always reported separately and never averaged.

    Args:
        frames: Rater name to cleaned sheet. Any number of raters is accepted.
        n_boot: Bootstrap resamples.
        seed: Random seed.
        resolved: Optional adjudicated values, column to artefact_id to value.

    Returns:
        A tuple of the agreement table, the merged frame needing adjudication,
        the unordered disagreement pair counts and the directed confusion
        matrix.
    """
    results = agreement_for_stage(frames, "pre-adjudication", {}, n_boot, seed)
    if resolved:
        results += agreement_for_stage(
            frames, "post-adjudication", resolved, n_boot, seed + 1000
        )
    agree_df = pd.DataFrame([r.__dict__ for r in results])

    code_values = rater_values(frames, "primary_code", rubric.CODE_IDS)
    ids, _ = build_units(code_values)
    pairs = disagreement_pairs(ids, code_values, rubric.CODE_IDS)
    crosstab = disagreement_crosstab(code_values, rubric.CODE_IDS)

    names = sorted(frames)
    if len(names) < 2:
        return agree_df, pd.DataFrame(), pairs, crosstab
    # The adjudication worksheet is pairwise by design: two people sit down
    # with the artefacts they coded differently. With more than two raters it
    # is built from the first two and the rest are covered by alpha only.
    r1, r2 = frames[names[0]], frames[names[1]]
    merged = r1.merge(r2, on="artefact_id", suffixes=("_r1", "_r2"))
    disagree = merged[merged["primary_code_r1"] != merged["primary_code_r2"]].copy()
    disagree["reason"] = "primary code differs"
    flagged = merged[
        (merged["flag_for_adjudication_r1"] | merged["flag_for_adjudication_r2"])
        & (merged["primary_code_r1"] == merged["primary_code_r2"])
    ].copy()
    flagged["reason"] = "agreed but flagged by a rater"
    adj = pd.concat([disagree, flagged], ignore_index=True) if len(flagged) else disagree
    return agree_df, adj, pairs, crosstab


def agreement_selfcheck(n_boot: int = 200, seed: int = 20260907) -> dict[str, float]:
    """Sanity check the hand rolled alpha against three known answers.

    A reliability statistic written from the definition is easy to get subtly
    wrong in a way that still produces plausible looking numbers, so the three
    cases with known answers are checked in code rather than by eye:

    1. Perfect agreement must return exactly 1.0.
    2. Independent random labelling must return approximately 0.0.
    3. On a complete two rater nominal matrix with no missing data, alpha and
       Cohen's kappa differ only by the finite sample correction and must land
       close to each other.

    Args:
        n_boot: Unused placeholder kept so the signature matches the CLI.
        seed: Random seed for the two randomised cases.

    Returns:
        The three headline numbers plus supporting detail.
    """
    codes = list(rubric.CODE_IDS)
    rng = np.random.default_rng(seed)

    perfect = [[c, c] for c in codes for _ in range(6)]
    a_perfect = krippendorff_alpha(perfect, codes, "nominal")

    n_chance = 4000
    chance = [
        [str(rng.choice(codes)), str(rng.choice(codes))] for _ in range(n_chance)
    ]
    a_chance = krippendorff_alpha(chance, codes, "nominal")

    n_cmp = 300
    truth = rng.choice(codes, size=n_cmp)
    noise = rng.random(n_cmp) < 0.35
    other = rng.choice(codes, size=n_cmp)
    ra = [str(x) for x in truth]
    rb = [str(o) if flip else str(t) for t, o, flip in zip(truth, other, noise)]
    cmp_units = [[x, y] for x, y in zip(ra, rb)]
    a_cmp = krippendorff_alpha(cmp_units, codes, "nominal")
    k_cmp = _kappa(ra, rb, codes, None)

    ordinal_perfect = krippendorff_alpha(
        [[s, s] for s in rubric.SEVERITY_IDS for _ in range(6)],
        list(rubric.SEVERITY_IDS),
        "ordinal",
    )
    ordinal_chance = krippendorff_alpha(
        [
            [str(rng.choice(list(rubric.SEVERITY_IDS))),
             str(rng.choice(list(rubric.SEVERITY_IDS)))]
            for _ in range(n_chance)
        ],
        list(rubric.SEVERITY_IDS),
        "ordinal",
    )

    return {
        "perfect_nominal_alpha": a_perfect,
        "chance_nominal_alpha": a_chance,
        "complete_matrix_alpha": a_cmp,
        "complete_matrix_kappa": k_cmp,
        "alpha_minus_kappa": a_cmp - k_cmp,
        "perfect_ordinal_alpha": ordinal_perfect,
        "chance_ordinal_alpha": ordinal_chance,
        "n_chance_units": float(n_chance),
        "n_complete_units": float(n_cmp),
    }


def print_selfcheck(res: dict[str, float]) -> int:
    """Print the self check and return a non zero code if any case fails.

    Args:
        res: The result of agreement_selfcheck.

    Returns:
        0 when all three cases pass, 1 otherwise.
    """
    ok = True
    print("Krippendorff alpha self check")
    print(
        f"  1. perfect agreement, nominal, 60 units: alpha = "
        f"{res['perfect_nominal_alpha']:.6f} (must be exactly 1.0)"
    )
    if res["perfect_nominal_alpha"] != 1.0:
        ok = False
        print("     FAIL: perfect agreement did not return exactly 1.0")
    print(
        f"  2. independent random labelling, {int(res['n_chance_units'])} units: "
        f"alpha = {res['chance_nominal_alpha']:.6f} (must be near 0.0)"
    )
    if abs(res["chance_nominal_alpha"]) > 0.05:
        ok = False
        print("     FAIL: chance agreement is not near zero")
    print(
        f"  3. complete two rater nominal matrix, {int(res['n_complete_units'])} "
        f"units: alpha = {res['complete_matrix_alpha']:.6f}, Cohen kappa = "
        f"{res['complete_matrix_kappa']:.6f}, difference = "
        f"{res['alpha_minus_kappa']:+.6f}"
    )
    if abs(res["alpha_minus_kappa"]) > 0.02:
        ok = False
        print("     FAIL: alpha and kappa disagree by more than 0.02")
    print(
        f"  supporting: ordinal perfect = {res['perfect_ordinal_alpha']:.6f}, "
        f"ordinal chance = {res['chance_ordinal_alpha']:.6f}"
    )
    print("  result: all three cases pass" if ok else "  result: SELF CHECK FAILED")
    return 0 if ok else 1


def build_disagreement_table(adj: pd.DataFrame) -> pd.DataFrame:
    """Reduce the merged disagreement frame to the adjudication worksheet.

    Args:
        adj: Rows needing adjudication.

    Returns:
        A tidy frame with an empty `adjudicated_code` column to fill in.
    """
    cols = {
        "artefact_id": "artefact_id",
        "display_index_r1": "display_index",
        "reason": "reason",
        "primary_code_r1": "rater1_code",
        "primary_code_r2": "rater2_code",
        "severity_r1": "rater1_severity",
        "severity_r2": "rater2_severity",
        "note_r1": "rater1_note",
        "note_r2": "rater2_note",
    }
    present = {k: v for k, v in cols.items() if k in adj.columns}
    out = adj[list(present)].rename(columns=present).copy()
    out["adjudicated_code"] = ""
    out["adjudicated_severity"] = ""
    out["adjudicator_note"] = ""
    if "display_index" in out.columns:
        out = out.sort_values("display_index", key=lambda s: pd.to_numeric(s, errors="coerce"))
    return out


# ----------------------------------------------------------------------------
# Outcome metrics
# ----------------------------------------------------------------------------


def wilson(successes: int, n: int) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Args:
        successes: Number of successes.
        n: Number of trials.

    Returns:
        The 95 percent lower and upper bounds, or (nan, nan) when n is zero.
    """
    if n == 0:
        return float("nan"), float("nan")
    lo, hi = proportion_confint(successes, n, alpha=0.05, method="wilson")
    return float(lo), float(hi)


def per_arm_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Precision, under-action and dangerous-action rates for each arm.

    Args:
        df: The analysis frame, one row per artefact, with `arm` and `code`.

    Returns:
        One row per arm, plus an overall row.
    """
    rows: list[dict[str, Any]] = []
    groups = [(arm, df[df["arm"] == arm]) for arm in arm_list(df)]
    groups.append(("all arms", df))
    for arm, sub in groups:
        n = len(sub)
        for metric, mask in (
            ("precision (F0)", sub["code"] == "F0"),
            ("under-action rate (F5, F8)", sub["code"].isin(rubric.UNDER_ACTION_CODES)),
            (
                "dangerous-action rate (F4, F7)",
                sub["code"].isin(rubric.DANGEROUS_ACTION_CODES),
            ),
            # Truncated artefacts never enter the rating package, so this
            # rate covers model contract failures only. Harness truncation is
            # reported separately from rating/manifest.json. This is computed
            # after lenient repair: the headline number.
            ("model contract failure rate", ~sub["parse_ok"].astype(bool)),
            # Descriptive secondary statistic. How often the arm emitted JSON
            # that needed no lenient retry.
            (
                "strict JSON conformance rate",
                sub["strict_ok"].astype(bool)
                if "strict_ok" in sub.columns
                else sub["parse_ok"].astype(bool),
            ),
            (
                "lenient repair rate",
                sub["parse_repaired"].astype(bool)
                if "parse_repaired" in sub.columns
                else sub["parse_ok"] & False,
            ),
        ):
            k = int(mask.sum())
            lo, hi = wilson(k, n)
            rows.append(
                {
                    "arm": arm,
                    "metric": metric,
                    "count": k,
                    "n": n,
                    "proportion": (k / n) if n else float("nan"),
                    "ci_low": lo,
                    "ci_high": hi,
                }
            )
    return pd.DataFrame(rows)


def arm_list(df: pd.DataFrame) -> list[str]:
    """Return the arms present, in the canonical reporting order.

    Args:
        df: The analysis frame.

    Returns:
        Arm names, known arms first in canonical order then any extras.
    """
    present = set(df["arm"].dropna().unique())
    ordered = [a for a in ARM_ORDER if a in present]
    return ordered + sorted(present - set(ordered))


def code_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Full ten code distribution per arm, as counts and percentages.

    Args:
        df: The analysis frame.

    Returns:
        A long frame with one row per arm and code.
    """
    rows: list[dict[str, Any]] = []
    for arm in arm_list(df):
        sub = df[df["arm"] == arm]
        n = len(sub)
        counts = sub["code"].value_counts()
        for code in rubric.CODE_IDS:
            k = int(counts.get(code, 0))
            rows.append(
                {
                    "arm": arm,
                    "code": code,
                    "label": rubric.CODE_LABELS[code],
                    "count": k,
                    "n": n,
                    "percent": (100.0 * k / n) if n else float("nan"),
                }
            )
    return pd.DataFrame(rows)


def scenario_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    """Precision per arm within each scenario class.

    Args:
        df: The analysis frame.

    Returns:
        One row per arm and scenario class.
    """
    rows: list[dict[str, Any]] = []
    for arm in arm_list(df):
        for sc in sorted(df["scenario_class"].dropna().unique()):
            sub = df[(df["arm"] == arm) & (df["scenario_class"] == sc)]
            n = len(sub)
            k = int((sub["code"] == "F0").sum())
            lo, hi = wilson(k, n)
            rows.append(
                {
                    "arm": arm,
                    "scenario_class": sc,
                    "n": n,
                    "correct_f0": k,
                    "precision": (k / n) if n else float("nan"),
                    "ci_low": lo,
                    "ci_high": hi,
                    "under_action": int(
                        sub["code"].isin(rubric.UNDER_ACTION_CODES).sum()
                    ),
                    "dangerous_action": int(
                        sub["code"].isin(rubric.DANGEROUS_ACTION_CODES).sum()
                    ),
                }
            )
    return pd.DataFrame(rows)


def sood_rollup(df: pd.DataFrame) -> pd.DataFrame:
    """Roll the ten codes up to Sood's five hallucination categories.

    F9 internally inconsistent is not part of Sood's scheme and is reported on
    its own row. F0 is not a failure and is reported as "None".

    Args:
        df: The analysis frame.

    Returns:
        One row per arm and category.
    """
    order = list(rubric.SOOD_ORDER) + ["Consistency", "None"]
    rows: list[dict[str, Any]] = []
    for arm in arm_list(df):
        sub = df[df["arm"] == arm]
        n = len(sub)
        cats = sub["code"].map(rubric.sood_category)
        counts = cats.value_counts()
        for cat in order:
            k = int(counts.get(cat, 0))
            member = (
                ", ".join(rubric.SOOD_CATEGORIES[cat])
                if cat in rubric.SOOD_CATEGORIES
                else ("F9" if cat == "Consistency" else "F0")
            )
            rows.append(
                {
                    "arm": arm,
                    "sood_category": cat,
                    "codes": member,
                    "count": k,
                    "n": n,
                    "percent": (100.0 * k / n) if n else float("nan"),
                }
            )
    return pd.DataFrame(rows)


def arm_comparisons(df: pd.DataFrame) -> pd.DataFrame:
    """Pairwise Fisher exact tests between arms on the headline proportions.

    Args:
        df: The analysis frame.

    Returns:
        One row per arm pair and metric.
    """
    metrics = {
        "precision (F0)": lambda s: s["code"] == "F0",
        "under-action rate (F5, F8)": lambda s: s["code"].isin(
            rubric.UNDER_ACTION_CODES
        ),
        "dangerous-action rate (F4, F7)": lambda s: s["code"].isin(
            rubric.DANGEROUS_ACTION_CODES
        ),
    }
    arms = arm_list(df)
    rows: list[dict[str, Any]] = []
    for i in range(len(arms)):
        for j in range(i + 1, len(arms)):
            a, b = arms[i], arms[j]
            sa, sb = df[df["arm"] == a], df[df["arm"] == b]
            for name, fn in metrics.items():
                ka, na = int(fn(sa).sum()), len(sa)
                kb, nb = int(fn(sb).sum()), len(sb)
                if na == 0 or nb == 0:
                    continue
                table = [[ka, na - ka], [kb, nb - kb]]
                try:
                    odds, p = stats.fisher_exact(table)
                except ValueError:
                    odds, p = float("nan"), float("nan")
                rows.append(
                    {
                        "metric": name,
                        "arm_a": a,
                        "arm_b": b,
                        "count_a": ka,
                        "n_a": na,
                        "prop_a": ka / na,
                        "count_b": kb,
                        "n_b": nb,
                        "prop_b": kb / nb,
                        "difference": ka / na - kb / nb,
                        "odds_ratio": float(odds),
                        "fisher_p": float(p),
                        "interpretation": "exploratory, not corrected for multiplicity",
                    }
                )
    return pd.DataFrame(rows)


def latency_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Latency descriptive statistics per arm.

    Args:
        df: The analysis frame, carrying `latency_ms` from the key.

    Returns:
        One row per arm.
    """
    rows: list[dict[str, Any]] = []
    for arm in arm_list(df):
        s = pd.to_numeric(df[df["arm"] == arm]["latency_ms"], errors="coerce").dropna()
        if s.empty:
            rows.append({"arm": arm, "n": 0})
            continue
        rows.append(
            {
                "arm": arm,
                "n": int(s.size),
                "mean_ms": float(s.mean()),
                "sd_ms": float(s.std(ddof=1)) if s.size > 1 else float("nan"),
                "median_ms": float(s.median()),
                "p25_ms": float(s.quantile(0.25)),
                "p75_ms": float(s.quantile(0.75)),
                "min_ms": float(s.min()),
                "max_ms": float(s.max()),
            }
        )
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------
# Figures
# ----------------------------------------------------------------------------


def fig_code_distribution(dist: pd.DataFrame, out: Path) -> None:
    """Grouped bar chart of the ten code distribution per arm.

    Args:
        dist: Output of `code_distribution`.
        out: Destination PDF path.
    """
    arms = list(dict.fromkeys(dist["arm"]))
    codes = list(rubric.CODE_IDS)
    x = np.arange(len(codes))
    width = 0.8 / max(len(arms), 1)
    fig, ax = plt.subplots(figsize=(9, 4.2))
    for i, arm in enumerate(arms):
        sub = dist[dist["arm"] == arm].set_index("code").reindex(codes)
        ax.bar(x + i * width - 0.4 + width / 2, sub["percent"].values, width, label=arm)
    ax.set_xticks(x)
    ax.set_xticklabels(codes)
    ax.set_xlabel("Primary rubric code")
    ax.set_ylabel("Percent of artefacts")
    ax.set_title("Distribution of primary rubric codes by arm")
    ax.legend(title="Arm")
    ax.grid(axis="y", linewidth=0.4, alpha=0.5)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(out, format="pdf")
    plt.close(fig)


def fig_precision(summary: pd.DataFrame, out: Path) -> None:
    """Bar chart of precision per arm with Wilson intervals.

    Args:
        summary: Output of `per_arm_summary`.
        out: Destination PDF path.
    """
    sub = summary[
        (summary["metric"] == "precision (F0)") & (summary["arm"] != "all arms")
    ]
    if sub.empty:
        return
    x = np.arange(len(sub))
    vals = sub["proportion"].values * 100
    lo = np.clip(vals - sub["ci_low"].values * 100, 0, None)
    hi = np.clip(sub["ci_high"].values * 100 - vals, 0, None)
    fig, ax = plt.subplots(figsize=(5.5, 4.0))
    ax.bar(x, vals, 0.55, yerr=[lo, hi], capsize=5)
    ax.set_xticks(x)
    ax.set_xticklabels(sub["arm"])
    ax.set_ylabel("Percent coded F0, correct and safe")
    ax.set_xlabel("Arm")
    ax.set_ylim(0, 100)
    ax.set_title("Precision by arm, with Wilson 95 percent intervals")
    ax.grid(axis="y", linewidth=0.4, alpha=0.5)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(out, format="pdf")
    plt.close(fig)


def fig_sood(roll: pd.DataFrame, out: Path) -> None:
    """Grouped bar chart of the Sood category roll-up per arm.

    Args:
        roll: Output of `sood_rollup`.
        out: Destination PDF path.
    """
    cats = list(rubric.SOOD_ORDER) + ["Consistency"]
    arms = list(dict.fromkeys(roll["arm"]))
    x = np.arange(len(cats))
    width = 0.8 / max(len(arms), 1)
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    for i, arm in enumerate(arms):
        sub = roll[roll["arm"] == arm].set_index("sood_category").reindex(cats)
        ax.bar(x + i * width - 0.4 + width / 2, sub["percent"].values, width, label=arm)
    ax.set_xticks(x)
    ax.set_xticklabels(cats)
    ax.set_xlabel("Hallucination category")
    ax.set_ylabel("Percent of artefacts")
    ax.set_title("Failures rolled up to Sood's categories, by arm")
    ax.legend(title="Arm")
    ax.grid(axis="y", linewidth=0.4, alpha=0.5)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(out, format="pdf")
    plt.close(fig)


def fig_scenario(bd: pd.DataFrame, out: Path) -> None:
    """Grouped bar chart of precision per scenario class and arm.

    Args:
        bd: Output of `scenario_breakdown`.
        out: Destination PDF path.
    """
    if bd.empty:
        return
    scs = sorted(bd["scenario_class"].unique())
    arms = list(dict.fromkeys(bd["arm"]))
    x = np.arange(len(scs))
    width = 0.8 / max(len(arms), 1)
    fig, ax = plt.subplots(figsize=(6.5, 4.0))
    for i, arm in enumerate(arms):
        sub = bd[bd["arm"] == arm].set_index("scenario_class").reindex(scs)
        ax.bar(
            x + i * width - 0.4 + width / 2,
            sub["precision"].values * 100,
            width,
            label=arm,
        )
    ax.set_xticks(x)
    ax.set_xticklabels(scs)
    ax.set_xlabel("Scenario class")
    ax.set_ylabel("Percent coded F0")
    ax.set_ylim(0, 100)
    ax.set_title("Precision by scenario class and arm")
    ax.legend(title="Arm")
    ax.grid(axis="y", linewidth=0.4, alpha=0.5)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(out, format="pdf")
    plt.close(fig)


def fig_latency(df: pd.DataFrame, out: Path) -> None:
    """Box plot of per artefact latency by arm.

    Args:
        df: The analysis frame.
        out: Destination PDF path.
    """
    arms = arm_list(df)
    data = [
        pd.to_numeric(df[df["arm"] == a]["latency_ms"], errors="coerce").dropna().values
        for a in arms
    ]
    if not any(len(d) for d in data):
        return
    fig, ax = plt.subplots(figsize=(6.0, 4.0))
    # matplotlib renamed the boxplot label keyword in 3.9. Support both so the
    # analysis runs on whatever is installed.
    try:
        ax.boxplot(data, tick_labels=arms, showmeans=True)
    except TypeError:
        ax.boxplot(data, labels=arms, showmeans=True)
    ax.set_ylabel("Latency per artefact (ms)")
    ax.set_xlabel("Arm")
    ax.set_yscale("log")
    ax.set_title("Generation latency by arm, log scale")
    ax.grid(axis="y", linewidth=0.4, alpha=0.5)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(out, format="pdf")
    plt.close(fig)


# ----------------------------------------------------------------------------
# LaTeX
# ----------------------------------------------------------------------------


def tex_escape(s: Any) -> str:
    """Escape LaTeX special characters in a cell value.

    Args:
        s: Any value.

    Returns:
        A LaTeX safe string.
    """
    text = "" if s is None else str(s)
    for a, b in (
        ("\\", r"\textbackslash{}"),
        ("&", r"\&"),
        ("%", r"\%"),
        ("$", r"\$"),
        ("#", r"\#"),
        ("_", r"\_"),
        ("{", r"\{"),
        ("}", r"\}"),
        ("~", r"\textasciitilde{}"),
        ("^", r"\textasciicircum{}"),
    ):
        text = text.replace(a, b)
    return text


def fmt(v: Any, places: int = 2) -> str:
    """Format a number as a plain LaTeX cell value.

    No siunitx macros are emitted, so the tables work with or without the
    package. A sisetup declaring a table format still aligns these cleanly.

    Args:
        v: The value.
        places: Decimal places for floats.

    Returns:
        The formatted string, or an en rule for missing values.
    """
    if v is None:
        return "--"
    if isinstance(v, (int, np.integer)):
        return str(int(v))
    if isinstance(v, float) or isinstance(v, np.floating):
        if np.isnan(v):
            return "--"
        return f"{v:.{places}f}"
    return tex_escape(v)


def latex_table(
    df: pd.DataFrame,
    columns: Sequence[tuple[str, str, str]],
    caption: str,
    label: str,
    note: str = "",
) -> str:
    """Render a DataFrame as a booktabs table.

    Args:
        df: The data.
        columns: Triples of (dataframe column, header text, alignment).
        caption: Table caption.
        label: LaTeX label without the `tab:` prefix.
        note: Optional footnote placed under the table.

    Returns:
        The complete LaTeX table environment.
    """
    align = "".join(c[2] for c in columns)
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{" + caption + "}",
        r"\label{tab:" + label + "}",
        r"\begin{tabular}{" + align + "}",
        r"\toprule",
        " & ".join(tex_escape(c[1]) for c in columns) + r" \\",
        r"\midrule",
    ]
    for _, row in df.iterrows():
        cells = []
        for col, _hdr, _al in columns:
            v = row.get(col)
            if isinstance(v, str):
                cells.append(tex_escape(v))
            else:
                cells.append(fmt(v))
        lines.append(" & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    if note:
        lines.append(
            r"\par\vspace{2pt}\footnotesize\raggedright " + note
        )
    lines.append(r"\end{table}")
    return "\n".join(lines)


def write_tex(
    out_dir: Path,
    agree: pd.DataFrame | None,
    summary: pd.DataFrame,
    dist: pd.DataFrame,
    bd: pd.DataFrame,
    roll: pd.DataFrame,
    comp: pd.DataFrame,
    lat: pd.DataFrame,
    source_note: str,
) -> Path:
    """Write all booktabs tables to a single includable file.

    Args:
        out_dir: Output directory.
        agree: Agreement table, or None when only one rater was available.
        summary: Per arm summary.
        dist: Code distribution.
        bd: Scenario breakdown.
        roll: Sood roll-up.
        comp: Pairwise comparisons.
        lat: Latency summary.
        source_note: Sentence naming which coding was used.

    Returns:
        The path written.
    """
    parts: list[str] = [
        "% Generated by lab/analysis/analyse.py. Do not edit by hand.",
        "% Requires \\usepackage{booktabs}.",
        "% Numbers are plain, so an \\sisetup table-format declaration in the",
        "% preamble will align them without any siunitx macro inside a cell.",
        f"% Coding source: {source_note}",
        "",
    ]

    if agree is not None and not agree.empty:
        a = agree.copy()
        a["ci"] = [
            "--" if (np.isnan(l) or np.isnan(h)) else f"[{l:.2f}, {h:.2f}]"
            for l, h in zip(a["ci_low"], a["ci_high"])
        ]
        parts.append(
            latex_table(
                a,
                [
                    ("measure", "Measure", "l"),
                    ("statistic", "Statistic", "l"),
                    ("stage", "Stage", "l"),
                    ("n", "n", "r"),
                    ("observed_agreement", "Raw agreement", "r"),
                    ("estimate", "Estimate", "r"),
                    ("ci", "95 pct CI", "c"),
                ],
                "Inter-rater agreement between the independent raters.",
                "agreement",
                "Both statistics are reported and neither replaces the other. "
                "Cohen's kappa is defined for a rater pair on their shared "
                "artefacts. Krippendorff's alpha admits any number of raters "
                "and tolerates the partial overlap the stratified subsample "
                "creates. Intervals are percentile bootstrap intervals over "
                "resampled artefacts.",
            )
        )
        parts.append("")

    s = summary.copy()
    s["pct"] = s["proportion"] * 100
    s["ci"] = [
        "--" if (np.isnan(l) or np.isnan(h)) else f"[{l * 100:.1f}, {h * 100:.1f}]"
        for l, h in zip(s["ci_low"], s["ci_high"])
    ]
    parts.append(
        latex_table(
            s,
            [
                ("arm", "Arm", "l"),
                ("metric", "Metric", "l"),
                ("count", "Count", "r"),
                ("n", "n", "r"),
                ("pct", "Percent", "r"),
                ("ci", "Wilson 95 pct CI", "c"),
            ],
            "Headline outcome rates by arm.",
            "per-arm-summary",
            f"Coding source: {tex_escape(source_note)}",
        )
    )
    parts.append("")

    wide = dist.pivot_table(
        index=["code", "label"], columns="arm", values="count", fill_value=0
    ).reset_index()
    wide["code_order"] = wide["code"].map(rubric.CODE_ORDER)
    wide = wide.sort_values("code_order").drop(columns="code_order")
    cols: list[tuple[str, str, str]] = [("code", "Code", "l"), ("label", "Description", "l")]
    for arm in [c for c in wide.columns if c not in ("code", "label")]:
        cols.append((arm, str(arm), "r"))
    parts.append(
        latex_table(
            wide,
            cols,
            "Distribution of primary rubric codes by arm, counts.",
            "code-distribution",
            "Codes are assigned by an ordered decision procedure, first match "
            "wins, so each artefact contributes to exactly one row.",
        )
    )
    parts.append("")

    b = bd.copy()
    b["pct"] = b["precision"] * 100
    parts.append(
        latex_table(
            b,
            [
                ("arm", "Arm", "l"),
                ("scenario_class", "Scenario", "l"),
                ("n", "n", "r"),
                ("correct_f0", "F0", "r"),
                ("pct", "Precision pct", "r"),
                ("under_action", "Under-action", "r"),
                ("dangerous_action", "Dangerous", "r"),
            ],
            "Precision by scenario class and arm.",
            "scenario-breakdown",
            "B1 is the benign control, where taking no action is the correct "
            "answer.",
        )
    )
    parts.append("")

    parts.append(
        latex_table(
            roll,
            [
                ("arm", "Arm", "l"),
                ("sood_category", "Category", "l"),
                ("codes", "Codes", "l"),
                ("count", "Count", "r"),
                ("percent", "Percent", "r"),
            ],
            "Failures rolled up to Sood's hallucination categories.",
            "sood-rollup",
            "F9 internally inconsistent falls outside Sood's scheme and is "
            "reported separately as Consistency. None denotes F0, which is not "
            "a failure.",
        )
    )
    parts.append("")

    if not comp.empty:
        c = comp.copy()
        c["pair"] = c["arm_a"] + " vs " + c["arm_b"]
        c["pa"] = c["prop_a"] * 100
        c["pb"] = c["prop_b"] * 100
        c["diff"] = c["difference"] * 100
        parts.append(
            latex_table(
                c,
                [
                    ("metric", "Metric", "l"),
                    ("pair", "Comparison", "l"),
                    ("pa", "A pct", "r"),
                    ("pb", "B pct", "r"),
                    ("diff", "Diff pct", "r"),
                    ("fisher_p", "Fisher p", "r"),
                ],
                "Pairwise comparisons between arms, Fisher exact test.",
                "arm-comparisons",
                "These comparisons are exploratory. The study was not powered "
                "for them and no multiplicity correction has been applied, so "
                "the p values are descriptive rather than confirmatory.",
            )
        )
        parts.append("")

    if not lat.empty:
        parts.append(
            latex_table(
                lat,
                [
                    ("arm", "Arm", "l"),
                    ("n", "n", "r"),
                    ("median_ms", "Median ms", "r"),
                    ("p25_ms", "P25 ms", "r"),
                    ("p75_ms", "P75 ms", "r"),
                    ("mean_ms", "Mean ms", "r"),
                    ("sd_ms", "SD ms", "r"),
                ],
                "Generation latency per artefact by arm.",
                "latency",
                "Latency is wall clock time for one request including retries. "
                "The baseline arm performs no network call.",
            )
        )

    path = out_dir / "tables.tex"
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return path


# ----------------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------------


def build_analysis_frame(key: pd.DataFrame, codes: pd.DataFrame) -> pd.DataFrame:
    """Join the chosen coding onto the unblinding key.

    Args:
        key: The unblinding key.
        codes: A frame with `artefact_id`, `primary_code` and optional
            `severity`.

    Returns:
        The analysis frame, one row per coded artefact.
    """
    keep = ["artefact_id", "primary_code"]
    if "severity" in codes.columns:
        keep.append("severity")
    df = key.merge(codes[keep], on="artefact_id", how="inner")
    df = df.rename(columns={"primary_code": "code"})
    missing = len(key) - len(df)
    if missing:
        print(
            f"note: {missing} of {len(key)} artefacts in the key carry no "
            "primary code and are excluded from the outcome tables"
        )
    return df


def report_withheld(rating_dir: Path) -> None:
    """Report artefacts the harness withheld for truncation.

    A response cut off at the token ceiling is a harness measurement error,
    not a model failure, so those artefacts were never put in front of a
    rater and are absent from every table here. That exclusion has to be
    stated rather than left implicit, because it changes the denominator.

    Args:
        rating_dir: The rating package directory.
    """
    mpath = rating_dir / "manifest.json"
    if not mpath.is_file():
        return
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    withheld = manifest.get("withheld_truncated") or []
    if not withheld:
        return
    by_arm: dict[str, int] = {}
    for w in withheld:
        by_arm[str(w.get("arm"))] = by_arm.get(str(w.get("arm")), 0) + 1
    detail = ", ".join(f"{a} {n}" for a, n in sorted(by_arm.items()))
    print(
        f"note: {len(withheld)} artefact(s) were withheld before rating "
        f"because the harness truncated them at the token ceiling ({detail}). "
        f"They are excluded from every denominator below. This is a harness "
        f"limitation, not a model result, and it must be reported as such."
    )


#: Completed rater sheets follow this pattern. Discovery is by glob rather
#: than by a fixed pair of names, because Krippendorff's alpha is defined for
#: any number of raters and the study should be extensible to a third without
#: touching this file. The current design is two raters.
RATER_SHEET_GLOB = "rater_*_ratings.csv"


def discover_rater_sheets(
    rating_dir: Path,
    rater1: str | None,
    rater2: str | None,
    extra: Sequence[str] | None,
) -> dict[str, Path]:
    """Locate every completed rater sheet.

    Args:
        rating_dir: Directory holding the rating package.
        rater1: Explicit override for the primary rater's sheet.
        rater2: Explicit override for the second rater's sheet.
        extra: Additional sheets, each either a path or "name=path".

    Returns:
        Rater name to sheet path.
    """
    found: dict[str, Path] = {}
    for path in sorted(rating_dir.glob(RATER_SHEET_GLOB)):
        name = path.name[len("rater_") : -len("_ratings.csv")]
        if name:
            found[name] = path
    if rater1:
        found["r1"] = Path(rater1)
    if rater2:
        found["r2"] = Path(rater2)
    for spec in extra or []:
        if "=" in spec:
            name, _, raw = spec.partition("=")
            found[name.strip()] = Path(raw.strip())
        else:
            path = Path(spec)
            name = path.stem
            if name.startswith("rater_"):
                name = name[len("rater_") :]
            if name.endswith("_ratings"):
                name = name[: -len("_ratings")]
            found[name or path.stem] = path
    if not found:
        found["r1"] = rating_dir / "rater_r1_ratings.csv"
    return found


def load_adjudication(
    path: Path, labels: Sequence[str]
) -> tuple[dict[str, str], dict[str, str]]:
    """Read the adjudicated codes and severities, if the file exists.

    Args:
        path: Path to adjudicated.csv.
        labels: Valid primary codes.

    Returns:
        A tuple of artefact_id to adjudicated code and artefact_id to
        adjudicated severity. Both are empty when there is no file.
    """
    adjud = read_csv_safe(path, "adjudicated codes")
    if adjud is None or "artefact_id" not in adjud.columns:
        return {}, {}
    col = "adjudicated_code" if "adjudicated_code" in adjud.columns else "primary_code"
    codes: dict[str, str] = {}
    if col in adjud.columns:
        for aid, val in zip(adjud["artefact_id"], adjud[col]):
            v = str(val).strip().upper()
            if v in set(labels):
                codes[str(aid)] = v
    sevs: dict[str, str] = {}
    scol = (
        "adjudicated_severity"
        if "adjudicated_severity" in adjud.columns
        else ("severity" if "severity" in adjud.columns else None)
    )
    if scol:
        for aid, val in zip(adjud["artefact_id"], adjud[scol]):
            v = str(val).strip().upper()
            if v in set(rubric.SEVERITY_IDS):
                sevs[str(aid)] = v
    return codes, sevs


def run(args: argparse.Namespace) -> int:
    """Execute the analysis.

    Args:
        args: Parsed command line arguments.

    Returns:
        A process exit code.
    """
    rating_dir = Path(args.rating_dir)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    key = load_key(Path(args.key) if args.key else rating_dir / "key.csv")
    print(f"key: {len(key)} artefacts across {key['arm'].nunique()} arm(s)")
    report_withheld(rating_dir)

    sheets = discover_rater_sheets(
        rating_dir, args.rater1, args.rater2, getattr(args, "rater", None)
    )
    r1_path = sheets.get("r1", rating_dir / "rater_r1_ratings.csv")
    frames: dict[str, pd.DataFrame] = {}
    for name in sorted(sheets):
        loaded = load_ratings(sheets[name], f"rater {name}")
        if loaded is None:
            continue
        if loaded.empty:
            print(f"warning: rater {name}'s sheet has no completed rows")
            continue
        frames[name] = loaded
    primary = "r1" if "r1" in frames else (sorted(frames)[0] if frames else None)
    r1 = frames[primary] if primary else None
    if primary and primary != "r1":
        print(
            f"note: no rater r1 sheet, using {primary} as the primary rater "
            "for the outcome tables"
        )

    runs = load_runs([Path(d) for d in args.runs]) if args.runs else None
    if runs is not None:
        print(f"runs: {len(runs)} artefacts from {len(args.runs)} run director(ies)")

    if r1 is None:
        # Generation can finish long before rating does. Rather than fail,
        # emit the tables that need no ratings and leave the rest as clearly
        # marked placeholders, so the thesis still compiles.
        if args.tables_dir:
            written = write_thesis_tables(
                Path(args.tables_dir), runs, None, None, 0,
                "No ratings were available when this table was generated.",
            )
            print(
                f"no ratings yet, wrote {len(written)} thesis table(s) to "
                f"{args.tables_dir} (generation tables filled, rating tables "
                f"left as marked placeholders):"
            )
            for w in written:
                print(f"  {w.name}")
            return 0
        raise SystemExit(
            f"error: no usable ratings from rater 1 at {r1_path}. "
            "At least one completed rater sheet is required, or pass "
            "--tables-dir to emit the generation tables only."
        )

    # Adjudication is resolved first, because agreement is reported at two
    # stages and the post-adjudication stage needs the resolved codes.
    adjud_path = (
        Path(args.adjudicated) if args.adjudicated else rating_dir / "adjudicated.csv"
    )
    adj_codes, adj_sevs = load_adjudication(adjud_path, rubric.CODE_IDS)
    resolved_values: dict[str, dict[str, str]] = {}
    if adj_codes:
        resolved_values["primary_code"] = adj_codes
    if adj_sevs:
        resolved_values["severity"] = adj_sevs

    if adj_codes:
        base = r1[["artefact_id", "primary_code", "severity"]].copy()
        base = base[~base["artefact_id"].astype(str).isin(set(adj_codes))]
        rows = [
            {
                "artefact_id": aid,
                "primary_code": code,
                "severity": adj_sevs.get(aid, ""),
            }
            for aid, code in sorted(adj_codes.items())
        ]
        codes = pd.concat([base, pd.DataFrame(rows)], ignore_index=True)
        source_note = (
            f"rater 1 with {len(adj_codes)} artefacts replaced by the "
            "adjudicated code"
        )
    else:
        codes = r1[["artefact_id", "primary_code", "severity"]].copy()
        source_note = (
            "the primary rater's codes over the full corpus. No adjudication "
            "pass was run, so no code was revised after the two raters "
            "compared sheets; reliability is established by the independent "
            "double coding reported in the agreement table."
        )
    print(f"coding source: {source_note}")

    agree_df: pd.DataFrame | None = None
    pairs_df: pd.DataFrame | None = None
    overlap = 0
    if len(frames) >= 2:
        agree_df, adj_rows, pairs_df, crosstab = agreement(
            frames, args.bootstrap, args.seed, resolved_values or None
        )
        agree_df.to_csv(out_dir / "agreement.csv", index=False)
        disagreements = build_disagreement_table(adj_rows)
        disagreements.to_csv(out_dir / "disagreements.csv", index=False)
        pairs_df.to_csv(out_dir / "disagreement_pairs.csv", index=False)
        if not crosstab.empty:
            crosstab.to_csv(out_dir / "disagreement_matrix.csv")
        pre = agree_df[agree_df["stage"] == "pre-adjudication"]
        overlap = int(pre["overlap_n"].max()) if not pre.empty else 0
        names = sorted(frames)
        ids = {n: set(frames[n]["artefact_id"].astype(str)) for n in names}
        only_primary = len(ids[primary] - set().union(
            *[ids[n] for n in names if n != primary]
        ))
        print(
            f"reliability: {len(names)} raters {', '.join(names)}. "
            f"{overlap} artefacts carry at least two codes "
            f"({only_primary} coded by {primary} alone). Cohen's kappa uses "
            "the pairwise overlap; Krippendorff's alpha uses every artefact "
            "carrying at least two codes and needs no complete overlap."
        )
        for n in names:
            if n == primary:
                continue
            stray = len(ids[n] - ids[primary])
            if stray:
                print(
                    f"warning: {stray} artefacts were scored by rater {n} but "
                    f"not by rater {primary}. The subsample should be a subset "
                    "of the full set, so check both sheets came from the same "
                    "rating package."
                )
        if overlap < 30:
            print(
                f"warning: the reliability overlap is only {overlap} "
                "artefacts. Both statistics have a very wide interval at that "
                "size. Report the interval, not the point estimate alone."
            )
        for stage in ("pre-adjudication", "post-adjudication"):
            sub = agree_df[agree_df["stage"] == stage]
            if sub.empty:
                continue
            print(f"  {stage}")
            for _, row in sub.iterrows():
                ci = (
                    "[nan, nan]"
                    if np.isnan(row["ci_low"])
                    else f"[{row['ci_low']:.3f}, {row['ci_high']:.3f}]"
                )
                print(
                    f"    {row['measure']}, {row['statistic']} "
                    f"({row['raters']}): {row['estimate']:.3f} 95% CI {ci} "
                    f"(raw agreement {row['observed_agreement']:.3f}, "
                    f"n={int(row['n'])})"
                )
        if not resolved_values:
            print(
                "  post-adjudication agreement not computed: no adjudicated.csv"
            )
        print(f"  {len(disagreements)} artefacts need adjudication")
        if pairs_df is not None and not pairs_df.empty:
            top = ", ".join(
                f"{r.code_a}/{r.code_b} x{r.count}"
                for r in pairs_df.head(5).itertuples()
            )
            print(f"  most confused code pairs: {top}")
    else:
        print(
            "only one rater sheet available, skipping the agreement "
            "statistics and the disagreement table"
        )

    df = build_analysis_frame(key, codes)
    if df.empty:
        raise SystemExit(
            "error: no artefact has both a key entry and a primary code. The "
            "rater sheet is probably still blank, or the artefact ids do not "
            "match the key."
        )

    summary = per_arm_summary(df)
    dist = code_distribution(df)
    bd = scenario_breakdown(df)
    roll = sood_rollup(df)
    comp = arm_comparisons(df)
    lat = latency_summary(df)

    summary.to_csv(out_dir / "per_arm_summary.csv", index=False)
    dist.to_csv(out_dir / "code_distribution.csv", index=False)
    bd.to_csv(out_dir / "scenario_breakdown.csv", index=False)
    roll.to_csv(out_dir / "sood_rollup.csv", index=False)
    comp.to_csv(out_dir / "arm_comparisons.csv", index=False)
    lat.to_csv(out_dir / "latency.csv", index=False)
    df.to_csv(out_dir / "analysis_frame.csv", index=False)

    fig_code_distribution(dist, out_dir / "fig_code_distribution.pdf")
    fig_precision(summary, out_dir / "fig_precision_by_arm.pdf")
    fig_sood(roll, out_dir / "fig_sood_rollup.pdf")
    fig_scenario(bd, out_dir / "fig_scenario_precision.pdf")
    fig_latency(df, out_dir / "fig_latency.pdf")

    tex = write_tex(out_dir, agree_df, summary, dist, bd, roll, comp, lat, source_note)

    print()
    print(
        "headline results, computed on the primary rater's full set "
        "(adjudication applied where available)"
    )
    for arm in arm_list(df):
        row = summary[(summary["arm"] == arm) & (summary["metric"] == "precision (F0)")]
        if row.empty:
            continue
        r = row.iloc[0]
        print(
            f"  {arm:9s} precision {r['count']:>3d}/{r['n']:<3d} = "
            f"{r['proportion'] * 100:5.1f} pct  "
            f"Wilson 95% CI [{r['ci_low'] * 100:.1f}, {r['ci_high'] * 100:.1f}]"
        )
    print()
    written = sorted(p.name for p in out_dir.iterdir() if p.is_file())
    print(f"wrote {len(written)} files to {out_dir}:")
    for name in written:
        print(f"  {name}")
    print(f"LaTeX tables: {tex}")
    if args.tables_dir:
        overlap_n = overlap
        tw = write_thesis_tables(
            Path(args.tables_dir), runs, df, agree_df, overlap_n,
            source_note, pairs_df,
        )
        print(f"thesis tables: wrote {len(tw)} file(s) to {args.tables_dir}")
        for w in tw:
            print(f"  {w.name}")
        print(
            "  detection_hitrate.tex was not touched, as intended"
        )
    print()
    print(
        "reminder: the pairwise arm comparisons in arm_comparisons.csv are "
        "exploratory, uncorrected for multiplicity, and should be reported as "
        "descriptive."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the command line parser.

    Returns:
        The configured ArgumentParser.
    """
    p = argparse.ArgumentParser(
        prog="analyse.py",
        description=(
            "Compute inter-rater agreement, outcome rates per arm, the Sood "
            "roll-up and latency, then write CSVs, vector figures and "
            "booktabs LaTeX tables."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "example:\n"
            "  python3 analyse.py --rating-dir ../harness/rating --out out\n"
        ),
    )
    p.add_argument(
        "--runs",
        nargs="+",
        default=None,
        help=(
            "generation run directories, each containing artefacts.jsonl. "
            "Used for the corpus, latency and JSON conformance tables, which "
            "do not need ratings"
        ),
    )
    p.add_argument(
        "--tables-dir",
        default=None,
        help=(
            "if given, write the seven thesis tables here, overwriting them. "
            "detection_hitrate.tex is never touched"
        ),
    )
    p.add_argument(
        "--rating-dir",
        default="../harness/rating",
        help="directory holding key.csv and the rater CSVs",
    )
    p.add_argument("--key", default=None, help="explicit path to key.csv")
    p.add_argument("--rater1", default=None, help="explicit path to rater 1 CSV")
    p.add_argument("--rater2", default=None, help="explicit path to rater 2 CSV")
    p.add_argument(
        "--rater",
        nargs="*",
        default=None,
        metavar="NAME=PATH",
        help=(
            "additional rater sheets beyond r1 and r2, each a path or "
            "name=path. Completed sheets matching rater_*_ratings.csv in the "
            "rating directory are picked up automatically."
        ),
    )
    p.add_argument(
        "--adjudicated",
        default=None,
        help="explicit path to adjudicated.csv, optional",
    )
    p.add_argument("--out", default="out", help="output directory (default out)")
    p.add_argument(
        "--bootstrap",
        type=int,
        default=2000,
        help="bootstrap resamples for the kappa intervals (default 2000)",
    )
    p.add_argument(
        "--seed", type=int, default=20260907, help="bootstrap seed (default 20260907)"
    )
    p.add_argument(
        "--selfcheck",
        action="store_true",
        help=(
            "run the Krippendorff alpha sanity checks and exit, without "
            "reading any rating data"
        ),
    )
    return p


def main(argv: Iterable[str] | None = None) -> int:
    """Program entry point.

    Args:
        argv: Argument vector, defaults to sys.argv[1:].

    Returns:
        A process exit code.
    """
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    if args.selfcheck:
        return print_selfcheck(agreement_selfcheck(args.bootstrap, args.seed))
    return run(args)

# ----------------------------------------------------------------------------
# Thesis table emission
# ----------------------------------------------------------------------------

#: The only filenames this script may write into the thesis tables directory.
#: detection_hitrate.tex is written by hand from the lab output and must never
#: be touched here. Anything not on this list is refused.
THESIS_TABLE_FILES = (
    "corpus.tex",
    "agreement.tex",
    "precision.tex",
    "code_distribution.tex",
    "severity.tex",
    "latency.tex",
    "rollup.tex",
)

#: Never write this, under any circumstances.
THESIS_PROTECTED = frozenset({"detection_hitrate.tex"})


def load_runs(run_dirs: Sequence[Path]) -> pd.DataFrame | None:
    """Read artefact records straight from the generation run directories.

    These columns describe generation itself, so they are available before any
    rating has happened.

    Args:
        run_dirs: Directories each containing an `artefacts.jsonl`.

    Returns:
        One row per artefact, or None if nothing could be read.
    """
    frames: list[dict[str, Any]] = []
    for d in run_dirs:
        jl = Path(d) / "artefacts.jsonl"
        if not jl.is_file():
            print(f"warning: no artefacts.jsonl in {d}, skipping")
            continue
        for line in jl.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    frames.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if not frames:
        return None
    df = pd.DataFrame(frames)
    for col in ("parse_ok", "parse_repaired", "truncated"):
        if col in df.columns:
            df[col] = df[col].fillna(False).astype(bool)
        else:
            df[col] = False
    df["latency_ms"] = pd.to_numeric(df.get("latency_ms"), errors="coerce")
    return df


#: Measured from the thesis preamble with \the\textwidth under
#: report/12pt and the geometry settings in thesis/preamble.tex. The brief
#: says 6.3 inches; the document actually gives 6.10 inches, so the stricter
#: number is used.
THESIS_TEXTWIDTH_PT = 441.0

#: Point size of each LaTeX size command in a 12pt document.
LATEX_SIZE_PT = {
    r"\small": 10.95,
    r"\footnotesize": 10.0,
    r"\scriptsize": 8.0,
}

#: Sizes to try, widest first.
SIZE_LADDER = (r"\small", r"\footnotesize", r"\scriptsize")

#: Inter column padding used by these floats. The LaTeX default is 6pt; the
#: floats set 4pt locally, which buys about 24pt on a seven column table and
#: lets several of them stay a size larger. \tabcolsep is a length, not a
#: package, and the assignment is scoped to the float.
TABCOLSEP_PT = 4.0

_NARROW_CHARS = set("ijltfr.,:;()[]|!'/ ")
_WIDE_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZmwMW%")


def _visible(cell: str) -> str:
    """Strip LaTeX markup down to the characters that actually print.

    Args:
        cell: One table cell as written.

    Returns:
        An approximation of the printed text, for width estimation only.
    """
    out = re.sub(r"\\textbf\{([^{}]*)\}", r"\1", cell)
    out = re.sub(r"\\multicolumn\{\d+\}\{[^{}]*\}\{", "", out)
    out = out.replace(r"\%", "%")
    out = re.sub(r"\\(alpha|kappa)", "a", out)
    out = out.replace("_", "")
    out = re.sub(r"\\[a-zA-Z]+", "", out)
    return out.replace("{", "").replace("}", "").replace("$", "")


def _em_width(text: str, bold: bool) -> float:
    """Approximate width of a string in em, for Latin Modern roman."""
    total = 0.0
    for ch in text:
        if ch in _NARROW_CHARS:
            total += 0.30
        elif ch in _WIDE_CHARS:
            total += 0.72
        else:
            total += 0.50
    return total * (1.09 if bold else 1.0)


def estimate_tabular_width(tab: str, size: str) -> float:
    """Estimate the printed width of one tabular in points.

    Calibrated against ten tabulars measured with \\the\\wd under the real
    thesis preamble. The estimate ran between 2.6 and 10.6 per cent high on
    that sample, never low, so it errs towards choosing a smaller font rather
    than towards letting an overfull box through.

    Args:
        tab: A complete tabular environment.
        size: A LaTeX size command such as "\\footnotesize".

    Returns:
        Estimated width in points.
    """
    pt = LATEX_SIZE_PT.get(size, 10.0)
    header: list[str] | None = None
    rows: list[list[str]] = []
    for line in (ln.strip() for ln in tab.splitlines()):
        if not line.endswith(r"\\"):
            continue
        cells = line[:-2].split("&")
        if r"\multicolumn" in line and len(cells) == 1:
            continue
        if header is None:
            header = cells
        else:
            rows.append(cells)
    if not header:
        return 0.0
    ncols = len(header)
    widths = [_em_width(_visible(c), True) for c in header]
    for row in rows:
        for j, cell in enumerate(row[:ncols]):
            widths[j] = max(widths[j], _em_width(_visible(cell), False))
    return sum(widths) * pt + 2.0 * TABCOLSEP_PT * (ncols - 1)


def choose_size(body: str, label: str) -> str:
    """Pick the largest size at which every panel still fits the text block.

    Args:
        body: One or more tabular environments.
        label: Table label, used only in the warning.

    Returns:
        A LaTeX size command.
    """
    tabs = re.findall(r"\\begin\{tabular\}.*?\\end\{tabular\}", body, re.S)
    if not tabs:
        return r"\small"
    for size in SIZE_LADDER:
        widest = max(estimate_tabular_width(t, size) for t in tabs)
        if widest <= THESIS_TEXTWIDTH_PT:
            return size
    smallest = SIZE_LADDER[-1]
    over = max(estimate_tabular_width(t, smallest) for t in tabs)
    print(
        f"warning: table {label} is an estimated {over - THESIS_TEXTWIDTH_PT:.0f}pt "
        f"too wide even at {smallest}. Shorten a column or split the table."
    )
    return smallest


def thesis_float(
    body: str,
    caption: str,
    label: str,
    note: str = "",
    size: str | None = None,
) -> str:
    """Wrap a tabular in a complete, self contained thesis float.

    Args:
        body: One or more complete tabular environments.
        caption: The caption text, already escaped.
        label: Label suffix, used as `tab:<label>`.
        note: Optional footnote under the table.
        size: A LaTeX size command applied inside the float. None picks the
            largest size at which the table still fits the text block.

    Returns:
        A complete table environment from begin to end.
    """
    parts = [
        r"%% generated by lab/analysis/analyse.py, do not edit by hand",
        r"\begin{table}[H]",
        r"\centering",
        r"\caption{" + caption + "}",
        r"\label{tab:" + label + "}",
        r"\setlength{\tabcolsep}{4pt}",
        size if size else choose_size(body, label),
        body.rstrip(),
    ]
    if note:
        parts.append(r"\par\vspace{2pt}\footnotesize\raggedright " + note)
    parts.append(r"\end{table}")
    return "\n".join(parts) + "\n"


def tabular(
    colspec: str, header: Sequence[str], rows: Sequence[Sequence[str]],
    midrules_before: Sequence[int] = (),
) -> str:
    """Build one booktabs tabular.

    Args:
        colspec: The LaTeX column specification.
        header: Header cells, already escaped.
        rows: Body rows, cells already escaped.
        midrules_before: Row indices that should be preceded by a midrule.

    Returns:
        A complete tabular environment.
    """
    out = [
        r"\begin{tabular}{@{}" + colspec + r"@{}}",
        r"\toprule",
        " & ".join(r"\textbf{" + h + "}" for h in header) + r" \\",
        r"\midrule",
    ]
    for i, row in enumerate(rows):
        if i in midrules_before:
            out.append(r"\midrule")
        out.append(" & ".join(row) + r" \\")
    out += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(out)


def pending_float(caption: str, label: str, reason: str) -> str:
    """Emit a clearly marked placeholder when the inputs are not ready yet.

    A placeholder is far safer than a half filled table, because it cannot be
    mistaken for a result.

    Args:
        caption: The intended caption.
        label: Label suffix.
        reason: Why the table could not be built.

    Returns:
        A complete table environment.
    """
    body = tabular("l", ["Status"], [[tex_escape(reason)]])
    return thesis_float(
        body,
        caption + " (pending)",
        label,
        note=(
            "This table is a placeholder. It is regenerated by "
            r"\texttt{lab/analysis/analyse.py} once the required input exists."
        ),
    )


def pct(k: int, n: int) -> str:
    """Format a count as a percentage string, guarding division by zero."""
    if not n:
        return "n/a"
    return f"{100.0 * k / n:.1f}\\%"


def ci_str(lo: float, hi: float) -> str:
    """Format a confidence interval as a bracketed percentage range."""
    if pd.isna(lo) or pd.isna(hi):
        return "n/a"
    return f"[{100.0 * lo:.1f}, {100.0 * hi:.1f}]"


def arms_present(runs: pd.DataFrame | None, df: pd.DataFrame | None) -> list[str]:
    """Return the arms to report, in the canonical order.

    Args:
        runs: The generation frame, or None.
        df: The rated analysis frame, or None.

    Returns:
        Arm names ordered by ARM_ORDER, with any extras appended.
    """
    seen: set[str] = set()
    for src in (runs, df):
        if src is not None and "arm" in src.columns:
            seen |= {str(a) for a in src["arm"].dropna().unique()}
    ordered = [a for a in ARM_ORDER if a in seen]
    return ordered + sorted(seen - set(ordered))


def table_corpus(runs: pd.DataFrame | None) -> str:
    """The generated corpus and its serialisation outcomes."""
    cap = "Generated remediation corpus and response parsing outcomes"
    if runs is None or runs.empty:
        return pending_float(cap, "corpus", "Generation has not been run yet.")
    rows: list[list[str]] = []
    for arm in arms_present(runs, None):
        sub = runs[runs["arm"] == arm]
        n = len(sub)
        model = str(sub["model_id"].iloc[0]) if "model_id" in sub else "n/a"
        alerts = sub["alert_id"].nunique() if "alert_id" in sub else 0
        samples = (
            int(sub["sample_index"].max()) + 1 if "sample_index" in sub else 1
        )
        strict = int((sub["parse_ok"] & ~sub["parse_repaired"]).sum())
        rep = int(sub["parse_repaired"].sum())
        fail = int((~sub["parse_ok"]).sum())
        trunc = int(sub["truncated"].sum())
        rows.append([
            tex_escape(arm), tex_escape(model), str(alerts), str(samples),
            str(n), str(strict), str(rep), str(fail), str(trunc),
        ])
    tot = runs
    rows.append([
        r"\textbf{Total}", "", "", "", str(len(tot)),
        str(int((tot["parse_ok"] & ~tot["parse_repaired"]).sum())),
        str(int(tot["parse_repaired"].sum())),
        str(int((~tot["parse_ok"]).sum())),
        str(int(tot["truncated"].sum())),
    ])
    body = tabular(
        "llrrrrrrr",
        ["Arm", "Model", "Alerts", "Samples", "Artefacts",
         "Strict", "Repaired", "Failed", "Truncated"],
        rows,
        midrules_before=(len(rows) - 1,),
    )
    pv = ""
    if "prompt_version" in runs.columns and len(runs):
        pv = str(runs["prompt_version"].iloc[0])
    fp = ""
    if "prompt_fingerprint" in runs.columns and len(runs):
        fp = str(runs["prompt_fingerprint"].iloc[0])
    note = (
        "Strict counts responses that parsed as conformant JSON unaided. "
        "Repaired counts those that needed a lenient reparse tolerating "
        "literal control characters inside strings; these are rated normally, "
        "because the construct under study is remediation quality rather than "
        "serialisation conformance. Failed counts responses that could not be "
        "parsed at all. Truncated counts responses the harness cut off at the "
        "token ceiling; these are withheld from rating and are a harness "
        "limitation, not a model result. "
        f"Prompt version {tex_escape(pv)}, fingerprint {tex_escape(fp)}."
    )
    return thesis_float(body, cap, "corpus", note)


def table_latency(runs: pd.DataFrame | None) -> str:
    """Wall clock latency per arm."""
    cap = "Response latency by arm"
    if runs is None or runs.empty or runs["latency_ms"].isna().all():
        return pending_float(cap, "latency", "Generation has not been run yet.")
    rows = []
    for arm in arms_present(runs, None):
        s = runs.loc[runs["arm"] == arm, "latency_ms"].dropna() / 1000.0
        if s.empty:
            continue
        def sec(v: float) -> str:
            """Render seconds, avoiding a bare 0.0 for the offline arm."""
            return "$<$0.1" if v < 0.05 else f"{v:.1f}"

        rows.append([
            tex_escape(arm), str(len(s)),
            sec(s.median()), sec(s.mean()),
            sec(s.quantile(0.90)), sec(s.min()), sec(s.max()),
        ])
    body = tabular(
        "lrrrrrr",
        ["Arm", "n", "Median", "Mean", "P90", "Min", "Max"],
        rows,
    )
    note = (
        "All values in seconds, wall clock for one request including any "
        "retries, measured on a single machine on a single network. The "
        "baseline arm performs no network call. These figures are an "
        "operational indicator, not a benchmark."
    )
    return thesis_float(body, cap, "latency", note)


def table_precision(
    df: pd.DataFrame | None, runs: pd.DataFrame | None, source_note: str
) -> str:
    """Outcome rates per arm, plus a serialisation conformance panel."""
    cap = "Remediation outcome rates by arm, with strict JSON conformance"
    if df is None or df.empty:
        return pending_float(cap, "precision", "No rated artefacts yet.")
    rows = []
    for arm in arms_present(None, df):
        sub = df[df["arm"] == arm]
        n = len(sub)
        cells = [tex_escape(arm), str(n)]
        for mask in (
            sub["code"] == "F0",
            sub["code"].isin(rubric.UNDER_ACTION_CODES),
            sub["code"].isin(rubric.DANGEROUS_ACTION_CODES),
        ):
            k = int(mask.sum())
            lo, hi = wilson(k, n)
            cells += [f"{k}", pct(k, n), ci_str(lo, hi)]
        rows.append(cells)
    body = tabular(
        "lr" + "rrc" * 3,
        ["Arm", "n",
         "F0", "Precision", "95\\% CI",
         "n", "Under-action", "95\\% CI",
         "n", "Dangerous", "95\\% CI"],
        rows,
    )

    panel = ""
    if runs is not None and not runs.empty:
        prows = []
        for arm in arms_present(runs, None):
            sub = runs[runs["arm"] == arm]
            n = len(sub)
            strict = int((sub["parse_ok"] & ~sub["parse_repaired"]).sum())
            rep = int(sub["parse_repaired"].sum())
            fail = int((~sub["parse_ok"]).sum())
            lo, hi = wilson(strict, n)
            prows.append([
                tex_escape(arm), str(n), str(strict), pct(strict, n),
                ci_str(lo, hi), str(rep), pct(rep, n), str(fail),
            ])
        panel = (
            "\n\n" + r"\vspace{6pt}" + "\n"
            + r"\par\textbf{Strict JSON conformance, descriptive}" + "\n\n"
            + tabular(
                "lrrrcrrr",
                ["Arm", "n", "Strict", "Conformance", "95\\% CI",
                 "Repaired", "Repair rate", "Failed"],
                prows,
            )
        )

    note = (
        "Precision is the proportion coded F0, correct and safe. Under-action "
        "is F5 plus F8. Dangerous action is F4 plus F7. Intervals are Wilson "
        "score intervals. The lower panel is a descriptive secondary "
        "statistic: it reports how often each arm emitted conformant JSON "
        "unaided, and is not a remediation quality measure. "
        + sentence(source_note)
    )
    return thesis_float(body + panel, cap, "precision", note)


def sentence(text: str) -> str:
    """Capitalise the first letter so a note reads as prose, not a fragment."""
    text = text.strip()
    return text[:1].upper() + text[1:] if text else text


def table_agreement(
    agree_df: pd.DataFrame | None,
    overlap_n: int,
    pairs_df: pd.DataFrame | None = None,
) -> str:
    """Inter-rater agreement, both statistics, both stages, plus confusions."""
    cap = "Inter-rater agreement and code confusions"
    if agree_df is None or agree_df.empty:
        return pending_float(
            cap, "agreement", "The second rater has not returned a sheet yet."
        )

    stat_short = {
        "Cohen kappa": "Cohen $\\kappa$",
        "Cohen kappa (linear weights)": "Cohen $\\kappa_w$ (linear)",
        "Krippendorff alpha": "Krippendorff $\\alpha$",
    }
    stage_short = {"pre-adjudication": "Pre", "post-adjudication": "Post"}
    measures = list(dict.fromkeys(agree_df["measure"].tolist()))
    rows: list[list[str]] = []
    for pos, m in enumerate(measures):
        lead = "\\addlinespace " if pos else ""
        rows.append([
            f"{lead}\\multicolumn{{7}}{{@{{}}l}}{{\\textit{{{tex_escape(m)}}}}}"
        ])
        sub = agree_df[agree_df["measure"] == m]
        for stage in ("pre-adjudication", "post-adjudication"):
            block = sub[sub["stage"] == stage]
            for _, r in block.iterrows():
                stat = str(r.get("statistic", ""))
                rows.append([
                    stat_short.get(stat, tex_escape(stat)),
                    tex_escape(str(r.get("raters", ""))),
                    stage_short.get(str(r.get("stage", "")), ""),
                    str(int(r.get("n", 0) or 0)),
                    fmt(r.get("estimate"), 3),
                    f"[{fmt(r.get('ci_low'), 3)}, {fmt(r.get('ci_high'), 3)}]",
                    fmt(r.get("observed_agreement"), 3),
                ])
    body = tabular(
        "lllrrcr",
        ["Statistic", "Raters", "Stage", "n", "Estimate", "95\\% CI",
         "Raw agreement"],
        rows,
    )

    panel = ""
    if pairs_df is not None and not pairs_df.empty:
        labels = {c.code: c.label for c in rubric.CODES}
        total = int(pairs_df["count"].sum())
        shown = pairs_df.head(10)
        prows = []
        for r in shown.itertuples():
            prows.append([
                f"{r.code_a} / {r.code_b}",
                tex_escape(
                    f"{labels.get(r.code_a, r.code_a)} vs "
                    f"{labels.get(r.code_b, r.code_b)}"
                ),
                str(int(r.count)),
                pct(int(r.count), total),
            ])
        rest = total - int(shown["count"].sum())
        if rest > 0:
            prows.append([
                "other",
                tex_escape(
                    f"{len(pairs_df) - len(shown)} further pairs, "
                    "each less frequent"
                ),
                str(rest),
                pct(rest, total),
            ])
        panel = (
            "\n\\vspace{6pt}\n"
            "\\par\\textbf{Code pairs the raters confused, "
            "pre-adjudication}\n\n"
            + tabular(
                "llrr",
                ["Pair", "Codes", "n", "\\% of disagreements"],
                prows,
            )
        )

    warn = ""
    if overlap_n and overlap_n < 30:
        warn = (
            f" The overlap is only {overlap_n} artefacts, so both intervals "
            "are wide and no point estimate should be read alone."
        )
    has_post = (
        "post-adjudication" in set(agree_df["stage"].tolist())
        if "stage" in agree_df.columns
        else False
    )
    post_note = (
        " Post-adjudication figures describe the codes the headline results "
        "actually use, and sit close to one by construction, so they are "
        "reported beside the pre-adjudication figures rather than in place "
        "of them."
        if has_post
        else " Post-adjudication agreement is not shown because no "
        "adjudication pass was run; every figure here is pre-adjudication."
    )
    note = (
        "Cohen's kappa is unweighted over the ten nominal codes and linearly "
        "weighted over the ordered severity scale S0 to S3. It is defined for "
        "a rater pair on the artefacts both scored. Krippendorff's alpha uses "
        "the nominal metric for the code and the ordinal metric for severity, "
        "admits any number of raters and needs no complete overlap. Both "
        "raters coded every artefact here, so the two statistics are expected "
        "to agree closely and their agreement serves as an implementation "
        "check. Both intervals are 95 per cent percentile bootstrap intervals "
        "resampling artefacts, not asymptotic intervals, because at ten "
        "categories several cells stay sparse and the normal approximation is "
        "unreliable."
        + post_note
        + warn
    )
    return thesis_float(body + panel, cap, "agreement", note)


def table_code_distribution(df: pd.DataFrame | None, source_note: str) -> str:
    """Full ten code distribution per arm."""
    cap = "Distribution of the ten rubric codes by arm"
    if df is None or df.empty:
        return pending_float(
            cap, "code_distribution", "No rated artefacts yet."
        )
    arms = arms_present(None, df)
    header = ["Code", "Description"]
    for a in arms:
        header += [a, "\\%"]
    rows = []
    for c in rubric.CODES:
        sub_cells = [c.code, tex_escape(c.label)]
        for a in arms:
            arm_df = df[df["arm"] == a]
            k = int((arm_df["code"] == c.code).sum())
            sub_cells += [str(k), pct(k, len(arm_df))]
        rows.append(sub_cells)
    totals = [r"\textbf{Total}", ""]
    for a in arms:
        totals += [str(len(df[df["arm"] == a])), ""]
    rows.append(totals)
    body = tabular(
        "ll" + "rr" * len(arms), header, rows,
        midrules_before=(len(rows) - 1,),
    )
    note = (
        "Codes are applied by an ordered decision procedure in which the "
        "first matching test wins, so the categories are mutually exclusive "
        "and sum to the column total. " + sentence(source_note)
    )
    return thesis_float(body, cap, "code_distribution", note)


def table_severity(df: pd.DataFrame | None, source_note: str) -> str:
    """Severity distribution per arm."""
    cap = "Severity of the consequence had the artefact been executed"
    if df is None or df.empty or "severity" not in df.columns:
        return pending_float(
            cap, "severity", "No severity annotations recorded yet."
        )
    sev = df[df["severity"].notna() & (df["severity"].astype(str) != "")]
    if sev.empty:
        return pending_float(
            cap, "severity", "No severity annotations recorded yet."
        )
    arms = arms_present(None, sev)
    header = ["Severity", "Meaning"]
    for a in arms:
        header += [a, "\\%"]
    short = {
        "S0": "No consequence",
        "S1": "Minor, trivially reversed",
        "S2": "Serious, access lost or threat uncontained",
        "S3": "Critical, evidence or data destroyed",
    }
    rows = []
    for code, _desc in rubric.SEVERITY:
        cells = [code, tex_escape(short.get(code, ""))]
        for a in arms:
            arm_df = sev[sev["arm"] == a]
            k = int((arm_df["severity"].astype(str) == code).sum())
            cells += [str(k), pct(k, len(arm_df))]
        rows.append(cells)
    totals = [r"\textbf{Total}", ""]
    for a in arms:
        totals += [str(len(sev[sev["arm"] == a])), ""]
    rows.append(totals)
    body = tabular(
        "ll" + "rr" * len(arms), header, rows,
        midrules_before=(len(rows) - 1,),
    )
    note = (
        "Severity is a secondary annotation recorded alongside the primary "
        "code, and describes the worst plausible outcome had the artefact "
        "been executed as written. " + sentence(source_note)
    )
    return thesis_float(body, cap, "severity", note)


def table_rollup(df: pd.DataFrame | None, source_note: str) -> str:
    """Roll-up to Sood's five hallucination categories."""
    cap = "Failure modes rolled up to Sood's hallucination categories"
    if df is None or df.empty:
        return pending_float(cap, "rollup", "No rated artefacts yet.")
    arms = arms_present(None, df)
    header = ["Category", "Codes"]
    for a in arms:
        header += [a, "\\%"]
    members: dict[str, list[str]] = {}
    for c in rubric.CODES:
        cat = rubric.sood_category(c.code)
        members.setdefault(cat, []).append(c.code)
    rows = []
    for cat in list(rubric.SOOD_ORDER) + ["Consistency", "None"]:
        codes = members.get(cat, [])
        if not codes:
            continue
        cells = [tex_escape(cat), tex_escape(", ".join(codes))]
        for a in arms:
            arm_df = df[df["arm"] == a]
            k = int(arm_df["code"].isin(codes).sum())
            cells += [str(k), pct(k, len(arm_df))]
        rows.append(cells)
    totals = [r"\textbf{Total}", ""]
    for a in arms:
        totals += [str(len(df[df["arm"] == a])), ""]
    rows.append(totals)
    body = tabular(
        "ll" + "rr" * len(arms), header, rows,
        midrules_before=(len(rows) - 1,),
    )
    note = (
        "Factual covers F1 and F2, Attributional F3, Logical F4 and F7, "
        "Contextual F5 and F6, Ambiguous F8. F9 has no counterpart in Sood's "
        "scheme and is reported separately as Consistency. F0, correct and "
        "safe, is not a failure and is shown as None. " + sentence(source_note)
    )
    return thesis_float(body, cap, "rollup", note)


def write_thesis_tables(
    tables_dir: Path,
    runs: pd.DataFrame | None,
    df: pd.DataFrame | None,
    agree_df: pd.DataFrame | None,
    overlap_n: int,
    source_note: str,
    pairs_df: pd.DataFrame | None = None,
) -> list[Path]:
    """Write the seven thesis tables, and nothing else.

    Only the filenames on THESIS_TABLE_FILES may be written. Any other name,
    and in particular the hand written detection_hitrate.tex, is refused. The
    guard is belt and braces: the names are also hard coded below.

    Args:
        tables_dir: The thesis tables directory.
        runs: Generation frame, or None.
        df: Rated analysis frame, or None.
        agree_df: Agreement frame, or None.
        overlap_n: Number of double coded artefacts.
        source_note: Sentence naming the coding source.
        pairs_df: Confused code pair counts, or None.

    Returns:
        The paths written.
    """
    tables_dir.mkdir(parents=True, exist_ok=True)
    content = {
        "corpus.tex": table_corpus(runs),
        "latency.tex": table_latency(runs),
        "precision.tex": table_precision(df, runs, source_note),
        "agreement.tex": table_agreement(agree_df, overlap_n, pairs_df),
        "code_distribution.tex": table_code_distribution(df, source_note),
        "severity.tex": table_severity(df, source_note),
        "rollup.tex": table_rollup(df, source_note),
    }
    written: list[Path] = []
    for name, text in content.items():
        if name in THESIS_PROTECTED or name not in THESIS_TABLE_FILES:
            print(f"refusing to write {name}: not on the allowed list")
            continue
        if "—" in text:
            raise SystemExit(
                f"error: an em dash reached {name}. Fix the generator."
            )
        path = tables_dir / name
        path.write_text(text, encoding="utf-8")
        written.append(path)
    return written


if __name__ == "__main__":
    raise SystemExit(main())

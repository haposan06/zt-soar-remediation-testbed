#!/usr/bin/env python3
"""Build the blinded rating package from one or more artefact files.

Reads `artefacts.jsonl` from every arm, shuffles the pooled artefacts with a
recorded seed so that arm order is not guessable, strips every field that
would reveal which arm produced an artefact, and writes

    rating/blind_artefacts.json      the full set, loaded by the primary rater
    rating/key.csv                   the unblinding key, experimenter only
    rating/rater_<name>_sheet.csv    empty sheet for the primary rater
    rating/manifest.json             seed and provenance for the method chapter

When --subsample N is greater than zero and a second rater is named, the
reliability pass is run on a stratified subsample rather than on all 126
artefacts, because the second rater has limited time. Three more files appear.

    rating/rater2_subsample.json           the subsample, loaded by rater two
    rating/rater_<name>_subsample_sheet.csv  empty sheet for each extra rater
    rating/subsample_manifest.csv          the draw and its seed, experimenter
                                           only, it names the arm

The subsample is drawn from the same pool, so every artefact in it also
appears in the primary rater's full set. Cohen's kappa is therefore computed
on the overlap, while all precision, under-action and dangerous-action figures
come from the primary rater's full set after adjudication. Adjudication covers
the overlap only.

The draw is stratified jointly by arm and scenario class, allocated in
proportion to stratum size by the largest remainder method, so all three arms
and all four scenario classes appear in roughly their population share.

The key file is written with a loud header comment and must never be given to
a rater. Everything a rater sees comes from blind_artefacts.json.

Blinding limitation worth stating in the thesis: the baseline arm is a
template playbook and its prose is visibly formulaic once a rater has seen a
few. Blinding removes the label, not the style. This is recorded in the
manifest so the limitation is not lost.

Typical use

  python3 make_rating_sheet.py \\
      --artefacts runs/final-gemini/artefacts.jsonl runs/final-claude/artefacts.jsonl \\
                  runs/final-baseline/artefacts.jsonl \\
      --raters r1 r2 --seed 20260912 --out rating
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rubric  # noqa: E402  (local module, path adjusted above)

DEFAULT_SEED = 20260912  # the 2026-09-06 pilot used 20260907

#: Fields removed from every artefact before a rater sees it. Anything that
#: names the arm, the model, the sampling position or the wall clock cost of
#: the call is a tell.
BLIND_STRIP_FIELDS = frozenset(
    {
        "arm",
        "model_id",
        "model_version",
        "sample_index",
        "endpoint",
        "temperature",
        "top_p",
        "max_tokens",
        "json_mode",
        "thinking_budget",
        "reasoning_mode",
        "reasoning_detail",
        "finish_reason",
        "truncated",
        "latency_ms",
        "attempts",
        "request_timestamp",
        "harness_version",
        "prompt_version",
        "prompt_fingerprint",
        "extra_keys",
        "missing_keys",
        # Repair provenance. A rater judging the remediation must not be told
        # that the envelope needed a lenient reparse, or they would read it as
        # a quality signal about the arm.
        "parse_repaired",
        "strict_parse_error",
        # Design labels. scenario_class would tell the rater outright whether
        # no action was the correct answer.
        "scenario_class",
        "is_true_positive",
    }
)

#: Columns of the unblinding key.
KEY_COLUMNS = (
    "artefact_id",
    "display_index",
    "arm",
    "model_id",
    "model_version",
    "sample_index",
    "alert_id",
    "rule_id",
    "scenario_class",
    "is_true_positive",
    "temperature",
    "top_p",
    "max_tokens",
    "json_mode",
    "reasoning_mode",
    "reasoning_detail",
    "endpoint",
    "prompt_version",
    "latency_ms",
    "parse_ok",
    "parse_repaired",
    "language",
    "source_file",
)


# ----------------------------------------------------------------------------
# Rater reference card
# ----------------------------------------------------------------------------

#: Marker in rate.html replaced by the rendered reference card at build time.
REFERENCE_PLACEHOLDER = "<!--REFERENCE_CARD_PLACEHOLDER-->"


def _inline_markdown(text: str) -> str:
    """Render the inline subset of Markdown used by the reference card.

    Handles `code`, **bold** and *italic*, in that order, on text that has
    already been HTML escaped.

    Args:
        text: Escaped source text.

    Returns:
        An HTML fragment.
    """
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![*\w])\*([^*]+)\*(?![*\w])", r"<em>\1</em>", text)
    return text


def render_markdown(md: str) -> str:
    """Render the Markdown subset used by the reference card to HTML.

    Deliberately tiny and dependency free: headings, tables, bullet lists and
    paragraphs. Everything is HTML escaped before any markup is introduced, so
    the card cannot inject script into the rating tool.

    Args:
        md: Markdown source.

    Returns:
        An HTML fragment.
    """
    esc = (
        md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
    lines = esc.split("\n")
    out: list[str] = []
    i = 0
    in_list = False

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()
        stripped = line.strip()

        if not stripped:
            close_list()
            i += 1
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m:
            close_list()
            level = min(len(m.group(1)) + 1, 6)
            out.append(f"<h{level}>{_inline_markdown(m.group(2))}</h{level}>")
            i += 1
            continue

        # A table is a pipe row followed by a dashed separator row.
        if stripped.startswith("|") and i + 1 < len(lines):
            sep = lines[i + 1].strip()
            if re.match(r"^\|[\s:\-\|]+\|$", sep) and "-" in sep:
                close_list()
                header = [c.strip() for c in stripped.strip("|").split("|")]
                out.append('<table class="refTable"><thead><tr>')
                for c in header:
                    out.append(f"<th>{_inline_markdown(c)}</th>")
                out.append("</tr></thead><tbody>")
                i += 2
                while i < len(lines) and lines[i].strip().startswith("|"):
                    cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                    out.append("<tr>")
                    for c in cells:
                        out.append(f"<td>{_inline_markdown(c)}</td>")
                    out.append("</tr>")
                    i += 1
                out.append("</tbody></table>")
                continue

        m = re.match(r"^[-*]\s+(.*)$", stripped)
        if m:
            if not in_list:
                out.append("<ul>")
                in_list = True
            item = [m.group(1)]
            i += 1
            # Continuation lines of the same bullet are indented.
            while i < len(lines) and re.match(r"^\s{2,}\S", lines[i]):
                item.append(lines[i].strip())
                i += 1
            out.append(f"<li>{_inline_markdown(' '.join(item))}</li>")
            continue

        close_list()
        para = [stripped]
        i += 1
        while i < len(lines) and lines[i].strip() and not re.match(
            r"^(#{1,6}\s|[-*]\s|\|)", lines[i].strip()
        ):
            para.append(lines[i].strip())
            i += 1
        out.append(f"<p>{_inline_markdown(' '.join(para))}</p>")

    close_list()
    return "\n".join(out)


def build_rate_html(
    out_dir: Path, template: Path, reference: Path | None
) -> tuple[Path, bool]:
    """Copy rate.html into the rating package with the reference card inlined.

    The card is inlined at build time rather than fetched at runtime, so the
    delivered rate.html stays a single self contained file that works from a
    file:// URL with no network.

    Args:
        out_dir: The rating package directory.
        template: Path to the rate.html source template.
        reference: Path to reference.md, or None to skip.

    Returns:
        A tuple of the written path and whether a card was actually inlined.

    Raises:
        SystemExit: If the template is missing.
    """
    if not template.is_file():
        raise SystemExit(f"error: rate.html template not found at {template}")
    html = template.read_text(encoding="utf-8")

    if reference is not None and reference.is_file():
        card = render_markdown(reference.read_text(encoding="utf-8"))
        inlined = True
    else:
        card = (
            "<p>The reference card was not built into this copy. Ask the "
            "experimenter for reference.md.</p>"
        )
        inlined = False

    if REFERENCE_PLACEHOLDER not in html:
        raise SystemExit(
            f"error: {template} has no {REFERENCE_PLACEHOLDER} marker, so the "
            "reference card cannot be inlined. The template is out of date."
        )
    html = html.replace(REFERENCE_PLACEHOLDER, card)
    dest = out_dir / "rate.html"
    dest.write_text(html, encoding="utf-8")
    return dest, inlined


def read_artefacts(paths: Sequence[Path]) -> list[dict[str, Any]]:
    """Read and concatenate artefact records from JSONL files.

    Args:
        paths: One or more `artefacts.jsonl` paths.

    Returns:
        The pooled artefact records, each tagged with `source_file`.

    Raises:
        SystemExit: If a file is missing or a line is not valid JSON.
    """
    records: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            raise SystemExit(f"error: artefact file not found: {path}")
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"error: {path} line {lineno} is not valid JSON: {exc}"
                ) from exc
            rec["source_file"] = str(path)
            records.append(rec)
    if not records:
        raise SystemExit("error: no artefacts were read")
    return records


def check_duplicates(records: Sequence[dict[str, Any]]) -> list[str]:
    """Report artefact ids that appear more than once in the pool.

    Args:
        records: The pooled artefact records.

    Returns:
        A list of duplicated artefact ids.
    """
    seen: set[str] = set()
    dupes: set[str] = set()
    for r in records:
        aid = str(r.get("artefact_id"))
        if aid in seen:
            dupes.add(aid)
        seen.add(aid)
    return sorted(dupes)


def blind_record(record: dict[str, Any], display_index: int) -> dict[str, Any]:
    """Strip a record down to what a blinded rater is allowed to see.

    The raw response text is carried through only when parsing failed, because
    that is exactly the case where the rater has to look at the unparseable
    blob to decide F1. For parsed artefacts the raw text would leak formatting
    habits that differ by arm.

    Args:
        record: One full artefact record.
        display_index: Position in the shuffled order, one based.

    Returns:
        The blinded artefact object.
    """
    parse_ok = bool(record.get("parse_ok"))
    out: dict[str, Any] = {
        "artefact_id": record.get("artefact_id"),
        "display_index": display_index,
        "alert": record.get("alert_summary", {}),
        "parse_ok": parse_ok,
        "rationale": record.get("rationale"),
        "language": record.get("language"),
        "script": record.get("script"),
        "rollback": record.get("rollback"),
        "stated_confidence": record.get("confidence"),
    }
    if not parse_ok:
        out["parse_error"] = record.get("parse_error")
        out["raw_response_text"] = record.get("raw_response_text", "")
    for stripped in BLIND_STRIP_FIELDS:
        assert stripped not in out, f"blinding leak: {stripped}"
    return out


def write_blind_json(
    blinded: Sequence[dict[str, Any]],
    out_dir: Path,
    seed: int,
    filename: str = "blind_artefacts.json",
    set_id: str = "full",
) -> Path:
    """Write a file the raters load into rate.html.

    Args:
        blinded: The shuffled, stripped artefacts.
        out_dir: The rating package directory.
        seed: The shuffle seed, recorded inside the file for traceability.
        filename: Output file name.
        set_id: Either "full" or "subsample". rate.html shows this so a rater
            can tell which set they opened, and uses it to notice when saved
            progress belongs to a different set.

    Returns:
        The path written.
    """
    path = out_dir / filename
    payload = {
        "package_version": "rating-package-v1",
        "set_id": set_id,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "shuffle_seed": seed,
        "artefact_count": len(blinded),
        "rubric_version": "ten-code-v1",
        "artefacts": list(blinded),
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def largest_remainder(
    sizes: dict[tuple[str, str], int], target: int
) -> dict[tuple[str, str], int]:
    """Allocate `target` draws across strata in proportion to stratum size.

    Uses the largest remainder method, then clips each allocation to the
    stratum size and redistributes any shortfall to strata that still have
    spare artefacts. This keeps all three arms and all four scenario classes
    represented rather than letting rounding wipe out a small stratum.

    Args:
        sizes: Map of stratum key to the number of artefacts available.
        target: Total number of artefacts to draw.

    Returns:
        Map of stratum key to the number to draw from it.
    """
    total = sum(sizes.values())
    if total == 0 or target <= 0:
        return {k: 0 for k in sizes}
    target = min(target, total)
    exact = {k: target * v / total for k, v in sizes.items()}
    alloc = {k: min(int(v), sizes[k]) for k, v in exact.items()}
    # A non empty stratum should contribute at least one artefact where the
    # budget allows it, otherwise a small cell can vanish from the reliability
    # estimate entirely.
    for k in sorted(sizes, key=lambda x: (-sizes[x], x)):
        if sizes[k] > 0 and alloc[k] == 0 and sum(alloc.values()) < target:
            alloc[k] = 1
    remainder = sorted(
        sizes, key=lambda k: (-(exact[k] - int(exact[k])), -sizes[k], k)
    )
    i = 0
    guard = 0
    while sum(alloc.values()) < target and guard < 10000:
        k = remainder[i % len(remainder)]
        if alloc[k] < sizes[k]:
            alloc[k] += 1
        i += 1
        guard += 1
    while sum(alloc.values()) > target:
        for k in sorted(sizes, key=lambda x: (-alloc[x], x)):
            if alloc[k] > 0:
                alloc[k] -= 1
                break
    return alloc


#: Fields the subsample must cover at least once each. The reliability
#: estimate is only interpretable if every arm, every behaviour class and
#: every alert appears in it, otherwise a whole stratum has no reliability
#: evidence at all.
COVERAGE_FIELDS = ("arm", "scenario_class", "alert_id")


def coverage_report(
    records: Sequence[dict[str, Any]], picked: Sequence[int]
) -> dict[str, dict[str, Any]]:
    """Describe how completely a draw covers each field that must be covered.

    Args:
        records: The pooled artefact records.
        picked: Indices into `records` forming the draw.

    Returns:
        Field name to a dict of covered, total, and any missing values.
    """
    out: dict[str, dict[str, Any]] = {}
    chosen = set(picked)
    for field in COVERAGE_FIELDS:
        available = {str(r.get(field)) for r in records}
        seen = {str(records[i].get(field)) for i in chosen}
        missing = sorted(available - seen)
        out[field] = {
            "covered": len(available) - len(missing),
            "total": len(available),
            "missing": missing,
        }
    return out


def draw_subsample(
    records: Sequence[dict[str, Any]],
    order: Sequence[int],
    target: int,
    seed: int,
) -> list[int]:
    """Draw a stratified subsample of artefact positions for the second rater.

    The draw runs in three seeded phases so that coverage is guaranteed rather
    than hoped for:

    1. Alert coverage. One artefact is taken for each alert, choosing from the
       arm that is least represented so far, so all eighteen alerts appear and
       the arms stay balanced while doing it.
    2. Cell coverage. Any arm or behaviour class still absent gets one
       artefact, which only bites when the budget is smaller than the number
       of alerts.
    3. Proportional fill. Whatever budget is left is allocated across the
       joint arm by behaviour class strata using the largest remainder method,
       drawing only from artefacts not already picked.

    Args:
        records: The pooled artefact records in their original order.
        order: Indices into `records` giving the shuffled display order.
        target: How many artefacts to draw.
        seed: Random seed, offset from the shuffle seed so the draw is not a
            deterministic function of the display order.

    Returns:
        Indices into `records`, shuffled, forming the subsample.
    """
    rng = random.Random(seed + 1)
    pool = list(order)
    if target <= 0 or not pool:
        return []
    target = min(target, len(pool))
    picked: list[int] = []
    taken: set[int] = set()

    # Phase 1, one artefact per alert, spreading the arms as it goes.
    by_alert: dict[str, list[int]] = {}
    for idx in pool:
        by_alert.setdefault(str(records[idx].get("alert_id")), []).append(idx)
    arm_used: dict[str, int] = {}
    for alert in sorted(by_alert):
        if len(picked) >= target:
            break
        candidates = list(by_alert[alert])
        rng.shuffle(candidates)
        candidates.sort(key=lambda i: arm_used.get(str(records[i].get("arm")), 0))
        choice = candidates[0]
        picked.append(choice)
        taken.add(choice)
        arm = str(records[choice].get("arm"))
        arm_used[arm] = arm_used.get(arm, 0) + 1

    # Phase 2, repair any arm or behaviour class the first phase missed.
    for field in ("arm", "scenario_class"):
        available = sorted({str(records[i].get(field)) for i in pool})
        for value in available:
            if len(picked) >= target:
                break
            if any(str(records[i].get(field)) == value for i in taken):
                continue
            options = [
                i for i in pool
                if i not in taken and str(records[i].get(field)) == value
            ]
            if not options:
                continue
            rng.shuffle(options)
            picked.append(options[0])
            taken.add(options[0])

    # Phase 3, proportional fill over the joint arm by class strata.
    remaining = target - len(picked)
    if remaining > 0:
        strata: dict[tuple[str, str], list[int]] = {}
        for idx in pool:
            if idx in taken:
                continue
            key = (str(records[idx].get("arm")), str(records[idx].get("scenario_class")))
            strata.setdefault(key, []).append(idx)
        sizes = {k: len(v) for k, v in strata.items()}
        alloc = largest_remainder(sizes, remaining)
        for key in sorted(strata):
            block = list(strata[key])
            rng.shuffle(block)
            for idx in block[: alloc.get(key, 0)]:
                picked.append(idx)
                taken.add(idx)

    rng.shuffle(picked)
    return picked


def write_subsample_manifest(
    records: Sequence[dict[str, Any]],
    picked: Sequence[int],
    full_position: dict[str, int],
    out_dir: Path,
    seed: int,
) -> Path:
    """Write the experimenter record of the reliability draw.

    Args:
        records: The pooled artefact records.
        picked: Indices into `records` forming the subsample.
        full_position: Map of artefact_id to display index in the full set.
        out_dir: The rating package directory.
        seed: The shuffle seed the draw was derived from.

    Returns:
        The path written.
    """
    path = out_dir / "subsample_manifest.csv"
    cols = (
        "subsample_index",
        "artefact_id",
        "full_set_display_index",
        "arm",
        "scenario_class",
        "alert_id",
        "rule_id",
        "stratum",
        "seed",
    )
    with path.open("w", encoding="utf-8", newline="") as fh:
        fh.write(
            "# RELIABILITY SUBSAMPLE DRAW. Experimenter only: this file names "
            "the arm. Do not send it to a rater.\n"
        )
        w = csv.DictWriter(fh, fieldnames=list(cols))
        w.writeheader()
        for n, idx in enumerate(picked, start=1):
            r = records[idx]
            aid = str(r.get("artefact_id"))
            w.writerow(
                {
                    "subsample_index": n,
                    "artefact_id": aid,
                    "full_set_display_index": full_position.get(aid, ""),
                    "arm": r.get("arm"),
                    "scenario_class": r.get("scenario_class"),
                    "alert_id": r.get("alert_id"),
                    "rule_id": r.get("rule_id"),
                    "stratum": f"{r.get('arm')}|{r.get('scenario_class')}",
                    "seed": seed,
                }
            )
    return path


def write_key(
    records: Sequence[dict[str, Any]],
    order: Sequence[int],
    out_dir: Path,
    truth: dict[str, bool],
) -> Path:
    """Write the unblinding key.

    Args:
        records: The pooled artefact records in their original order.
        order: Indices into `records` giving the shuffled display order.
        out_dir: The rating package directory.
        truth: Map of alert_id to is_true_positive, possibly empty.

    Returns:
        The path written.
    """
    path = out_dir / "key.csv"
    with path.open("w", encoding="utf-8", newline="") as fh:
        fh.write(
            "# UNBLINDING KEY. Experimenter only. Do not send this file to a "
            "rater.\n"
        )
        writer = csv.DictWriter(fh, fieldnames=KEY_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for display_index, idx in enumerate(order, start=1):
            r = records[idx]
            row = {c: r.get(c) for c in KEY_COLUMNS}
            row["display_index"] = display_index
            row["is_true_positive"] = truth.get(str(r.get("alert_id")), "")
            writer.writerow(row)
    return path


def write_rater_sheet(
    blinded: Sequence[dict[str, Any]],
    out_dir: Path,
    rater: str,
    suffix: str = "sheet",
) -> Path:
    """Write one empty rating sheet for one rater.

    Args:
        blinded: The shuffled, stripped artefacts.
        out_dir: The rating package directory.
        rater: Short rater name used in the filename and the `rater` column.
        suffix: File name suffix, "sheet" for the full set and
            "subsample_sheet" for the reliability subsample.

    Returns:
        The path written.
    """
    path = out_dir / f"rater_{rater}_{suffix}.csv"
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rubric.RATING_COLUMNS))
        writer.writeheader()
        for art in blinded:
            row = {c: "" for c in rubric.RATING_COLUMNS}
            row["artefact_id"] = art["artefact_id"]
            row["display_index"] = art["display_index"]
            row["rater"] = rater
            writer.writerow(row)
    return path


def write_codebook(out_dir: Path) -> Path:
    """Write the rubric codebook that ships with the rating package.

    Args:
        out_dir: The rating package directory.

    Returns:
        The path written.
    """
    path = out_dir / "codebook.md"
    lines = [
        "# Remediation rubric, ten codes",
        "",
        "Walk the tests in order. Assign the first code that fires, then stop.",
        "Assign F0 only after all nine failure tests have been checked.",
        "",
    ]
    for c in rubric.CODES:
        lines += [f"## {c.code} {c.label} (key {c.shortcut})", "", c.test, ""]
    lines += ["# Secondary annotations", ""]
    for title, items in (
        ("Severity if executed unreviewed", rubric.SEVERITY),
        ("Reversibility", rubric.REVERSIBILITY),
        ("Stated confidence of the rationale", rubric.CONFIDENCE),
        ("Rationale fidelity", rubric.RATIONALE_FIDELITY),
    ):
        lines.append(f"## {title}")
        lines.append("")
        for key, desc in items:
            lines.append(f"- `{key}`: {desc}")
        lines.append("")
    lines += [
        "## Secondary codes",
        "",
        "Multi select. Record every other code whose test also fires, even "
        "though only the first is the primary code. Comma separated.",
        "",
        "## Flag for adjudication",
        "",
        "Tick when you are genuinely unsure, not merely when the artefact is "
        "poor. Flagged items go to the adjudication pass regardless of whether "
        "the two raters happened to agree.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def load_truth(alerts_path: Path | None) -> dict[str, bool]:
    """Load ground truth labels from the alert file, if one was supplied.

    Args:
        alerts_path: Path to the alert file, or None.

    Returns:
        A map of alert_id to is_true_positive. Empty when unavailable.
    """
    if alerts_path is None:
        return {}
    if not alerts_path.is_file():
        print(
            f"note: alert file {alerts_path} not found, "
            "key.csv will omit is_true_positive"
        )
        return {}
    try:
        raw = json.loads(alerts_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"note: cannot read {alerts_path} ({exc}), key.csv will omit truth")
        return {}
    alerts = raw.get("alerts", raw) if isinstance(raw, dict) else raw
    out: dict[str, bool] = {}
    for a in alerts or []:
        if isinstance(a, dict) and "alert_id" in a and "is_true_positive" in a:
            out[str(a["alert_id"])] = bool(a["is_true_positive"])
    return out


def run(args: argparse.Namespace) -> int:
    """Build the rating package.

    Args:
        args: Parsed command line arguments.

    Returns:
        A process exit code.
    """
    paths = [Path(p) for p in args.artefacts]
    records = read_artefacts(paths)

    # A response cut off at the token ceiling is a harness measurement error.
    # Showing it to a rater would collect a judgement about our own truncation
    # and score it against the model, so those artefacts are withheld.
    truncated = [r for r in records if r.get("truncated")]
    if truncated:
        records = [r for r in records if not r.get("truncated")]
        print(
            f"withheld {len(truncated)} truncated artefact(s) from the rating "
            f"set. These were cut off at the token ceiling by the harness, "
            f"not by the model, so they are not ratable. Re run the affected "
            f"arm with a higher --max-tokens."
        )
        for r in truncated[:10]:
            print(
                f"  withheld {r.get('artefact_id')} "
                f"arm={r.get('arm')} alert={r.get('alert_id')} "
                f"max_tokens={r.get('max_tokens')}"
            )

    if not records:
        print(
            "error: no ratable artefacts remain. Every artefact was truncated "
            "by the token ceiling. Re run generation with a higher "
            "--max-tokens.",
            file=sys.stderr,
        )
        return 2

    dupes = check_duplicates(records)
    if dupes:
        print(
            f"warning: {len(dupes)} duplicate artefact_id values in the pool, "
            f"first few: {dupes[:5]}"
        )

    order = list(range(len(records)))
    rng = random.Random(args.seed)
    rng.shuffle(order)

    blinded = [blind_record(records[i], n) for n, i in enumerate(order, start=1)]

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    truth = load_truth(Path(args.alerts) if args.alerts else None)

    blind_path = write_blind_json(blinded, out_dir, args.seed)
    key_path = write_key(records, order, out_dir, truth)
    codebook_path = write_codebook(out_dir)

    here = Path(__file__).resolve().parent
    template = Path(args.rate_html) if args.rate_html else here / "rate.html"
    ref_path = Path(args.reference) if args.reference else out_dir / "reference.md"
    rate_path, card_inlined = build_rate_html(
        out_dir, template, ref_path if ref_path.is_file() else None
    )

    primary = args.raters[0]
    secondary = list(args.raters[1:])
    sheet_paths = [write_rater_sheet(blinded, out_dir, primary)]

    subsample_info: dict[str, Any] = {"enabled": False}
    if args.subsample > 0 and secondary:
        picked = draw_subsample(records, order, args.subsample, args.seed)
        full_position = {a["artefact_id"]: a["display_index"] for a in blinded}
        sub_blinded = []
        for n, idx in enumerate(picked, start=1):
            b = blind_record(records[idx], n)
            b["full_set_display_index"] = full_position.get(b["artefact_id"])
            sub_blinded.append(b)

        # Every subsample artefact must also be in the primary rater's set,
        # since kappa is computed on the overlap.
        full_ids = {a["artefact_id"] for a in blinded}
        stray = [b["artefact_id"] for b in sub_blinded if b["artefact_id"] not in full_ids]
        assert not stray, f"subsample escaped the full set: {stray}"

        sub_path = write_blind_json(
            sub_blinded, out_dir, args.seed, "rater2_subsample.json", "subsample"
        )
        sub_sheets = [
            write_rater_sheet(sub_blinded, out_dir, r, "subsample_sheet")
            for r in secondary
        ]
        sub_manifest = write_subsample_manifest(
            records, picked, full_position, out_dir, args.seed
        )
        strata_counts: dict[str, int] = {}
        for idx in picked:
            k = f"{records[idx].get('arm')}|{records[idx].get('scenario_class')}"
            strata_counts[k] = strata_counts.get(k, 0) + 1
        coverage = coverage_report(records, picked)
        for field, info in coverage.items():
            state = (
                "complete"
                if not info["missing"]
                else "INCOMPLETE, missing " + ", ".join(info["missing"])
            )
            print(
                f"subsample coverage, {field}: {info['covered']}/{info['total']} "
                f"{state}"
            )
            if info["missing"]:
                print(
                    f"warning: the reliability subsample does not cover every "
                    f"{field}. Raise --subsample to at least {info['total']} "
                    "so every one appears at least once."
                )
        subsample_info = {
            "enabled": True,
            "requested": args.subsample,
            "drawn": len(picked),
            "stratified_by": ["arm", "scenario_class"],
            "coverage_guaranteed": list(COVERAGE_FIELDS),
            "coverage": coverage,
            "draw_seed": args.seed + 1,
            "strata_counts": strata_counts,
            "file": str(sub_path),
            "manifest": str(sub_manifest),
            "rationale": (
                "The second rater double codes a stratified subsample rather "
                "than the whole set. The draw is seeded, recorded here and in "
                "subsample_manifest.csv, and covers every arm, every behaviour "
                "class and every alert at least once. Cohen's kappa is "
                "computed on this overlap; Krippendorff's alpha uses the same "
                "artefacts but does not require the overlap to be complete. "
                "Outcome rates come from the primary rater's full set after "
                "adjudication of the overlap."
            ),
        }
        sheet_paths.extend(sub_sheets)
        sheet_paths.append(sub_path)
        sheet_paths.append(sub_manifest)
        if len(picked) < 30:
            print(
                f"warning: the reliability subsample has only {len(picked)} "
                "artefacts. Kappa on fewer than 30 pairs has a very wide "
                "interval and should be reported with that caveat."
            )
    elif args.subsample > 0 and not secondary:
        print(
            "note: --subsample was given but only one rater was named, so no "
            "reliability subsample was drawn"
        )
    else:
        for r in secondary:
            sheet_paths.append(write_rater_sheet(blinded, out_dir, r))

    by_arm: dict[str, int] = {}
    for r in records:
        by_arm[str(r.get("arm"))] = by_arm.get(str(r.get("arm")), 0) + 1

    manifest = {
        "package_version": "rating-package-v1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "shuffle_seed": args.seed,
        "artefact_count": len(records),
        "withheld_truncated": [
            {
                "artefact_id": r.get("artefact_id"),
                "arm": r.get("arm"),
                "alert_id": r.get("alert_id"),
                "max_tokens": r.get("max_tokens"),
                "finish_reason": r.get("finish_reason"),
            }
            for r in truncated
        ],
        "artefacts_per_arm": by_arm,
        "source_files": [str(p.resolve()) for p in paths],
        "raters": list(args.raters),
        "primary_rater": args.raters[0],
        "reliability_subsample": subsample_info,
        "stripped_fields": sorted(BLIND_STRIP_FIELDS),
        "duplicate_artefact_ids": dupes,
        "reference_card": {
            "inlined": card_inlined,
            "source": str(ref_path.resolve()) if ref_path.is_file() else None,
        },
        "blinding_limitation": (
            "The label is hidden but style is not. The baseline arm is a "
            "template playbook whose prose repeats across alerts, so a rater "
            "may come to recognise it. The two model arms also differ in "
            "house style: rationale structure, hedging habits and the shape "
            "of a malformed response (a fenced code block versus a prose "
            "preamble) can hint at the vendor, and a model may refer to "
            "itself in the rationale. Raters were told not to guess the "
            "source. Report this as a limitation."
        ),
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    print(f"read {len(records)} artefacts from {len(paths)} file(s)")
    for arm, n in sorted(by_arm.items()):
        print(f"  {arm}: {n}")
    print(f"shuffle seed: {args.seed}")
    print(f"wrote {blind_path}")
    print(f"wrote {key_path}  (unblinding key, do not share with raters)")
    if subsample_info.get("enabled"):
        print(
            f"reliability subsample: {subsample_info['drawn']} artefacts "
            f"double coded by {', '.join(secondary)}, stratified by arm and "
            "scenario class"
        )
        for k in sorted(subsample_info["strata_counts"]):
            print(f"  {k}: {subsample_info['strata_counts'][k]}")
    for p in sheet_paths:
        print(f"wrote {p}")
    print(f"wrote {codebook_path}")
    if card_inlined:
        print(f"wrote {rate_path}  (reference card inlined from {ref_path})")
    else:
        print(
            f"wrote {rate_path}  WARNING: no reference card was inlined, "
            f"looked for {ref_path}. Raters will have to judge whether a "
            f"command or column exists from memory, which is exactly what "
            f"the card exists to prevent."
        )
    print(f"wrote {out_dir / 'manifest.json'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the command line parser.

    Returns:
        The configured ArgumentParser.
    """
    p = argparse.ArgumentParser(
        prog="make_rating_sheet.py",
        description=(
            "Pool artefacts from every arm, shuffle with a recorded seed, "
            "strip arm revealing fields, and emit the blind rating package."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "example:\n"
            "  python3 make_rating_sheet.py --artefacts runs/*/artefacts.jsonl "
            "--raters r1 r2 --out rating\n"
        ),
    )
    p.add_argument(
        "--artefacts",
        nargs="+",
        required=True,
        help="one or more artefacts.jsonl files, usually one per arm",
    )
    p.add_argument("--out", default="rating", help="output directory (default rating)")
    p.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"shuffle seed, recorded in the manifest (default {DEFAULT_SEED})",
    )
    p.add_argument(
        "--raters",
        nargs="+",
        default=["r1", "r2"],
        help="short rater names, one empty sheet each (default r1 r2)",
    )
    p.add_argument(
        "--reference",
        default=None,
        help=(
            "Markdown reference card inlined into the delivered rate.html "
            "(default: <out>/reference.md)"
        ),
    )
    p.add_argument(
        "--rate-html",
        default=None,
        help="rate.html template to build from (default: alongside this script)",
    )
    p.add_argument(
        "--subsample",
        type=int,
        default=40,
        help=(
            "size of the stratified reliability subsample double coded by "
            "the second and later raters. The seeded draw covers every arm, "
            "every behaviour class and every alert at least once, then fills "
            "proportionally across the joint arm by class strata. 0 gives "
            "every rater the full set (default 40)"
        ),
    )
    p.add_argument(
        "--alerts",
        default=None,
        help="optional alert file, used only to add is_true_positive to key.csv",
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
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

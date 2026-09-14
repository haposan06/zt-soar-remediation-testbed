#!/usr/bin/env python3
"""Leak scanner for the blind rating package.

Reads rating/blind_artefacts.json (and optionally a delivery bundle
directory) and reports anything that would tell a rater which arm produced an
artefact. The script only ever opens files for reading. It never edits,
rewrites or deletes anything: a model that names itself inside its rationale
is a blinding limitation to report in the thesis, not something to redact.

Two kinds of finding are distinguished.

STRUCTURAL (exit status 1)
    A forbidden key is present anywhere in a record (top level or nested),
    the record count is not the expected number, display_index is not
    1..n contiguous, the file is not a rating package, or, when a bundle
    directory is given, it contains an experimenter-only file or a
    rater_*_ratings.csv with data rows.

TEXTUAL (reported, exit status 0)
    A vendor or model token appears in a string value: rationale, script,
    rollback, raw response text, alert fields, or a bundle document. These
    are listed with display_index, field path and a snippet so they can be
    counted and disclosed as a limitation.

Usage
    python3 check_blind.py rating/blind_artefacts.json
    python3 check_blind.py rating/blind_artefacts.json --bundle-dir rating/for-r2
    python3 check_blind.py rating/blind_artefacts.json --expect-count 126
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

#: Keys that must not appear in any blinded record, at any depth.
FORBIDDEN_KEYS = frozenset(
    {
        "arm",
        "model_id",
        "model_version",
        "endpoint",
        "sample_index",
        "temperature",
        "top_p",
        "max_tokens",
        "thinking_budget",
        "reasoning_mode",
        "reasoning_detail",
        "latency_ms",
        "scenario_class",
        "is_true_positive",
        "finish_reason",
        "truncated",
        "prompt_version",
        "prompt_fingerprint",
        "harness_version",
    }
)

#: Case-insensitive tokens scanned for in every string value. Each is matched
#: with a non-alphanumeric character (or start of string) immediately before
#: it, so "corpus" does not hit "opus" but "gpt-4", "googleapis" and
#: "claude-opus" all hit.
TEXT_TOKENS = (
    "gemini",
    "claude",
    "anthropic",
    "opus",
    "google",
    "vertex",
    "llama",
    "ollama",
    "openai",
    "gpt",
    "as an ai",
    "language model",
)

#: Files that must never be in a rater's bundle.
FORBIDDEN_BUNDLE_FILES = frozenset(
    {
        "key.csv",
        "subsample_manifest.csv",
        "manifest.json",
    }
)

#: Text-like bundle files worth scanning for tokens.
BUNDLE_TEXT_SUFFIXES = {".md", ".html", ".csv", ".json", ".txt"}

_TOKEN_RE = re.compile(
    "|".join(rf"(?<![a-z0-9]){re.escape(t)}" for t in TEXT_TOKENS),
    re.IGNORECASE,
)


def walk(obj: Any, path: str = "") -> Iterator[tuple[str, str, Any]]:
    """Yield (path, key, value) for every key and leaf in a nested object.

    Args:
        obj: A parsed JSON value.
        path: Dotted path to `obj`, empty at the root.

    Yields:
        Tuples of dotted path, the last key on the path (empty for list
        elements and the root), and the value at that path.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            yield p, str(k), v
            yield from walk(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = f"{path}[{i}]"
            yield p, "", v
            yield from walk(v, p)


def snippet(text: str, start: int, end: int, width: int = 40) -> str:
    """Return a one-line excerpt around a match.

    Args:
        text: The full string.
        start: Match start offset.
        end: Match end offset.
        width: Characters of context on each side.

    Returns:
        A single-line excerpt with the match marked by [[ ]].
    """
    lo = max(0, start - width)
    hi = min(len(text), end + width)
    frag = text[lo:start] + "[[" + text[start:end] + "]]" + text[end:hi]
    frag = re.sub(r"\s+", " ", frag)
    return ("..." if lo > 0 else "") + frag + ("..." if hi < len(text) else "")


def scan_text(text: str) -> list[tuple[str, str]]:
    """Find every token hit in a string.

    Args:
        text: The string to scan.

    Returns:
        A list of (token, snippet) pairs, one per hit.
    """
    hits = []
    for m in _TOKEN_RE.finditer(text):
        hits.append((m.group(0).lower(), snippet(text, m.start(), m.end())))
    return hits


def check_package(path: Path, expect_count: int) -> tuple[list[str], list[dict[str, Any]]]:
    """Check one blind_artefacts.json.

    Args:
        path: Path to the package file.
        expect_count: Expected number of artefacts, 0 to skip the check.

    Returns:
        A tuple of structural problems and textual hits.
    """
    structural: list[str] = []
    textual: list[dict[str, Any]] = []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read {path}: {exc}"], []

    if isinstance(data, list):
        records = data
        envelope: dict[str, Any] = {}
    elif isinstance(data, dict) and isinstance(data.get("artefacts"), list):
        records = data["artefacts"]
        envelope = {k: v for k, v in data.items() if k != "artefacts"}
    else:
        return [f"{path} is not a rating package (no 'artefacts' list)"], []

    # The envelope itself must not carry arm information either.
    for p, k, _ in walk(envelope):
        if k in FORBIDDEN_KEYS:
            structural.append(f"forbidden key in package envelope: {p}")

    declared = envelope.get("artefact_count")
    if declared is not None and declared != len(records):
        structural.append(
            f"envelope says artefact_count={declared} but {len(records)} records present"
        )
    if expect_count and len(records) != expect_count:
        structural.append(f"expected {expect_count} records, found {len(records)}")

    seen_idx: list[int] = []
    seen_ids: set[str] = set()
    for n, rec in enumerate(records, start=1):
        if not isinstance(rec, dict):
            structural.append(f"record #{n} is not an object")
            continue
        di = rec.get("display_index")
        aid = rec.get("artefact_id")
        if not isinstance(di, int):
            structural.append(f"record #{n} ({aid}) has no integer display_index")
        else:
            seen_idx.append(di)
        if aid in seen_ids:
            structural.append(f"duplicate artefact_id {aid}")
        seen_ids.add(str(aid))

        for p, k, v in walk(rec):
            if k in FORBIDDEN_KEYS:
                structural.append(
                    f"forbidden key '{k}' at display_index={di} path={p}"
                )
            if isinstance(v, str) and v:
                for token, frag in scan_text(v):
                    textual.append(
                        {
                            "display_index": di,
                            "artefact_id": aid,
                            "field": p,
                            "token": token,
                            "snippet": frag,
                        }
                    )

    if seen_idx:
        expected = list(range(1, len(records) + 1))
        if sorted(seen_idx) != expected:
            missing = sorted(set(expected) - set(seen_idx))
            extra = sorted(set(seen_idx) - set(expected))
            structural.append(
                "display_index is not 1..n contiguous"
                + (f", missing {missing[:10]}" if missing else "")
                + (f", unexpected {extra[:10]}" if extra else "")
            )
        elif seen_idx != expected:
            # Contiguous but stored out of order. Not a leak, but rate.html
            # shows records in file order, so it would break "one fixed order".
            structural.append("records are not stored in display_index order")

    return structural, textual


def check_bundle(bundle: Path) -> tuple[list[str], list[dict[str, Any]]]:
    """Check a delivery bundle directory.

    Args:
        bundle: Directory that will be zipped and sent to a rater.

    Returns:
        A tuple of structural problems and textual hits.
    """
    structural: list[str] = []
    textual: list[dict[str, Any]] = []
    if not bundle.is_dir():
        return [f"bundle directory not found: {bundle}"], []

    for f in sorted(p for p in bundle.rglob("*") if p.is_file()):
        name = f.name
        rel = str(f.relative_to(bundle))
        if name in FORBIDDEN_BUNDLE_FILES:
            structural.append(f"experimenter-only file in bundle: {rel}")
        if name.startswith("rater_") and name.endswith("_ratings.csv"):
            try:
                lines = [
                    ln for ln in f.read_text(encoding="utf-8").splitlines() if ln.strip()
                ]
            except OSError as exc:
                structural.append(f"cannot read {rel}: {exc}")
                continue
            if len(lines) > 1:
                structural.append(
                    f"{rel} has {len(lines) - 1} data row(s); only a header-only "
                    "template may ship"
                )
        if name.startswith("rater_") and "_sheet" in name and name.endswith(".csv"):
            # Pre-filled sheets carry artefact ids and a rater column but no
            # arm; harmless, but this round ships a header-only template.
            textual.append(
                {
                    "display_index": None,
                    "artefact_id": None,
                    "field": rel,
                    "token": "(pre-filled sheet present)",
                    "snippet": "not a leak, but not part of this round's bundle",
                }
            )
        if f.suffix.lower() in BUNDLE_TEXT_SUFFIXES and name != "blind_artefacts.json":
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                structural.append(f"cannot read {rel}: {exc}")
                continue
            for token, frag in scan_text(text):
                textual.append(
                    {
                        "display_index": None,
                        "artefact_id": None,
                        "field": rel,
                        "token": token,
                        "snippet": frag,
                    }
                )
    return structural, textual


def main(argv: list[str] | None = None) -> int:
    """Program entry point.

    Args:
        argv: Argument vector, defaults to sys.argv[1:].

    Returns:
        1 on a structural leak, 0 otherwise.
    """
    ap = argparse.ArgumentParser(
        prog="check_blind.py",
        description="Scan a blind rating package for arm-revealing keys and vendor tokens.",
    )
    ap.add_argument("package", help="path to blind_artefacts.json")
    ap.add_argument(
        "--bundle-dir",
        default=None,
        help="optional delivery bundle directory to check as well",
    )
    ap.add_argument(
        "--expect-count",
        type=int,
        default=126,
        help="expected number of records, 0 to skip (default 126)",
    )
    ap.add_argument(
        "--max-hits",
        type=int,
        default=200,
        help="maximum textual hits to print in full (default 200)",
    )
    args = ap.parse_args(argv)

    package = Path(args.package)
    structural, textual = check_package(package, args.expect_count)

    if args.bundle_dir:
        s2, t2 = check_bundle(Path(args.bundle_dir))
        structural += s2
        textual += t2

    print(f"check_blind: {package}")
    if textual:
        print(f"\nTEXTUAL HITS ({len(textual)}), report as a blinding limitation, do not edit:")
        for h in textual[: args.max_hits]:
            where = (
                f"display_index={h['display_index']} field={h['field']}"
                if h["display_index"] is not None
                else f"file={h['field']}"
            )
            print(f"  [{h['token']}] {where}")
            print(f"      {h['snippet']}")
        if len(textual) > args.max_hits:
            print(f"  ... {len(textual) - args.max_hits} more not shown")
        by_token: dict[str, int] = {}
        by_art: set[Any] = set()
        for h in textual:
            by_token[h["token"]] = by_token.get(h["token"], 0) + 1
            if h["display_index"] is not None:
                by_art.add(h["display_index"])
        print("  per token: " + ", ".join(f"{k}={v}" for k, v in sorted(by_token.items())))
        print(f"  artefacts affected: {len(by_art)}")
    else:
        print("\nTEXTUAL HITS: none")

    if structural:
        print(f"\nSTRUCTURAL LEAKS ({len(structural)}):")
        for s in structural:
            print(f"  {s}")
        print("\nRESULT: FAIL, do not send this package")
        return 1
    print("\nSTRUCTURAL LEAKS: none")
    print("RESULT: PASS (structure clean; review textual hits above, if any)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

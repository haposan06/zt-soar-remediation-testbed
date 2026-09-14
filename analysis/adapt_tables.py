#!/usr/bin/env python3
"""Adapt analyse.py --tables-dir output to the ACL two-column layout.

analyse.py emits `\\begin{table}[H]` floats sized for a one-column report. The
ACL thesis wants a `% !TEX root` header, full-width `table*[t]` floats for the
wide tables, a `table[t]` float with `\\footnotesize` for the narrow latency
table, and a shorter provenance note. This script applies exactly the
transformation that was applied by hand for the 2026-09-08 submission
(derived by diffing the generated files against thesis-acl/tables/), so the
thesis tables can be regenerated mechanically after every analysis run.

Usage:
    python3 adapt_tables.py <generated-tables-dir> <thesis-tables-dir>
"""
from __future__ import annotations

import sys
from pathlib import Path

WIDE = ("agreement", "code_distribution", "corpus", "precision", "rollup", "severity")
NARROW = ("latency",)

LONG_NOTE = (
    "The primary rater's codes over the full corpus. No adjudication pass was "
    "run, so no code was revised after the two raters compared sheets; "
    "reliability is established by the independent double coding reported in "
    "the agreement table."
)
SHORT_NOTE = "Primary rater's codes over the full corpus, pre-adjudication."


def adapt(name: str, text: str) -> str:
    if not text.startswith("% !TEX root"):
        text = "% !TEX root = ../main.tex\n" + text
    text = text.replace(LONG_NOTE, SHORT_NOTE)
    if name in WIDE:
        text = text.replace("\\begin{table}[H]", "\\begin{table*}[t]", 1)
        text = text.replace("\\end{table}", "\\end{table*}")
    elif name in NARROW:
        text = text.replace("\\begin{table}[H]", "\\begin{table}[t]", 1)
        text = text.replace("\n\\small\n", "\n\\footnotesize\n", 1)
    else:
        raise SystemExit(f"unknown table {name}; add it to WIDE or NARROW")
    return text


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 64
    src, dst = Path(argv[1]), Path(argv[2])
    dst.mkdir(parents=True, exist_ok=True)
    for name in WIDE + NARROW:
        path = src / f"{name}.tex"
        if not path.is_file():
            print(f"missing: {path}")
            return 1
        out = adapt(name, path.read_text(encoding="utf-8"))
        (dst / f"{name}.tex").write_text(out, encoding="utf-8")
        print(f"adapted {name}.tex -> {dst / (name + '.tex')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

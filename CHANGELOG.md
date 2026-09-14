# Changelog

## v1.0.0 (2026-09-14)

Initial public release accompanying the paper "Enhancing Cloud-Native SOAR
with Generative AI" (Napitupulu and Aminanto, 2026, under review).

- `testbed/`: Teleport 17 + PostgreSQL 16 compose stack, provisioning and
  teardown scripts, 14-day corpus generator, audit collector, eleven YARA-L
  2.0 rules with their Python evaluator, and the runbook.
- `data/`: the synthetic corpus (raw Teleport audit log, ground truth, joined
  events, session map, summary, change windows, detection hit rate) and the
  18 alerts used for generation.
- `harness/`: generation harness v1.1.0 (`generate-v1.1.0`, prompt
  `soar-remediation-v1.1.0`), rubric, blind package builder, rater UI and
  rating kit.
- `runs/`: all final and smoke runs of 12 September 2026 (Gemini 3.1 Pro,
  Claude Opus 4.6, template baseline; 126 rated artefacts).
- `rating/`: the delivered blind package, the unblinding key, both returned
  rating sheets and the 13 September correction package.
- `analysis/`: statistics, figures, LaTeX tables and the facts extractor,
  with the outputs used in the paper.
- `paper-appendices/`: the five paper appendices as LaTeX.

Release preparation: cloud project identifiers replaced by
`<redacted-project>`, local paths replaced by `<repo>` or made relative,
private keys, identity files, session recordings and the raters' original
sheets (which carried names) excluded. `generate.py` now reads the project id
from `GOOGLE_CLOUD_PROJECT` and the dotenv path from `SOAR_LAB_ENV_FILE`;
everything else is byte-identical to the code that produced the artefacts.

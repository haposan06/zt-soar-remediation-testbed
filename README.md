# Zero-Trust SOAR Remediation Testbed

Experiment testbed, synthetic audit corpus, generation harness, model
artefacts, blind human ratings and analysis code for a study of generative-AI
remediation in a cloud-native SOAR setting. A local zero-trust database-access
plane (Teleport 17 in front of PostgreSQL 16) produces genuine Teleport audit
logs from scripted benign and malicious sessions; eleven detection rules turn
those logs into 18 alerts; two frontier language models (Gemini 3.1 Pro and
Claude Opus 4.6, both through Vertex AI) and a deterministic template baseline
each write a remediation script for every alert; two raters code the resulting
126 artefacts blind against a fixed rubric; and the analysis scripts compute
precision, failure-code distributions, dangerous-action rates, latency and
inter-rater agreement from the returned sheets.

## Everything here is synthetic

Nothing in this repository describes a real person, vendor, transaction or
organisation. Every identity is a fabricated account under the reserved test
domain `@eproc.test`; every database row was produced by `generate_series`
and a small word list in `testbed/postgres/init.sql`; the "procurement"
schema, the attack sessions and the audit log all come from the local
container pair described in `testbed/RUNBOOK.md`. The two raters are
anonymised as `r1` (first author) and `r2` (independent expert). Cloud
project identifiers and local filesystem paths were removed from the copies
shipped here (`<redacted-project>`, `<repo>`).

## Layout

| Path | Contents |
|---|---|
| `testbed/` | `docker-compose.yml`, `teleport/teleport.yaml`, `postgres/` (schema, `pg_hba.conf`, entrypoint), `scripts/` (`setup.sh`, `corpus.py`, `collect_audit.py`, `detect.py`, `traffic.py`, `teardown.sh`), `rules/` (eleven YARA-L 2.0 rules, `history/` holds the earlier labelled revision), `RUNBOOK.md`. `certs/` and `identities/` are created at run time and are never committed. |
| `data/corpus/` | The 14-day corpus that produced the alerts: `teleport_audit_2026-09-06.log.gz` (raw Teleport JSON audit log, 49,109 events), `ground_truth.jsonl.gz`, `db_events.jsonl.gz`, `sessions.csv`, `summary.json`, `change_windows.json`, `detection_hitrate.csv`. |
| `data/alerts.json` | The 18 alerts (12 true positives, 6 benign-but-alerting controls) that are the only input to generation. Schema in `harness/alerts_schema.md`. |
| `harness/` | `generate.py` (arms `gemini`, `claude`, `baseline`, `ollama`), `prompts.py` (prompt `soar-remediation-v1.1.0`), `rubric.py`, `make_rating_sheet.py` (blind package builder), `check_runs.py`, `rate.html` (rater UI), `rating-kit/` (rater instructions, reference card, leak scanner, bundle builder). |
| `runs/` | Every generation run: `final-gemini*`, `final-claude*` (sharded, pooled at rating time), `final-baseline`, and the three `smoke-*` runs. Each holds `artefacts.jsonl`, one JSON file per artefact and (where written) `run_manifest.json`. |
| `rating/` | The blind rating package as delivered, the unblinding key, both returned rating sheets and the post-hoc correction package. See `rating/README.md`. |
| `analysis/` | `analyse.py` (statistics, figures, LaTeX tables), `extract_facts.py` (every number the paper quotes, as `facts.json`/`facts.md`), `adapt_tables.py`, plus the shipped `out/` and `tables/`. |
| `paper-appendices/` | The five paper appendices (scenario catalogue, prompts, rating instrument, detection rules, supplementary results) as LaTeX, with the two tables they `\input`. Figures referenced by appendix E are `analysis/out/fig_*.pdf`. |
| `run_generation.sh` | Driver: `smoke`, `full`, `claude-shards`, `rate`, `analyse`, `status`. |
| `requirements.txt` | Python dependencies (Python 3.12 was used). |

## Quick start: the testbed

Requirements: Docker with Compose v2, `tsh` (Teleport client, v17), Python 3
with `psycopg2` (`pip install psycopg2-binary`). Full detail, the safety
model, the data model and the verified results are in `testbed/RUNBOOK.md`.

```bash
cd testbed
./scripts/setup.sh                                            # bring up Teleport + PostgreSQL, provision users
python3 scripts/corpus.py --days 14 --benign-target 48000 --seed 42
python3 scripts/collect_audit.py                              # join the audit log to ground truth
python3 scripts/detect.py                                     # rules -> out/alerts.json + hit rate
./scripts/teardown.sh                                         # or --purge to delete volumes and the audit log
```

Every `tsh` call uses an identity file, `TELEPORT_HOME=testbed/tsh-home` and
an explicit `--proxy=localhost:3080`, so an operator's own `~/.tsh` profile is
never read or written. All ports bind to `127.0.0.1`.

## Regenerating the artefacts

The model arms need a Google Cloud project with the Vertex AI API enabled and
access to `gemini-3.1-pro-preview` and `claude-opus-4-6`, plus Application
Default Credentials:

```bash
python3 -m pip install -r requirements.txt
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=<your-project-id>   # or pass --project to generate.py
./run_generation.sh smoke                        # one alert per arm into runs/smoke-*
./run_generation.sh full                         # 54 + 54 + 18 artefacts into runs/final-*
./run_generation.sh rate                         # blind package into rating/
```

`generate.py` refuses to run a model arm without a project id, validates every
alert before contacting anything, and refuses alerts that name a non-loopback
database host. Credentials may also be placed in a dotenv file named by
`SOAR_LAB_ENV_FILE` (default `.env`); no secret is ever written into an
artefact. The baseline arm needs nothing beyond Python. `run_generation.sh
full` refuses to overwrite an existing run directory, so move `runs/final-*`
aside first if you want fresh artefacts.

## Running the analysis from the shipped sheets

No model access is needed to reproduce the reported statistics:

```bash
cd analysis && python3 analyse.py --rating-dir ../rating --runs ../runs/final-* --out out --seed 20260912
python3 extract_facts.py --rating-dir ../rating --analysis-out out --runs ../runs/final-* --out out/facts.json
```

Bootstrap confidence intervals use seed 20260912 (`analyse.py` defaults to 20260907,
so pass `--seed 20260912` to reproduce the shipped intervals). The shipped `analysis/out/`
and `analysis/tables/` are the outputs used in the paper.

## Citation

Software and data:

```bibtex
@software{napitupulu2026testbed,
  author  = {Napitupulu, Johannes Haposan and Aminanto, Muhamad Erza},
  title   = {Zero-Trust {SOAR} Remediation Testbed: synthetic {Teleport} database-access corpus, {LLM} remediation artefacts and blind ratings},
  year    = {2026},
  version = {1.0.0},
  url     = {https://github.com/haposan06/zt-soar-remediation-testbed}
}
```

Paper: Napitupulu, J.H., Aminanto, M.E. (2026). Enhancing Cloud-Native SOAR
with Generative AI ... (under review).

## Licences

Code (`testbed/`, `harness/`, `analysis/*.py`, `run_generation.sh`) is
released under the MIT License, see `LICENSE`. Data and study records
(`data/`, `runs/`, `rating/`, `analysis/out/`) are released under Creative
Commons Attribution 4.0 International, see `DATA_LICENSE`. The paper
appendices in `paper-appendices/` are provided as documentation of the study
and remain the authors' copyright.

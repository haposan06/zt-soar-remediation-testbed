# Remediation experiment harness

> **Release layout note.** In this public release `runs/`, `rating/` and `analysis/`
> sit at the repository root beside `harness/`, not inside it. Commands below
> that say `runs/...` or `rating/...` from `harness/` therefore mean `../runs/...`
> and `../rating/...`; `run_generation.sh` at the root already uses the right paths.

Runnable harness for the study comparing language model generated SOAR
remediation artefacts against a deterministic template playbook, judged by two
human raters against a ten code rubric.

Everything here targets `localhost`. Nothing in this directory connects to,
probes, or executes against a production host, and no generated script is ever
executed by the harness. Model output is text to be read by a rater.

## Contents

| File | Purpose |
| ---- | ------- |
| `alerts_schema.md` | The alert JSON contract that `generate.py` consumes. |
| `alerts.example.json` | Three fully worked alerts covering S1, S2 and B1. |
| `prompts.py` | Frozen system and user prompts shared by both model arms. |
| `rubric.py` | Single source of truth for the ten codes and the secondary annotations. |
| `generate.py` | Produces artefacts for one arm. |
| `make_rating_sheet.py` | Builds the blind rating package and the reliability subsample. |
| `rate.html` | Self contained rating tool for the human raters. |
| `../analysis/analyse.py` | Agreement, outcome rates, figures and LaTeX tables. |

## Design

18 alerts by two model arms by 3 samples gives 108 artefacts, plus 18 baseline
artefacts, 126 in total.

| Arm | What it is |
| --- | ---------- |
| `gemini` | `gemini-2.5-pro` through Vertex AI on the project named in `GOOGLE_CLOUD_PROJECT`, location `global`, using Application Default Credentials. |
| `ollama` | A local model through the Ollama HTTP API on `http://localhost:11434`, default `llama3:8b`. |
| `baseline` | A deterministic template playbook. Pure Python rule table, no model, no network. Deterministic, so it always produces exactly one artefact per alert. |

The two model arms receive byte identical prompts, so any difference is
attributable to the model rather than to prompt engineering.

## Step 0. Prerequisites, once

Python 3.12 with pandas, numpy, scipy, statsmodels, scikit-learn and
matplotlib. Verify and install what is missing.

```bash
python3 -c "import pandas, numpy, scipy, statsmodels, sklearn, matplotlib; print('core ok')"
pip install google-genai
```

For the `gemini` arm, Application Default Credentials must be present.

```bash
gcloud auth application-default login
python3 -c "import os; from google import genai; genai.Client(vertexai=True, project=os.environ['GOOGLE_CLOUD_PROJECT'], location='global'); print('vertex client ok')"
```

For the `ollama` arm, the server must be up with the model pulled.

```bash
ollama serve            # in its own terminal, if not already running
ollama pull llama3:8b   # about 4.7 GB, once
curl -s http://localhost:11434/api/tags | python3 -m json.tool
```

The `baseline` arm needs nothing beyond Python.

Secrets are read from the environment, falling back to the dotenv file named
by `SOAR_LAB_ENV_FILE` (default `.env` in the current directory). No secret is
ever printed or written into an artefact.

## Step 1. Check the alert file

`generate.py` validates every alert before it contacts anything, and refuses
to run if any alert names a database host that is not loopback. Confirm the
file is clean, and read the assembled prompt, before spending any tokens.

```bash
cd <repo>/harness

python3 generate.py --alerts alerts.json --arm gemini --dry-run
```

This prints the frozen system prompt, the rendered user prompt for the first
alert, the prompt version and fingerprint, and how many artefacts a real run
would write. It contacts no backend and writes nothing.

## Step 2. Generate the artefacts

Use one timestamped run directory per arm so a failed arm can be repeated
without disturbing the others.

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

# Baseline. Deterministic, so --samples is forced to 1. 18 artefacts.
python3 generate.py --alerts alerts.json --arm baseline \
    --out runs/$STAMP-baseline

# Gemini. 18 alerts by 3 samples = 54 artefacts, roughly 20 to 30 s each.
python3 generate.py --alerts alerts.json --arm gemini --samples 3 \
    --temperature 0.2 --top-p 0.95 --max-tokens 16384 --thinking-budget 2048 \
    --out runs/$STAMP-gemini

# Ollama. 54 artefacts, roughly 10 s each on this machine.
python3 generate.py --alerts alerts.json --arm ollama --model llama3:8b \
    --samples 3 --temperature 0.2 --top-p 0.95 --max-tokens 2048 \
    --out runs/$STAMP-ollama
```

Notes that matter.

* `--max-tokens` now defaults per arm: gemini 16384, ollama 8192, baseline
  8192. The gemini default is high because `gemini-2.5-pro` is a thinking
  model and cannot be told to stop thinking. At 8192 the response is cut off
  mid JSON; at 16384 it is not.
* A response the backend cut off at the token ceiling is **harness
  truncation**, not the model failing the output contract. Those artefacts are
  flagged `truncated: true` with `finish_reason: MAX_TOKENS`, their
  `parse_error` starts with `harness_truncation:`, they are **withheld from
  the rating package**, and they are excluded from the contract failure
  statistics. `generate.py` prints a warning telling you to re run the arm
  with a higher ceiling. Do not report results from a run that truncated.
* Every artefact records the token ceiling that was actually sent to the
  backend, reported by the arm itself rather than copied from the requested
  configuration.
* **Lenient JSON repair.** Responses are parsed strictly first. If strict
  parsing fails, a lenient retry runs that tolerates literal control
  characters inside strings, which is the defect models most often commit when
  they put a real newline in a script field. If the lenient parse succeeds the
  artefact carries `parse_repaired: true` and the verbatim strict failure in
  `strict_parse_error`, and it is rated normally. The rater is never told an
  artefact was repaired. The rationale is construct validity: the thesis
  measures whether the model authors safe and effective remediation, not
  whether it emits RFC 8259 conformant JSON, and letting a serialisation
  defect halve an arm's apparent compliance would confound transport hygiene
  with remediation quality. Nothing is laundered: `analyse.py` reports the
  contract failure rate after repair as the headline and a strict JSON
  conformance rate alongside it, so the reader sees exactly how often each arm
  needed repair.
* Every generation parameter is recorded on every artefact, along with the
  prompt version, a prompt fingerprint, the model version string the API
  returned, the request timestamp and the latency.
* Retries use exponential backoff on transport errors only. A response with bad
  content is never retried, because re running it would bias the sample.
* `--json-mode` is available but off by default, so the study measures whether
  a model follows the output contract rather than forcing it to.

Each run directory contains `artefacts.jsonl`, one JSON file per artefact under
`artefacts/`, and a `run_manifest.json` recording the whole configuration.

## Step 3. Build the blind rating package

```bash
python3 make_rating_sheet.py \
    --artefacts runs/$STAMP-gemini/artefacts.jsonl \
                runs/$STAMP-ollama/artefacts.jsonl \
                runs/$STAMP-baseline/artefacts.jsonl \
    --alerts alerts.json \
    --raters r1 r2 \
    --seed 20260907 \
    --subsample 40 \
    --out rating
```

This pools all 126 artefacts, shuffles them with the recorded seed so arm order
is not guessable, strips every field that names the arm, the model, the sample
index or the latency, and writes:

| File | Give to | Contents |
| ---- | ------- | -------- |
| `rating/blind_artefacts.json` | rater 1 | the full blinded set |
| `rating/rater_r1_sheet.csv` | rater 1 | empty sheet, one row per artefact |
| `rating/rater2_subsample.json` | rater 2 | the stratified reliability subsample |
| `rating/rater_r2_subsample_sheet.csv` | rater 2 | empty sheet for the subsample |
| `rating/codebook.md` | both raters | the rubric, in full |
| `rating/key.csv` | **nobody** | the unblinding key |
| `rating/subsample_manifest.csv` | **nobody** | the draw, it names the arm |
| `rating/manifest.json` | the method chapter | seed, counts, withheld artefacts, provenance |
| `rating/rate.html` | both raters | the rating tool, with the reference card built in |

The second rater double codes a stratified subsample rather than all 126
artefacts. The draw is seeded, recorded in `rating/manifest.json` and
`rating/subsample_manifest.csv`, and runs in three phases so coverage is
guaranteed rather than hoped for:

1. **Alert coverage.** One artefact per alert, taken from whichever arm is
   least represented so far, so all 18 alerts appear and the arms stay
   balanced while doing it.
2. **Cell coverage.** Any arm or behaviour class still absent gets one
   artefact. This only bites when the subsample is smaller than 18.
3. **Proportional fill.** The remaining budget is allocated across the joint
   arm by behaviour class strata with the largest remainder method.

The script prints the coverage it achieved for arm, behaviour class and alert,
and warns loudly if any value is missing. At `--subsample 40` all three are
complete. Both agreement statistics are computed on that overlap; every
precision figure comes from rater 1's full set.

`key.csv` and `subsample_manifest.csv` both carry a header comment saying they
are experimenter only. Do not send either to a rater.

## Step 4. Rate

`make_rating_sheet.py` writes `rating/rate.html`, which is the source
`rate.html` with `rating/reference.md` rendered to HTML and inlined at build
time. Send raters that built copy, not the source template. It is still one
self contained file with no network access and no fetch.

The reference card is what makes two of the ten codes decidable. F2 turns on
whether a command, flag, table or column actually exists, and without the card
a rater is guessing, so kappa would partly measure the raters' Teleport
knowledge rather than the instrument. The card is docked on the right, opens
and closes with the **Reference** button or the `G` key without losing rating
position or scroll, and is reachable on every artefact.

Send each rater their JSON file, their empty CSV (as a fallback if the tool
misbehaves), `codebook.md` and the built `rating/rate.html`. Then:

1. Open the `rate.html` from the rating package in a browser. No server, no
   network.
2. Type your initials in the Rater box.
3. Choose your JSON file. The header states which set is open and how many
   artefacts it holds.
4. Rate. Walk the ten tests in order and take the first that fires. Keyboard
   shortcuts: digits `1` to `9` and `0` for the codes, `Q W E R` for severity,
   `A S D` for reversibility, `Z X` for stated confidence, `C V B` for
   rationale fidelity, `F` to flag for adjudication, `N` to jump to the note,
   arrow keys to move, `G` for the reference card, `?` for the key list.
5. Press **Download my ratings CSV** at the end of every sitting.

Progress autosaves to browser localStorage, so closing the tab is safe. A few
browsers refuse localStorage on a `file://` URL. If the header says autosave is
off, serve the folder instead and reopen over http:

```bash
python3 -m http.server 8765 --directory rating
# then open http://localhost:8765/rate.html in the browser
```

Collect the two downloaded files as `rating/rater_r1_ratings.csv` and
`rating/rater_r2_ratings.csv`.

## Step 5. First analysis pass, agreement and disagreements

```bash
cd <repo>/analysis

python3 analyse.py --rating-dir ../rating --out out
```

This reports both agreement statistics on both rated scales, states the
overlap count explicitly and warns if it is under 30.

* **Cohen's kappa**, unweighted on the ten nominal codes and linearly weighted
  on the ordinal severity scale. This is the statistic named in the method
  chapter and the one that makes the result comparable with the published
  annotation literature. It is defined for exactly two raters and only on the
  artefacts both scored.
* **Krippendorff's alpha**, nominal metric for the code and ordinal metric for
  severity. Reported alongside kappa because kappa cannot describe a design
  with partial overlap: alpha admits any number of raters and absorbs the
  incomplete overlap by construction, with no imputation and no listwise
  deletion. It is implemented from the coincidence matrix definition with no
  third party dependency.

Both intervals are 95 per cent percentile bootstrap intervals resampling
artefacts, not asymptotic intervals, because the subsample is too small for the
normal approximation.

The hand rolled alpha is verified against three known answers before you trust
any of it:

```bash
python3 analyse.py --selfcheck
```

which asserts that perfect agreement returns exactly 1.0, that independent
random labelling returns approximately 0.0, and that on a complete two rater
nominal matrix with no missing data alpha and Cohen's kappa land within 0.02 of
each other. It exits non zero if any case fails.

It also writes `out/disagreements.csv`, listing every artefact the two raters
coded differently plus everything either rater flagged, and two views of where
they disagreed: `out/disagreement_pairs.csv`, the unordered code pairs by
frequency, and `out/disagreement_matrix.csv`, the directed confusion matrix
with rater 1 on the rows.

## Step 6. Adjudicate

Open `out/disagreements.csv`, fill in the `adjudicated_code` column, and
optionally `adjudicated_severity` and `adjudicator_note`. Save it as:

```bash
cp out/disagreements.csv ../rating/adjudicated.csv
# edit ../rating/adjudicated.csv, filling in adjudicated_code
```

Adjudication covers the overlap only. Artefacts rater 1 coded alone keep rater
1's code.

## Step 7. Final analysis, tables and figures

```bash
python3 analyse.py --rating-dir ../rating --out out
```

With `adjudicated.csv` present the outcome tables use the adjudicated code and
say so. Without it they fall back to rater 1 and are labelled provisional.

Adjudication also switches on the second agreement stage. `agreement.csv` and
`tables/agreement.tex` then carry both statistics twice, once pre-adjudication
and once post-adjudication. The two are reported side by side and never
averaged: pre-adjudication is the honest measure of how reliable the
instrument is in two independent pairs of hands, post-adjudication describes
the codes the headline results actually use and sits close to one by
construction.

Outputs in `analysis/out/`:

| File | Contents |
| ---- | -------- |
| `agreement.csv` | Cohen's kappa and Krippendorff's alpha, on both scales, at both stages, with bootstrap intervals |
| `disagreements.csv` | the adjudication worksheet |
| `disagreement_pairs.csv` | how often each unordered pair of codes was confused |
| `disagreement_matrix.csv` | directed confusion matrix, rater 1 on the rows |
| `per_arm_summary.csv` | precision, under-action, dangerous-action, model contract failure, strict JSON conformance and lenient repair rates, all with Wilson 95 percent intervals |
| `code_distribution.csv` | the full ten code distribution per arm |
| `scenario_breakdown.csv` | precision per arm within B1, S1, S2, S3 |
| `sood_rollup.csv` | roll-up to Sood's five categories |
| `arm_comparisons.csv` | pairwise Fisher exact tests, exploratory |
| `latency.csv` | latency per arm |
| `analysis_frame.csv` | the joined per artefact frame behind every table |
| `fig_*.pdf` | vector figures, one chart per figure |
| `tables.tex` | booktabs tables ready to include |

Definitions used.

* **Precision** is the proportion of artefacts coded `F0`, correct and safe.
* **Under-action rate** is `F5` plus `F8`.
* **Dangerous-action rate** is `F4` plus `F7`.
* **Model contract failure rate** is the proportion whose response could not be
  parsed even leniently. This is the headline serialisation number.
* **Agreement** is reported twice over, Cohen's kappa and Krippendorff's alpha,
  each pre-adjudication and post-adjudication. Neither statistic replaces the
  other and the four numbers are never collapsed into one.
* **Strict JSON conformance rate** is the proportion that parsed under strict
  JSON with no repair. Descriptive secondary statistic.
* **Lenient repair rate** is the proportion that needed the lenient retry.
* **Sood roll-up**: Factual `F1,F2`; Attributional `F3`; Logical `F4,F7`;
  Contextual `F5,F6`; Ambiguous `F8`. `F9` sits outside Sood's scheme and is
  reported separately.

The pairwise arm comparisons are exploratory. The study was not powered for
them and no multiplicity correction is applied. `analyse.py` prints that
caveat, and it is repeated in the table footnote.

## Step 8. Emit the thesis tables

`analyse.py` writes the finished floats straight into the thesis. Give it the
three run directories and the tables directory:

```bash
cd <repo>/analysis

python3 analyse.py \
    --rating-dir ../rating \
    --runs ../runs/final-baseline \
           ../runs/final-ollama \
           ../runs/final-gemini \
    --tables-dir ../../thesis/tables \
    --out out
```

It overwrites exactly seven files and refuses to write any other name:

| File | Needs |
| ---- | ----- |
| `corpus.tex` | the run directories only |
| `latency.tex` | the run directories only |
| `precision.tex` | ratings, plus a strict JSON conformance panel from the runs |
| `agreement.tex` | two rater sheets, plus `adjudicated.csv` for the second stage |
| `code_distribution.tex` | ratings |
| `severity.tex` | ratings |
| `rollup.tex` | ratings |

`detection_hitrate.tex` is hand written and is never touched. The allowlist is
enforced twice, once as a constant and once as a check before each write.

Run it before rating is finished and it still works: the two generation tables
are filled from the run directories and the five rating tables are written as
clearly marked placeholders, so the thesis keeps compiling. Re-run it after
rating and after adjudication to fill them in.

Each file is a complete float from `\begin{table}[H]` to `\end{table}`, with
`\label{tab:<filename>}`, booktabs rules only, and no package the preamble
does not already load. Include them with:

```latex
\input{tables/corpus}
\input{tables/agreement}
```

Table width is not left to chance. The floats set `\tabcolsep` to 4pt locally
and the font size is chosen per table by estimating the printed width and
picking the largest of `\small`, `\footnotesize` and `\scriptsize` that still
fits the 441pt text block this document actually has. The estimator is
calibrated against tabulars measured under the real preamble and errs high, so
it will pick a size too small before it lets an overfull box through. If even
`\scriptsize` will not fit it says so by name instead of failing silently.

The figures are separate and still come from `analysis/out/`:

```latex
\includegraphics[width=\linewidth]{../lab/analysis/out/fig_precision_by_arm.pdf}
```

Numbers in the tables are plain, so an `\sisetup` table format declared in the
preamble aligns them without any `siunitx` macro appearing inside a cell.

## Reproducibility record

Record these in the method chapter. All are emitted by the harness.

* `prompt_version` and the prompt fingerprint, from `run_manifest.json`.
* Model id and the `model_version` string the API returned, per artefact.
* Temperature, top_p, max tokens, thinking budget and JSON mode, per artefact.
* The shuffle seed and the subsample draw seed, from `rating/manifest.json`,
  together with the coverage the draw achieved over arm, behaviour class and
  alert.
* The bootstrap seed, `--seed` on `analyse.py`, default 20260907, and the
  number of resamples, `--bootstrap`, default 2000.

## Known limitations to declare

* Blinding hides the label, not the style. The baseline arm is a template
  playbook whose prose repeats across alerts, so a rater may come to recognise
  it. This is recorded in `rating/manifest.json`.
* Agreement is estimated on the reliability subsample, not on all 126
  artefacts, because the second rater has limited time. The interval is wider
  than a full double coding would give. Cohen's kappa additionally assumes the
  two raters scored the same artefacts, which is why Krippendorff's alpha is
  reported beside it; alpha is the statistic that is actually well defined for
  this design.
* Post-adjudication agreement is close to one by construction, because
  adjudication resolves the disagreements it is computed over. It describes
  the codes the headline results use and is not evidence that the instrument
  is reliable. The pre-adjudication figures are the ones to read for that.
* Latency is wall clock time for one request including retries, measured on one
  machine on one network. It is a rough operational indicator, not a benchmark.
* Artefacts withheld for harness truncation are listed in
  `rating/manifest.json` under `withheld_truncated`, and `analyse.py` prints
  the count. If that list is not empty, the affected arm should be regenerated
  with a higher `--max-tokens` before the results are reported.

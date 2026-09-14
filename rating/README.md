# rating/: the blind rating round of 12 September 2026

This directory is the rating package exactly as it was delivered to the two
raters, plus the experimenter-only files that were sealed until both sheets
came back, plus the sheets themselves. Raters are anonymised throughout:
`r1` is the first author, `r2` is an independent expert. No file here carries
a name.

## Files

| File | What it is |
|---|---|
| `blind_artefacts.json` | The 126 artefacts (54 Gemini, 54 Claude, 18 baseline) shuffled with seed 20260912 and stripped of every field that could reveal the arm (`arm`, `model_id`, `endpoint`, `latency_ms`, ... ; the full list is `stripped_fields` in `manifest.json`). Each item carries a `display_index` 1..126, the alert digest, the script, the rollback and the rationale. This is what both raters loaded into `rate.html`. |
| `codebook.md` | The rubric: failure codes F0..F9, severity S0..S3, rationale fidelity, reversibility and the confidence/flag columns. Generated from `harness/rubric.py`. |
| `rate.html` | The built rater UI (reference card inlined). Runs offline in a browser, stores progress in `localStorage`, exports `rater_<id>_ratings.csv`. `harness/rate.html` is the unbuilt template. |
| `HOW-TO-RATE-r1.md` | Instructions given to `r1`. `r2` received `harness/rating-kit/HOW-TO-RATE-r2.md`, `codebook.md`, `rate.html`, `blind_artefacts.json`, the reference card and a header-only sheet, and nothing else. |
| `manifest.json` | Package manifest: counts per arm, seed, source run files, the stripped-field list, the reliability-subsample draw and the recorded blinding limitation (style can hint at the arm even when the label is hidden). |
| `key.csv` | **Unblinding key.** Maps `display_index` to `artefact_id`, arm, model, alert, scenario class, `is_true_positive` and the generation parameters. Sealed until both rating sheets had been returned; only then read by `analysis/analyse.py`. |
| `subsample_manifest.csv` | The seeded (20260913) stratified 40-item draw for a second-rater reliability subsample: arm, scenario class and alert are all covered. Also sealed with the key. |
| `rater2_subsample.json`, `rater_r2_subsample_sheet.csv` | The 40-item package and blank sheet for that subsample. **Unused**: `r2` chose to rate the full set of 126, so agreement is computed on all 126 items. |
| `rater_r1_sheet.csv` | The pre-filled blank sheet (display index and alert id only) issued to `r1`. |
| `rater_r1_ratings.csv` | `r1`'s returned sheet, 126 rows. |
| `rater_r2_ratings.csv` | `r2`'s returned sheet, 126 rows, unchanged from what was received apart from the file name. |
| `correction-2026-09-13/blind_artefacts_correction.json` | A ready 18-artefact re-rating package. See below. |

## Sealing

`key.csv` and `subsample_manifest.csv` were written by
`harness/make_rating_sheet.py` at package-build time and not opened until both
`rater_*_ratings.csv` files were in place; `harness/rating-kit/README.md`
records the procedure and `harness/rating-kit/check_blind.py` is the leak
scanner that was run on the delivered bundle (structural leaks: none; textual
hits, i.e. a model naming a vendor inside its own rationale, are reported as a
limitation in the paper rather than redacted).

## The correction package (found after rating, not re-rated)

While writing up, a defect was found in the alert digest the raters saw:
`generate.py`'s `alert_summary()` omitted three fields that the model prompt
does carry, namely `detector` (the detector score), `principal.teleport_roles`
and `principal.department`. A rater comparing a script against the digest
could therefore see a model "invent" a detector score or a Teleport role that
the model had in fact been given. 18 Claude artefacts (15 benign-alert, 3
attack) were coded F2 by both raters solely on that ground. The authors
decided not to re-rate; the reported numbers are the original ratings, the
digest builder was fixed in `generate.py`, and the paper's limitations section
quantifies the ceiling effect (Claude at most 33/54 F0 after correction).
`correction-2026-09-13/blind_artefacts_correction.json` holds those 18
artefacts with the corrected digest, ready for re-rating should anyone wish to
do so; the `note` field inside it explains the same thing.

## Reproducing the statistics

```bash
cd ../analysis && python3 analyse.py --rating-dir ../rating --runs ../runs/final-* --out out --seed 20260912
```

# Rating instructions, primary rater (r1)

Read `HOW-TO-RATE-r2.md` first. It is the full guide and everything in it applies to you,
including the house rules and the order rule. Five things differ.

## 1. Your label and your files

| | Second rater | You |
|---|---|---|
| Label to type in the Rater box | `r2` | `r1` |
| File to load | `blind_artefacts.json` | `blind_artefacts.json` |
| Items | 126 | 126 |
| Rough time | 5 to 6 hours | 5 to 6 hours |

Both raters rate the same full set this round, in the same shuffled order. The 40-item
subsample that `make_rating_sheet.py` also writes (`rater2_subsample.json`,
`rater_r2_subsample_sheet.csv`) is **not used**. Do not load it, do not send it.

Open `rating/rate.html` (the built copy, which has the reference card inlined; the one next to
`make_rating_sheet.py` is the unbuilt template and shows a placeholder instead of the card).
The header must say **full set, 126 artefacts to rate**.

Your download will be named `rater_r1_ratings.csv`. Put it in `rating/`, next to
`blind_artefacts.json`. The analysis script finds completed sheets by the pattern
`rater_*_ratings.csv` in that directory, so the name matters and stray files in there matter
too. The second rater's returned file goes in the same place as `rater_r2_ratings.csv`.

If you rated the previous round in this browser, the tool will notice that the saved progress
belongs to a different package and ask whether to keep it. Choose **Cancel** to start fresh.
Progress is kept in the browser's `localStorage` (key `soar_ratings_v1`), so use the same
browser for every sitting and download the CSV at the end of each one.

## 2. Split it across sittings, and say so

126 items in one sitting produces a fatigue effect that the shuffle spreads across arms but
does not remove. Chapter 5 already declares an order effect as a threat. Three or four sittings
of about 40 items is better, and the tool remembers where you were. Note the sitting boundaries
(item numbers and dates) so they can be reported.

## 3. Do not open the key until both sheets are in

`key.csv` and `subsample_manifest.csv` are in `rating/` and they unblind everything.
Chapter 5 states, as a methodological claim, that neither was opened until both rating sheets
had been submitted. That sentence has to be true. Do not open either file, and do not run the
analysis script, until the second rater's `rater_r2_ratings.csv` is back and your own
`rater_r1_ratings.csv` is final.

`manifest.json` names the arms in aggregate (per-arm counts, source paths) but not per
artefact. You already know which arms were run, so reading it is not an unblinding event, but
there is no reason to open it before rating either.

For the same reason, do not discuss any individual artefact with the second rater before then.

## 4. No machine pre-rating exists for this round

The previous round had a language-model pre-rating (`_machine_rater_claude/`) that had to be
quarantined because it matched the analysis script's discovery pattern. Nothing of the kind
exists in this repository (checked: no `_machine_rater_*` directory). Do not create one
inside `rating/`. If an exploratory machine comparison is ever wanted, it goes in a directory
whose files do not match `rater_*_ratings.csv`, and it is labelled machine-generated, never as
a rater.

## 5. What to send the second rater

Run `bash rating-kit/build_r2_bundle.sh` from `harness/` after the rating package exists. It
writes `rating/for-r2/` and `rating/for-r2.zip`, holding exactly:

| File | Why |
|---|---|
| `rate.html` | built copy, reference card inlined |
| `blind_artefacts.json` | the 126 blinded items |
| `codebook.md` | the rubric |
| `reference.md` | the reference card as plain text |
| `HOW-TO-RATE-r2.md` | the guide |
| `rater_r2_ratings.csv` | header-only fallback sheet |

The script refuses to build if `key.csv`, `subsample_manifest.csv`, `manifest.json` or any
`rater_*_ratings.csv` with data rows would be included, and it runs `check_blind.py` on the
bundled JSON first. Send `rating/for-r2.zip` and nothing else.

Never send `key.csv`, `subsample_manifest.csv`, `manifest.json`, `rater2_subsample.json`,
`rater_r1_sheet.csv`, your own ratings, or anything under `runs/`. Do not tell the second rater
which models are involved, and do not correct them if they guess.

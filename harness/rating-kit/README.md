# rating-kit: blind rating round of 12 September 2026

> **Release layout note.** In this public release `runs/`, `rating/` and `analysis/`
> sit at the repository root beside `harness/`, not inside it. Commands below
> that say `runs/...` or `rating/...` from `harness/` therefore mean `../runs/...`
> and `../rating/...`; `run_generation.sh` at the root already uses the right paths.

Everything here is read-only tooling around `../rating/`. Nothing in this
directory modifies artefacts or the rating package.

| File | Purpose |
|---|---|
| `HOW-TO-RATE-r2.md` | Instructions for the second rater (external). Ships in the bundle. |
| `HOW-TO-RATE-r1.md` | Instructions for the primary rater (author). Stays here. |
| `check_blind.py` | Leak scanner for `blind_artefacts.json` and the bundle. |
| `build_r2_bundle.sh` | Builds `rating/for-r2/` and `rating/for-r2.zip`. |

Decisions for this round: both raters rate the full set of 126 from
`blind_artefacts.json`; the 40-item subsample is generated but unused; raters
are `r1` and `r2` (no names anywhere); returned files are
`rating/rater_r1_ratings.csv` and `rating/rater_r2_ratings.csv`; the rubric
(`rubric.py`, `codebook.md`) is unchanged from the previous round.

## Tonight, in order

All commands from `harness/` (this directory's parent).

```bash
cd <repo>/harness

# 0. Confirm generation is finished: expect final-gemini 54, final-claude 54,
#    final-baseline 18. If final-baseline is missing, `full` has not completed.
../run_generation.sh status

# 1. Build the rating package (make_rating_sheet.py --raters r1 r2 --seed 20260912 --subsample 40).
#    Writes rating/blind_artefacts.json, key.csv, manifest.json, codebook.md,
#    rate.html (built, card inlined), rater_r1_sheet.csv, and the unused
#    rater2_subsample.json, rater_r2_subsample_sheet.csv, subsample_manifest.csv.
#    Read its output: if it says it WITHHELD truncated artefacts, the set is
#    not 126 and step 2 will fail on the count. Re-run that arm with a higher
#    --max-tokens before continuing, or consciously accept the smaller set and
#    pass --expect-count N to the scanner and EXPECT_COUNT=N to the bundler.
../run_generation.sh rate

# 2. Scan for leaks. Non-zero exit = structural leak, stop and fix the harness.
#    Zero exit with TEXTUAL HITS = a model named a vendor or itself inside its
#    own text. Do not edit; note the artefact numbers for the limitations section.
python3 rating-kit/check_blind.py rating/blind_artefacts.json

# 3. Build the second rater's bundle. Refuses if any experimenter-only file
#    or a filled ratings sheet would be included; re-runs check_blind on the
#    staged copy; prints the listing and sizes.
bash rating-kit/build_r2_bundle.sh

# 4. Send rating/for-r2.zip together with the message below. Nothing else.
```

Do not open `rating/key.csv` or `rating/subsample_manifest.csv` until both
ratings sheets are in. Do not run `../run_generation.sh analyse` before then.

## Message to send with the zip

> Thanks for doing this. Unzip the folder, open `HOW-TO-RATE-r2.md` and follow
> it; it takes about five to six hours across a few sittings. Type `r2` in the
> Rater box, load `blind_artefacts.json` (126 items), and press "Download my
> ratings CSV" at the end of every sitting. Please send back the single file
> `rater_r2_ratings.csv` by Saturday 13 September, afternoon. Do not run any of
> the scripts, do not paste them into any AI assistant, and do not try to work
> out where each answer came from. If you cannot finish, send what you have,
> rated in order from item 1.

## Returns

1. Save the second rater's file, unchanged, as
   `rating/rater_r2_ratings.csv`. If the browser renamed it
   (`rater_r2_ratings (1).csv`), rename it back; do not edit the contents.
2. Save your own download as `rating/rater_r1_ratings.csv`.
3. Check both are present and full length (header plus 126 rows):

   ```bash
   wc -l rating/rater_r1_ratings.csv rating/rater_r2_ratings.csv
   ../run_generation.sh status
   ```

4. Only now: `../run_generation.sh analyse`. It discovers sheets by the glob
   `rater_*_ratings.csv` in `rating/`, so keep the header-only template in
   `rating/for-r2/` where it is (the glob is not recursive) and never copy it
   into `rating/` itself.

## Notes

- `rate.html` stores progress in the browser's `localStorage` under
  `soar_ratings_v1`, keyed by package (seed, set id, count). A browser that
  was used for the previous round will offer to keep the old progress; both
  guides tell the rater to choose Cancel.
- `reference.md` is not written into `rating/` by `make_rating_sheet.py`; the
  `rate` step inlines it from the path given by `--reference`. The bundler
  copies it from `rating/reference.md` if present, otherwise from the source
  path recorded in `manifest.json`, so the rater also gets the plain-text card.
- No `_machine_rater_*` directory exists in this repository. Keep it that
  way inside `rating/`.

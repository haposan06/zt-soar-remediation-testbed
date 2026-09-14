#!/usr/bin/env bash
# Build the second rater's delivery bundle from an existing rating package.
#
# Run AFTER make_rating_sheet.py has written rating/. Copies exactly these
# files into rating/for-r2/ and zips them to rating/for-r2.zip:
#
#   rate.html               the BUILT copy from rating/ (reference card inlined)
#   blind_artefacts.json    the full blinded set
#   codebook.md             the rubric
#   reference.md            if present in rating/, else copied from the path
#                           recorded in manifest.json (read only), else omitted
#   HOW-TO-RATE-r2.md       from rating-kit/
#   rater_r2_blank_template.csv  header-only template built from rubric.RATING_COLUMNS
#
# Aborts if key.csv, subsample_manifest.csv, manifest.json or any
# rater_*_ratings.csv with data rows would end up in the bundle, if the
# rate.html is the unbuilt template, or if check_blind.py reports a
# structural leak. Nothing outside rating/for-r2/ and rating/for-r2.zip is
# written.
#
# Usage:  bash rating-kit/build_r2_bundle.sh          (from harness/)
#         RATING_DIR=/some/other/rating bash rating-kit/build_r2_bundle.sh
set -euo pipefail

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="$(cd "$KIT/.." && pwd)"
RATING="${RATING_DIR:-$HARNESS/rating}"
PY="${PY:-python3}"
OUT="$RATING/for-r2"
ZIP="$RATING/for-r2.zip"
EXPECT_COUNT="${EXPECT_COUNT:-126}"

die() { echo "build_r2_bundle: ABORT: $*" >&2; exit 1; }

# ---------------------------------------------------------------- preflight
[[ -d "$RATING" ]] || die "rating directory not found: $RATING (run make_rating_sheet.py first)"
for f in rate.html blind_artefacts.json codebook.md; do
  [[ -f "$RATING/$f" ]] || die "missing $RATING/$f (run make_rating_sheet.py first)"
done
[[ -f "$KIT/HOW-TO-RATE-r2.md" ]] || die "missing $KIT/HOW-TO-RATE-r2.md"
[[ -f "$KIT/check_blind.py" ]] || die "missing $KIT/check_blind.py"
[[ -f "$HARNESS/rubric.py" ]] || die "missing $HARNESS/rubric.py"

# The delivered rate.html must be the built copy, not the source template.
if grep -q 'REFERENCE_CARD_PLACEHOLDER' "$RATING/rate.html"; then
  die "$RATING/rate.html still contains the reference card placeholder; it is the unbuilt template"
fi
if grep -q 'The reference card was not built into this copy' "$RATING/rate.html"; then
  die "$RATING/rate.html was built without a reference card (reference.md was missing at build time)"
fi

# Locate reference.md: prefer rating/, else the source path manifest.json records.
REF_SRC=""
if [[ -f "$RATING/reference.md" ]]; then
  REF_SRC="$RATING/reference.md"
elif [[ -f "$RATING/manifest.json" ]]; then
  REF_SRC="$("$PY" - "$RATING/manifest.json" <<'PYEOF'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
src = (m.get("reference_card") or {}).get("source") or ""
print(src)
PYEOF
)"
  [[ -n "$REF_SRC" && -f "$REF_SRC" ]] || REF_SRC=""
fi

# ---------------------------------------------------------------- stage
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/for-r2.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

cp "$RATING/rate.html"            "$STAGE/rate.html"
cp "$RATING/blind_artefacts.json" "$STAGE/blind_artefacts.json"
cp "$RATING/codebook.md"          "$STAGE/codebook.md"
cp "$KIT/HOW-TO-RATE-r2.md"       "$STAGE/HOW-TO-RATE-r2.md"
if [[ -n "$REF_SRC" ]]; then
  cp "$REF_SRC" "$STAGE/reference.md"
  echo "reference.md taken from $REF_SRC"
else
  echo "warning: no reference.md found; the card is still inlined in rate.html (press G)" >&2
fi

# Header-only sheet. make_rating_sheet.py never writes a file by this name
# (its sheets are pre-filled and named rater_<r>_sheet.csv), so build it here.
( cd "$HARNESS" && "$PY" - "$STAGE/rater_r2_blank_template.csv" <<'PYEOF'
import csv, sys
sys.path.insert(0, ".")
import rubric
with open(sys.argv[1], "w", encoding="utf-8", newline="") as fh:
    csv.writer(fh).writerow(list(rubric.RATING_COLUMNS))
PYEOF
)

# ---------------------------------------------------------------- guards
shopt -s nullglob dotglob
for f in "$STAGE"/*; do
  b="$(basename "$f")"
  case "$b" in
    key.csv|subsample_manifest.csv|manifest.json|subsample_manifest*|rater2_subsample.json|*_sheet.csv)
      die "forbidden file staged for the bundle: $b" ;;
    rater_*_ratings.csv)
      rows="$(grep -c . "$f" || true)"
      [[ "$rows" -le 1 ]] || die "$b has $((rows-1)) data row(s); only a header-only template may ship" ;;
    .DS_Store|._*) rm -f "$f" ;;
  esac
done
shopt -u nullglob dotglob

# Any stray forbidden file in rating/ itself is a reminder, not a blocker,
# because we only copy an explicit list; report it so it is not zipped by hand.
for f in key.csv subsample_manifest.csv manifest.json; do
  [[ -f "$RATING/$f" ]] && echo "note: $RATING/$f exists; it is NOT in the bundle and must never be sent"
done

echo
echo "running check_blind.py on the staged bundle"
"$PY" "$KIT/check_blind.py" "$STAGE/blind_artefacts.json" \
  --bundle-dir "$STAGE" --expect-count "$EXPECT_COUNT" \
  || die "check_blind.py reported a structural leak; bundle not built"

# ---------------------------------------------------------------- publish
rm -rf "$OUT" "$ZIP"
mkdir -p "$OUT"
cp "$STAGE"/* "$OUT"/
( cd "$RATING" && zip -q -X -r "for-r2.zip" "for-r2" -x '*.DS_Store' -x '__MACOSX/*' )

echo
echo "bundle directory: $OUT"
ls -l "$OUT"
echo
echo "zip: $ZIP"
ls -l "$ZIP"
unzip -l "$ZIP"
echo
echo "send $ZIP and nothing else."

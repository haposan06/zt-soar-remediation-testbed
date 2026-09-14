#!/usr/bin/env bash
# Re-runnable driver for the 2026-09-12 experiment (Gemini 3.1 Pro, Claude
# Opus 4.6, template baseline). Every step is idempotent or refuses to
# overwrite. Usage:  ./run_generation.sh smoke|full|claude-shards|rate|analyse|status
#
# Layout (repository root):  harness/ code, runs/ artefacts, rating/ blind
# package and returned sheets, analysis/ scripts and outputs, data/alerts.json.
# The model arms need GOOGLE_CLOUD_PROJECT (or --project) and Application
# Default Credentials with access to the two Vertex AI models; see README.md.
set -euo pipefail
PY="${PYTHON:-python3}"
LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
H="$LAB/harness"
RUNS="$LAB/runs"
RATING="$LAB/rating"
ALERTS="$LAB/data/alerts.json"
LOGS="$RUNS/logs"
GEMINI_MODEL=gemini-3.1-pro-preview
CLAUDE_MODEL=claude-opus-4-6
REASONING=high          # vendor default level on both models; see harness/README.md
SEED=20260912
mkdir -p "$LOGS"

gen() {  # gen <arm> <run-dir-relative-to-runs/> [extra generate.py args]
  local arm=$1 out=$2; shift 2
  if [[ -e "$RUNS/$out/artefacts.jsonl" ]]; then
    echo "refusing: runs/$out already holds artefacts (artefacts.jsonl is append-only). Move it aside first." >&2
    return 1
  fi
  ( cd "$H" && "$PY" generate.py --alerts "$ALERTS" --arm "$arm" --out "$RUNS/$out" "$@" )
}

case "${1:-}" in
  smoke)
    gen gemini   smoke-gemini   --model "$GEMINI_MODEL" --reasoning "$REASONING" --limit 1 --samples 1
    gen claude   smoke-claude   --model "$CLAUDE_MODEL" --reasoning "$REASONING" --limit 1 --samples 1
    gen baseline smoke-baseline --limit 1 --samples 1
    ;;
  claude-shards)
    # Claude Opus 4.6 with high-effort thinking averages about two minutes per
    # call, so the arm is sharded four ways by alert id. Shards are pooled by
    # `rate` and `analyse`, which glob runs/final-claude*. Used on 2026-09-12
    # after ALRT-0001 and ALRT-0002 had been generated sequentially into
    # runs/final-claude; edit the id lists if re-running from scratch.
    i=1
    for ids in ALRT-0003,ALRT-0004,ALRT-0005,ALRT-0006 ALRT-0007,ALRT-0008,ALRT-0009,ALRT-0010 \
               ALRT-0011,ALRT-0012,ALRT-0013,ALRT-0014 ALRT-0015,ALRT-0016,ALRT-0017,ALRT-0018; do
      gen claude "final-claude-s$i" --model "$CLAUDE_MODEL" --reasoning "$REASONING" --samples 3 --alert-ids "$ids" \
          > "$LOGS/final-claude-s$i.log" 2>&1 &
      i=$((i+1))
    done
    wait
    ;;
  full)
    echo "starting gemini and claude in parallel; logs in $LOGS/"
    gen gemini final-gemini --model "$GEMINI_MODEL" --reasoning "$REASONING" --samples 3 \
        > "$LOGS/final-gemini.log" 2>&1 & G=$!
    gen claude final-claude --model "$CLAUDE_MODEL" --reasoning "$REASONING" --samples 3 \
        > "$LOGS/final-claude.log" 2>&1 & C=$!
    rc=0
    wait $G || { echo "gemini run failed, see runs/logs/final-gemini.log" >&2; rc=1; }
    wait $C || { echo "claude run failed, see runs/logs/final-claude.log" >&2; rc=1; }
    gen baseline final-baseline > "$LOGS/final-baseline.log" 2>&1
    tail -n 3 "$LOGS"/final-*.log
    exit $rc
    ;;
  rate)
    ( cd "$H" && "$PY" make_rating_sheet.py \
        --artefacts $(ls "$RUNS"/final-gemini*/artefacts.jsonl) $(ls "$RUNS"/final-claude*/artefacts.jsonl) "$RUNS/final-baseline/artefacts.jsonl" \
        --raters r1 r2 --seed "$SEED" --subsample 40 --alerts "$ALERTS" \
        --reference rating-kit/reference.md \
        --out "$RATING" )
    ;;
  analyse)
    ( cd "$LAB/analysis" && "$PY" analyse.py --rating-dir ../rating \
        --runs $(ls -d ../runs/final-gemini*) $(ls -d ../runs/final-claude*) ../runs/final-baseline \
        --out out --seed "$SEED" "${@:2}" )
    ;;
  status)
    for d in "$RUNS"/final-*; do
      [[ -e "$d/artefacts.jsonl" ]] && printf '%-40s %4d artefacts\n' "$(basename "$d")" "$(wc -l < "$d/artefacts.jsonl")"
    done
    ls "$RATING" 2>/dev/null | grep -E '^rater_.*_ratings\.csv$' || echo "no rating sheets returned yet"
    ;;
  *) echo "usage: $0 smoke|full|claude-shards|rate|analyse|status" >&2; exit 64 ;;
esac

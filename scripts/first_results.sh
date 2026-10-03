#!/usr/bin/env bash
# First-results run: a fixed random sample of the 30-day dev slice through every pack, Flash first, then Clef.
# Cached, so it's safe to rerun; only missing answers are requested.
set -euo pipefail
cd "$(dirname "$0")/.."
SAMPLE=${SAMPLE:-300}
RUN=".venv/bin/python -m clefcve.run --slice dev --sample $SAMPLE --seed 1"
for model in ${MODELS:-clef-flash clef}; do
  $RUN --model "$model" --pack quality --include-rejected
  $RUN --model "$model" --pack cvss31
  $RUN --model "$model" --pack cvss40
  $RUN --model "$model" --pack cwe_verify
done

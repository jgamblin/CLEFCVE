#!/usr/bin/env bash
# The core tool on the whole corpus: the description pack (security impact + clarity) with Clef Flash.
# Random order, cached, and time-limited per chunk, so rerun until it reports 0 requests to send.
set -euo pipefail
cd "$(dirname "$0")/.."
.venv/bin/python -m clefcve.run --pack description --model "${MODEL:-clef-flash}" --slice all --include-rejected \
  --time-limit-min "${CHUNK_MIN:-110}"

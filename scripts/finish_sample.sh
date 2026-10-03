#!/usr/bin/env bash
# Second half of the first-results sample on Clef 27B, plus the revised Q1 questions for both models. Cached.
set -euo pipefail
cd "$(dirname "$0")/.."
RUN=".venv/bin/python -m clefcve.run --slice dev --sample 300 --seed 1"
$RUN --model clef-flash --pack quality --include-rejected
$RUN --model clef --pack quality --include-rejected
for p in cvss31 cvss40 cwe_verify; do $RUN --model clef --pack "$p"; done

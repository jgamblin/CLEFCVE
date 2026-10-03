#!/usr/bin/env bash
# Ask every pack about the hand-labeling (gold) sample, so labels can be compared with both models. Cached.
set -euo pipefail
cd "$(dirname "$0")/.."
IDS=$(.venv/bin/python -c "import csv;print(','.join(r['cve_id'] for r in csv.DictReader(open('gold/to_label.csv'))))")
for model in ${MODELS:-clef-flash clef}; do
  for p in quality cvss31 cvss40 cwe_verify; do
    .venv/bin/python -m clefcve.run --model "$model" --pack "$p" --ids "$IDS"
  done
done

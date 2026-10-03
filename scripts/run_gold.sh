#!/usr/bin/env bash
# Ask the quality pack (Q1, clarity) about the hand-labeled gold sample for both models. Cached.
# CVSS/CWE references come from the LLM jury on the main sample instead (clefcve.jury).
set -euo pipefail
cd "$(dirname "$0")/.."
IDS=$(.venv/bin/python -c "import csv;print(','.join(r['cve_id'] for r in csv.DictReader(open('gold/to_label.csv'))))")
for model in ${MODELS:-clef-flash clef}; do
  .venv/bin/python -m clefcve.run --model "$model" --pack quality --ids "$IDS"
done

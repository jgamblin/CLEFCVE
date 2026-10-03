#!/usr/bin/env bash
# LLM-jury reference labels for CVSS/CWE on the first N of the seed-1 dev sample. Cached; jurors run one at a time.
# Usage: JURORS="gpt-oss:20b granite4.2:30b" ./scripts/jury.sh
set -euo pipefail
cd "$(dirname "$0")/.."
for j in ${JURORS:-qwen3.6:35b nemotron-3.5-lightning:30b foundation-sec-8b-instruct:latest gpt-oss:20b granite4.2:30b}; do
  .venv/bin/python -m clefcve.jury --sample "${SAMPLE:-150}" --jurors "$j"
done

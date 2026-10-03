# CLEFCVE
Audit recently published CVE records with Cloudflare's Clef / Clef Flash decision models running locally in Ollama. See [PLAN.md](PLAN.md).

## Setup
```bash
python3 -m venv .venv
PIP_USER=0 .venv/bin/pip install --no-user -e '.[dev]'
```
Requires Ollama ≥ 0.35.1 with `clef` and `clef-flash` pulled, and a local clone of [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) (default `~/Data/cvelistV5`, override with `CLEFCVE_REPO`).

## Stage 1 — ingest
```bash
git -C ~/Data/cvelistV5 pull
.venv/bin/python -m clefcve.ingest --days 60 --dev-days 30
```
Writes `data/clefcve.duckdb` (override with `--db` or `CLEFCVE_DB`). Rebuilt from scratch on each run.

## Stage 2 — deterministic lint (no model)
```bash
.venv/bin/python -m clefcve.lint
```
Needs the CWE catalog in `data/ref/` (`curl -sSLO https://cwe.mitre.org/data/xml/cwec_latest.xml.zip && unzip` there). 23 checks mapped to CNA Operational Rules 4.1.0 → `lint` table.

## Stage 3+ — ask Clef
Question packs live in [`questions/`](questions/) (YAML; editing a question's wording re-asks only that question).
```bash
.venv/bin/python -m clefcve.run --pack quality --model clef --sample 300 --include-rejected
SAMPLE=300 ./scripts/first_results.sh          # every pack, Flash then Clef
.venv/bin/python -m clefcve.evaluate           # → data/reports/first_results.md
```
Answers are cached in `data/answers.duckdb`.

## Gold set
```bash
.venv/bin/python -m clefcve.gold export        # → gold/to_label.csv (150 rows)
.venv/bin/python -m clefcve.gold import gold/to_label.csv
```

## Report card
```bash
.venv/bin/python -m clefcve.jury --sample 150     # LLM-jury reference for CVSS/CWE (or ./scripts/jury.sh)
.venv/bin/python -m clefcve.report_card           # → reports/cna_report_card.html
```

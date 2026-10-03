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

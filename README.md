# CLEFCVE
Measures how CVE Numbering Authorities write their CVE records, using two things:

1. **Rule checks** (no model): 23 deterministic checks against the CVE Program's CNA Operational Rules 4.1.0,
   run on every record, each reported per CNA as the share of records that pass. There is no composite grade or score.
2. **Two questions for Cloudflare's Clef decision model**, run locally in Ollama on each description:
   - *Does the description establish a security impact?* (and how: stated outright, implied by a vuln class, or only describes a bug fix)
   - *How clear is it for a defender?* (0 Unusable to 4 Excellent)

Clef Flash (9B) runs the whole corpus; Clef 27B checks a sample. Other questions we tried (CVSS, CWE, "is this a
vulnerability", SSVC) are shelved in [`questions/experimental/`](questions/experimental/); see [PLAN.md](PLAN.md)
for what we learned.

## Setup
```bash
python3 -m venv .venv
PIP_USER=0 .venv/bin/pip install --no-user -e '.[dev]'
```
Requires Ollama ≥ 0.35.1 with `clef-flash` (and optionally `clef`) pulled, and a local clone of
[CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) (default `~/Data/cvelistV5`, override with `CLEFCVE_REPO`).
The rule checks need the CWE catalog in `data/ref/` (`curl -sSLO https://cwe.mitre.org/data/xml/cwec_latest.xml.zip && unzip` there).

## Run
```bash
git -C ~/Data/cvelistV5 pull
.venv/bin/python -m clefcve.ingest              # last 60 days -> data/clefcve.duckdb (~10 s)
.venv/bin/python -m clefcve.lint                # rule checks (~3 s)
./scripts/full_corpus.sh                        # Clef Flash on every description; rerun until 0 requests remain
.venv/bin/python -m clefcve.report_card         # -> reports/cna_report_card.html (per-CNA page)
.venv/bin/python -m clefcve.evaluate            # -> data/reports/results.md  (add --experimental for the shelved work)
```
Answers are cached in `data/answers.duckdb` by question wording, so reruns only ask what changed.

## Checking Clef
- `MODELS=clef ./scripts/run_gold.sh` and `python -m clefcve.run --pack description --model clef --sample 300`: Clef 27B spot checks.
- `python -m clefcve.labeler`: a local web app for hand-labeling the 150-CVE gold set (`gold/`) on the same two questions.

## Experimental (shelved)
```bash
.venv/bin/python -m clefcve.run --pack experimental/cvss31 --model clef --sample 300
.venv/bin/python -m clefcve.jury --sample 150   # 5-model LLM jury as a CVSS/CWE reference
.venv/bin/python -m clefcve.evaluate --experimental
```

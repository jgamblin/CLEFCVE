# CLEFCVE
Measures how CVE Numbering Authorities write their CVE records, using two things:

1. **Rule checks** (no model): 23 deterministic checks against the CVE Program's CNA Operational Rules 4.1.0,
   run on every record, each reported per CNA as the share of records that pass. There is no composite grade or score.
2. **Two questions for Cloudflare's Clef decision models**, run locally through Ollama's decision endpoint on every
   description:
   - *Does the description establish a security impact?* (and how: stated outright, implied by a vuln class, or only
     describes a bug or fix)
   - *How clear is it for a defender?* (0 Unusable to 4 Excellent)

The impact question runs as a cascade: Clef Flash (9B) reads every description, and Clef 27B re-reads every one Flash
marks "no impact" outside the Linux kernel CNA, plus a Linux control sample. 27B's answer wins where it exists.
Clarity uses Flash everywhere, so every CNA is scored by the same model. Checked against 150 hand-labeled CVEs in
[`gold/`](gold/), the impact answer agrees on 128 of 129 published records and Flash clarity is within one level on
124 of 129.

Results for the 60 days to 2026-10-03 (27,489 CVEs): the per-CNA page at
<https://jgamblin.github.io/CLEFCVE/reports/cna_records.html>, and [PLAN.md](PLAN.md) for the full history,
including the experiments that were shelved (CVSS, CWE, "is this a vulnerability", SSVC, an LLM jury) in
[`questions/experimental/`](questions/experimental/).

## Setup
```bash
python3 -m venv .venv
PIP_USER=0 .venv/bin/pip install --no-user -e '.[dev]'
```
Requires Ollama 0.35.1 or later with `clef-flash` and `clef` pulled, and a local clone of
[CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) (default `~/Data/cvelistV5`, override with
`CLEFCVE_REPO`). The rule checks need the CWE catalog in `data/ref/`
(`curl -sSLO https://cwe.mitre.org/data/xml/cwec_latest.xml.zip && unzip` there).

## Run
```bash
git -C ~/Data/cvelistV5 pull
.venv/bin/python -m clefcve.ingest              # last 60 days -> data/clefcve.duckdb (~10 s)
.venv/bin/python -m clefcve.lint                # rule checks (~3 s)
./scripts/full_corpus.sh                        # Clef Flash on every description; rerun until 0 requests remain
./scripts/confirm_flagged.sh                    # Clef 27B re-reads Flash's "no impact" calls; rerun until 0 remain
.venv/bin/python -m clefcve.cna_page            # -> reports/cna_records.html (per-CNA page)
.venv/bin/python -m clefcve.evaluate            # -> data/reports/results.md  (add --experimental for the shelved work)
```
Both scripts stop themselves after a time limit (`CHUNK_MIN`, default 110 minutes) and pick up where they left off,
because answers are cached in `data/answers.duckdb` by question wording. Run one copy at a time: Ollama answers
decision requests serially, so two copies only ask the same questions twice at half speed.

On an M5 Pro MacBook Pro with 64 GB, Flash takes a median of 0.84 s per description for the three questions (about
6.4 hours for 27,489), and Clef 27B about 2.0 s per re-read (about 1.4 hours for 2,520).

## Hand labels
```bash
.venv/bin/python -m clefcve.labeler             # local web app at http://127.0.0.1:8765
```
Labels the 150-CVE gold set in `gold/to_label.csv` (up to three per CNA, plus 21 rejected records) on the same two
questions, saving to `gold/labels.json`. `clefcve.evaluate` scores the models against those labels. All 150 are
labeled.

## Experimental (shelved)
```bash
.venv/bin/python -m clefcve.run --pack experimental/cvss31 --model clef --sample 300
.venv/bin/python -m clefcve.jury --sample 150   # 5-model LLM jury as a CVSS/CWE reference
.venv/bin/python -m clefcve.evaluate --experimental
```

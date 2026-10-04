# CLEFCVE — Plan

Use Cloudflare's **Clef** (27B) and **Clef Flash** (9B) decision models, running locally in Ollama, to audit recently published CVE records.

## Constraints that shape the design

Clef is a **decision model, not a chat model**. It scores typed questions against a `state` in one non-autoregressive pass. It doesn't write free text. It accepts three question types:

| Type | Returns | Use for |
|---|---|---|
| `choice` | chosen option + per-option probabilities + confidence | picking a category (2–26 options) |
| `noul` (yes/no) | P(true) | binary checks |
| `score` | probability-weighted level + confidence | ordinal ratings (2–26 levels) |

- Endpoint: `POST http://localhost:11434/v1/systemone`. Each request can carry 1–64 named questions. Context is 256K.
- **Each question can have at most 26 options.** We can't ask "which of the ~940 CWEs is this?" directly. CVSS and CWE have to be broken into smaller questions (details below).
- Clef returns probabilities, not just labels. That lets us set thresholds, measure calibration, and flag only the cases where the model is confident.
- Ollama on this machine is **0.35.0**. Clef needs **0.35.1+**, so upgrading is step one.
- These API details come from a summary of the docs. Stage 0 confirms the real request and response shapes before we build on them.

## Questions to answer

### Core (your list)
1. **Is this a vulnerability?**
2. **Is the description well written?**
3. **Is the CWE correct?**
4. **Is the CVSS correct?**
5. **Does the record follow the published rules?** (CVE Program CNA Operational Rules)

### Additional questions from the deep dive
6. **SSVC decision points**: Exploitation (none/PoC/active), Automatable (y/n), Technical Impact (partial/total). CISA's Vulnrichment ADP publishes these for many new CVEs, so we get a **free external ground truth**.
7. **Raw commit-message detection**: does the description state security impact, or is it just a fix log? This is mostly the Linux kernel CNA, which is a large share of volume.
8. **Low-effort or AI-generated report detection**: generic boilerplate, inflated impact, no concrete mechanism.
9. **Internal consistency**: do the product, versions and vuln type in the text match the structured `affected` block, the CWE and the CVSS vector?
10. **One vuln per CVE**: does the description bundle several independently fixable issues? (This is also a rules question.)
11. **Product / attack-surface category**: web app, WordPress plugin, OS/kernel, library, firmware/IoT, network device, AI/LLM app, mobile, ICS, and so on. This is mainly for slicing the results.
12. **Reference quality**: is there a patch, advisory or PoC? Is each reference relevant? We classify each reference from its URL and tags.
13. **Severity drift**: is the assigned severity inflated or deflated compared with the model's own estimate? This comes out of #4.
14. **Rollup**: a per-CNA page that combines all of the above. **This is probably the headline output.**

## Data

**Primary source: [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)**, the official CVE JSON 5.x records.
- **Local clone: `~/Data/cvelistV5`.** It is a full clone (not shallow) with git history, and holds about 397k records. Point the ingester at it with a config value or env var (default `~/Data/cvelistV5`). Run `git pull` on the clone before each ingest run, and record the commit SHA with each run so results are reproducible.
- **Select records by `cveMetadata.datePublished`, not by ID year or folder.** Many CVE-2025 IDs are published in 2026. Also keep `dateUpdated` and `state` (PUBLISHED or REJECTED).
- For the REJECTED-history recovery: run `git log` on the files that were rejected during the window and take the last PUBLISHED version of each.
- Includes the CNA container (description, CWE, CVSS, affected, references) **and the ADP containers**, including CISA Vulnrichment (SSVC, CVSS, CWE, KEV).
- Git history keeps earlier versions of each record. That lets us recover **the original text of CVEs that were later REJECTED**, which gives a natural set of negative examples for Q1.

**Optional second opinion: NVD API 2.0** (NVD's own CVSS and CWE). Filter by `pubStartDate`/`pubEndDate`. An API key is needed for reasonable rate limits.

**Window:** ingest the **last 60 days** and tag each record with a 30-day flag. Develop on the 30-day slice and run the full 60 days at the end. Expect roughly 4–5k CVEs for 30 days and 8–10k for 60, based on recent publishing rates.

**Reference data:** the CWE XML catalog (names, descriptions, hierarchy, and the **mapping-usage flag Allowed / Discouraged / Prohibited**), the CWE-1003 view, the CVSS 3.1 and 4.0 specs, the CNA Operational Rules, and the CISA KEV list.

## Stage 0 results (2026-10-03)

- Ollama 0.35.1 is installed, with `clef` (17 GB) and `clef-flash` (10 GB) pulled.
- The API shape is confirmed. `POST /v1/systemone` takes `{model, state, questions}`. `state` can be a string or a JSON object.
  - `noul` answers return `{"noul": p}`.
  - `choice` answers return `{choice, probabilities, confidence}`.
  - `score` answers return `{score, legend, probabilities, confidence}`.
  - `usage.output_tokens` is always 0, because the model scores answers without generating text.
- **Latency on this Mac (Clef 27B, 5 questions, ~640 input tokens):** about 7.8 s on a cold load and **about 1.9 s warm**. Clef Flash took about 2.7 s, including its own cold load.
- **Rough budget:** 10k CVEs × 1–2 requests × ~2 s ≈ **6–11 h for Clef on 60 days**. Plan to develop with Flash and do the full Clef run overnight. Still to measure: how latency grows with the number of questions per request.
- **Sanity check on CVE-2026-12037** (Wordfence, WordPress SSRF, admin-only): `is_vuln` = 0.93. AV:N, PR:H and UI:N all match the CNA's vector, each with confidence ≈ 0.87–0.90.
- `score` confidence is low (≈ 0.26–0.29) even when the levels look reasonable. Rely on the probability distribution or the expected score, not on `confidence`.

## Stage 1 results (2026-10-03)

`python -m clefcve.ingest` writes `data/clefcve.duckdb` in about 10 s. It reads the clone at commit `70f91a3c4fb4`, which is HEAD as of 2026-10-03 13:55 UTC.

- **Corpus: 27,489 PUBLISHED CVEs in 60 days (about 460/day) and 14,959 in the 30-day development slice.** This is about 3× my earlier estimate. A full scan of all 397k files matches the git-log shortcut exactly, with 0 missing and 0 extra.
- **Biggest CNAs:** Linux 13.7%, VulnCheck 10.5%, GitHub_M 10.3%, VulDB 5.8%, Oracle 5.5%, Microsoft 5.3%, WPScan, MITRE, Patchstack, Chrome, and so on.
- **Field coverage:**
  - 30% have **no CNA CWE** (8,389).
  - 8% have **no CVSS** (2,137).
  - **85% have CISA SSVC** (23,384). That's plenty of outside reference data for Q6.
  - Only 43 are in KEV.
- **REJECTED records: 101 had their earlier published text recovered from git history.** Another 528 were rejected without ever being published.
  - ⚠️ **Many were rejected as *duplicates*.** Those describe real vulnerabilities, so they are *not* negatives for Q1. The Q1 negative set has to filter on the rejection reason, keeping wording like "not valid", "not a vulnerability", "further research determined" or "issued in error". Expect only a few dozen real negatives, so the hand-labeled gold set matters more.
- **Revised runtime:** 27.5k CVEs × ~2 s ≈ **15 h for Clef on 60 days**. Plan to do model development with Clef Flash on the 30-day slice, or on a stratified sample. Do a full Clef run only for the final report, and consider sampling the high-volume CNAs (Linux, for example).

**Tables:** `cves` (one row per CVE, with the raw `record` JSON), `cwes`, `metrics` (CVSS by source and version), `ssvc`, `kev`, `refs`, `affected`, and `ingest_run`, which records the repo SHA, the window and stats. Each child table has a `source` column: `cna`, `CISA-ADP`, and so on.

## Stage 2 results (2026-10-03)

`python -m clefcve.lint` runs 23 checks on all 27,489 CVEs in about 3 s. The checks map to CNA Operational Rules **4.1.0** (`data/ref/CNA_Rules_v4.1.0.pdf`) and CWE **v4.20**.

**Bugs in my checks, caught and fixed before trusting the numbers:**
- **CVSS 4.0 vectors with threat metrics.** VulDB's vectors include `E:P`. The CVSS-B base score has to be computed from base metrics only; otherwise 1,390 records falsely "mismatch".
- **WPScan vendors.** WPScan sets vendor to `Unknown` but names the product. Rule 5.1.3 is about the product, so a missing vendor is now a separate SHOULD-level warning.
- **Mozilla affected status.** Mozilla omits `defaultStatus`. The CVE 5 schema treats that as "unknown", which satisfies 5.1.4.

**Headline findings:**
- **No vulnerability type, a MUST in 5.1.7, is 18.5% of records.** Linux (3,753 CVEs, 100%), Mozilla, HPE and MITRE (`n/a`) all omit problemTypes.
- **No structured CWE: 30.5%.**
- **Prohibited or Discouraged CWE: 15%,** mostly Discouraged entries like CWE-20, CWE-200 and CWE-284.
- **Identical description shared with other CVEs: 7.1%.** For example, 31 Adobe AEM XSS CVEs and 30 NVIDIA CVEs share one description each.
- **Stated CVSS score doesn't match the vector: 200 records.** Some CNAs put the temporal score in `baseScore`.

## Stage 3 notes

- **Packs:** `quality` (19 questions: Q1, Q2, judgment-based rules, product category, SSVC), `cvss31` (8), `cvss40` (11), `cwe_verify` (2 per assigned CWE). The CVSS and quality packs see **only the title and description**, never the assigned vector or CWE, so the answers are independent.
- **Cost is about 0.6 s per question on Clef 27B** once a request carries 8 or more questions (single-runner medians: 8 questions 4.9 s, 11 questions 6.5 s, 19 questions 11.4 s). A 2-question request still takes 2.0 s, so each request has a fixed overhead. Batching a few questions per request costs a little accuracy. **Parallel requests give no speedup**, because Ollama serializes them.
- **Clef 27B is clearly better than Flash at CVSS.** On a WordPress SSRF, Flash picked AV:L. On kernel bugs, Flash guessed PR:H.
- **Data files:** answers go in `data/answers.duckdb`, opened briefly for each write so the corpus DB stays readable. `clefcve.gold export` writes a 150-row stratified CSV for hand labeling: at most 3 CVEs per CNA, plus 21 rejected records.

## First results (2026-10-03)

**Sample:** 300 random CVEs from the 30-day slice plus 101 recovered REJECTED records.
- **Clef Flash** answered every pack on all 300.
- **Clef 27B** answered the quality pack on all 300 (plus rejected) and the CVSS/CWE packs on the first 150. Its run was cut off by the 2-hour background limit.

Full tables: `reports/2026-10-03-first-results.md`. Regenerate with `python -m clefcve.evaluate`.

| Question | Verdict | Evidence |
|---|---|---|
| **Q1 Is it a vulnerability?** | ⚠️ **Weak** | Can't tell invalid CVEs from valid ones by the text: rejected-as-invalid records score p = 0.93 vs 0.89 for published. It *does* flag Linux kernel fix logs with no stated impact; all 10 lowest-scoring CVEs are Linux. |
| **Q2 Description quality** | ✅ **Useful** | Detects commit-message-style descriptions perfectly (Linux 100%, everyone else 0%). The clarity ranking by CNA is believable: VulnCheck 3.4, GitHub/WPScan 3.3 … Patchstack 1.9, whose descriptions state impact only 13% of the time. Also caught Cisco marketing boilerplate. |
| **Q3 CWE correct?** | ✅ **Promising** | Clef 27B: 71% exact, 20% too general. Rates Discouraged CWEs "too general" 41% of the time vs 14% for Allowed ones. Its top rejections are real errors: "integer underflow" mapped to CWE-122, "OOB write" mapped to CWE-125 (read). The `cwe_acceptable` yes/no is too lenient; use `cwe_fit`. |
| **Q4 CVSS correct?** | ✅ **Useful as a reviewer** | Clef 27B matches the CNA's severity band 62% of the time (v3.1; Flash 45%). Mean score difference is 1.3, with errors split evenly up and down. Exploitability metrics agree 80–96%; impact metrics 58–74%. Its most confident disagreements include likely CNA errors, such as an IBM DoS scored C:H/A:N (C and A apparently swapped) and an NVIDIA local bug scored AV:P. |
| **Q5 Rules** | ✅ Mostly deterministic | See Stage 2. Judgment rules: about 6% of records bundle multiple vulnerabilities, about 1% credit people. |
| **SSVC vs CISA** | Mixed | Technical impact 84% vs a 60% baseline (real skill). Exploitation 86% vs 80%, Automatable 76% vs 75% (no skill from the text alone). |

**Model comparison.** The two models give the same answer 81–93% of the time. Clef 27B is about 3.5–4× slower: roughly 11.4 s per CVE for the quality pack and 4.9 s for CVSS v3.1 (single-runner medians). Flash is fine for description quality. Use Clef 27B for CVSS and CWE.

**Prompt tuning so far.** Early CVSS impact questions under-rated impact. Spelling out how a stated outcome maps to an impact level raised Flash's C agreement from 38% to 52% and removed the bias.

### Update (same day): Q1 rephrased, Clef 27B on all 300, LLM jury

- **Q1 is now "does the description establish a security impact?"** (`security_impact_stated` plus `impact_basis`). Clef 27B finds no stated impact in **95% of Linux kernel descriptions**, versus 0–12% for every other CNA with at least 5 CVEs in the sample.
- **Clef 27B on all 300:** matches the CNA's CVSS v3.1 severity band **65%** of the time (Flash 45%), with a mean score difference of 1.2.
- **Hand labels cover Q1 and clarity only.** The labeling app is `python -m clefcve.labeler`; labels go to `gold/labels.json`. Scoring CVSS and CWE by hand was too slow for a POC.
- **CVSS and CWE references come from an LLM jury.** Five local models score the first 150 sampled CVEs from the same text Clef sees: gpt-oss:20b, granite4.2:30b, nemotron-3.5-lightning:30b, foundation-sec-8b and qwen3.6:35b. Qwen 3.8 is excluded because Clef is built on it. The strict-majority vote per field is the reference.
  - **The jury often disagrees with itself on impact:** unanimous on Scope 22% of the time and on Availability 15%. Exploitability is far more stable (AC 99%, UI 79%).
  - **Clef vs CNA, judged by the jury:** Clef is closer or tied on **7 of 8 metrics** (AC 92% vs 85%, S 82% vs 75%, C 63% vs 59%, I 63% vs 59%); the CNA is ahead only on UI (93% vs 92%).
  - **Clef is about as good as one strong general model.** Its average agreement with the jury (about 76%) matches each juror's agreement with the other four (70–78%). Its advantages are probabilities you can threshold and guaranteed-valid outputs, not better judgment.
  - **The jury doesn't help with CWE.** Its preferred CWE equals the CNA's 95% of the time, so it can't confirm or refute Clef's harsher "too general" calls (21%).
  - **Caveat:** the jurors got the same impact-inference guidance as Clef's CVSS questions, so they may share some biases with Clef.

### Reshaped to two questions (2026-10-03)

The tool now does three things:
- **Rule checks:** one column per check, per CNA.
- **"Does the description establish a security impact?"** (plus `impact_basis`).
- **"How clear is the description?"**

These run with **Clef Flash over the whole corpus** (`scripts/full_corpus.sh`, random order, cached, in chunks under 2 hours). Clef 27B is the spot check. Flash agrees with 27B on 94% of security-impact answers (it's slightly stricter) and on 89% of clarity answers (within half a level).

The commit-message flag was dropped from the core: Flash flagged ordinary Apple and GitHub advisories as commit messages, and `impact_basis = bug_fix_only` already covers fix logs.

CVSS, CWE, SSVC, the jury and the other judgment questions moved to `questions/experimental/`. Run `evaluate --experimental` for them.

### Full-corpus results (2026-10-04)

All 27,489 published CVEs were run through the cascade with 0 errors. Clef Flash needs about 6.4 hours of compute (median 0.84 s per CVE, 14,870 single-runner requests), and Clef 27B about 1.4 hours to re-read the 2,520 records Flash flagged as stating no impact (2,187 outside the Linux kernel CNA plus 333 Linux records as a control), at a median of 2.0 s for the two impact questions (661 single-runner requests). The re-check run itself asked 2,440 CVEs from a 2,487-CVE list; the rest were already answered from earlier sample runs. Full tables: `reports/2026-10-04-full-corpus-results.md`.

- **16.9% of CVEs never establish a security impact.** **78.7% of those come from the Linux kernel CNA**, where 97.5% of descriptions state no impact. Every other CNA combined: 4.2%.
- **The cascade was necessary.** Clef 27B overturned **55%** of Flash's non-Linux "no impact" calls (1,198 of 2,187), mostly terse but complete advisories (Apple 79%, GitHub 83%, Chrome 100%). It overturned only 6% of a 333-CVE Linux control sample.
- **Highest no-impact rates outside Linux:** Tanium 93% ("Tanium addressed an improper access controls vulnerability in Comply."), Qualcomm 71%, Mozilla 58% ("Use-after-free in the DOM: Streams component."), VMware 29%, Drupal 28% ("Vulnerability in Drupal Screenshot. This issue affects Screenshot versions: \*.\*"), Cisco 21%.
- **Clarity (Flash, 0–4):** corpus average 2.7. 0.7% rate Poor or worse; 70% rate Good or better.
- **Throughput:** Flash takes 0.84 s per CVE for three questions (p90 0.98 s). The wall clock was longer, and the apparent 1.7 s was an artifact: from 2026-10-03 19:42, two Claude sessions were both chaining full-corpus and re-check chunks over the same queue in the same order. That asked 12,003 Flash and 2,438 Clef 27B CVEs twice, a few seconds apart, with identical answers. `evaluate` keeps one answer per question, so results are unaffected.
- **The headline uses the plain cascade answer, not a stricter variant.** A briefly committed variant (4d7c9e4, reverted) also required `impact_basis` to be bug-fix-only or similar, giving 15.4%. Against the 150 hand labels, the plain answer agrees on 128 of 129 published records and the stricter one on 124, so 16.9% stays. The per-CNA page and the blog draft both use the plain answer.
- **Hand labels (gold set, all 150 labeled 2026-10-04):** the cascade agrees on 128 of 129 published records (Flash alone 121; all 7 of its misses were too strict, and 27B fixed all 7). Flash clarity is within one level on 124 of 129 (96.1%), exact after rounding 72.1%, r = 0.71, about +0.28 generous.

### Next
1. Finish hand-labeling Q1 and clarity in the labeling app.
2. Full 60-day runs: Flash for the quality pack (Q1 and clarity, about 24 h); Clef 27B for CVSS and CWE only on CVEs that lint or Flash flags.
3. Per-CNA page (done: `reports/cna_records.html`, built by `clefcve.cna_page`). No letter grades or composite scores, by design: each rule check and each Clef answer is its own column.

## Architecture (lightweight)

```
ingest  →  normalize  →  lint (deterministic)  →  decide (Clef)  →  evaluate  →  report
cvelistV5   flat table     no model                question packs     gold set     CNA cards
NVD (opt)   SQLite/DuckDB  rules, CVSS math         per CVE            calibration  dashboard
```

- **Python** with `httpx` against `/v1/systemone`. Storage in **DuckDB or SQLite**.
- **Question registry in YAML.** Each question has an id, version, type, instructions, criteria, and a template for what goes into `state`. Prompt wording is the main lever we'll tune, so it should be versioned data, not code.
- **Cache key:** `(cve_id, record_hash, model, question_id, question_version)`. Reruns only redo what changed.
- **Batching:** put all questions for one CVE into as few requests as possible (up to 64 per request). One CVE costs about 1–3 requests.
- **Deterministic first:** anything code can check (schema, CVSS score vs vector, CWE mapping-usage, required fields) never goes to the model.

## Question design details

### Q1 — Is this a vulnerability?
- `noul`. True means an attacker can violate confidentiality, integrity or availability beyond their intended privileges. False means a functional bug, hardening, by-design behavior, or a case where the attacker already holds the privilege that grants the impact.
- `choice` for the reason: `real_vuln`, `functional_bug`, `hardening`, `by_design`, `requires_existing_privilege`, `insufficient_info`, `no_security_impact_stated`.
- **Validation:** recovered REJECTED records (negatives), records tagged `disputed`, and the hand-labeled gold set.

### Q2 — Description quality
Rather than asking "is it good?", break it into elements:
- A `noul` for each element: names the product, gives a version range, names the vuln type, states the attacker and precondition, states the impact, states the vector or component.
- `score` (5 levels) for overall clarity and actionability.
- `noul` for "is a raw commit message" and "is boilerplate / AI-generated filler".
- Combine these into a rubric score, modeled on the CVE "key details" template: *[vuln type] in [component] in [vendor product version] allows [attacker] to [impact] via [vector]*.

### Q3 — CWE correctness (works within the 26-option limit)
1. **Deterministic:** valid ID? Mapping usage Discouraged or Prohibited (for example, pillars and categories)? `NVD-CWE-Other` / `noinfo`?
2. **Verify** (main approach): put the description, the assigned CWE's name and its CWE definition into `state`. Ask a `choice`: `exact` / `too_general` (parent or pillar) / `too_specific` / `related_but_wrong` / `wrong`.
3. **Predict independently** (stretch): a two-step tournament. First ask a `choice` across ≤26 buckets built from CWE-1003 / Top 25 groupings. Then ask a `choice` among the ≤26 children of the winning bucket. Compare the result with the assigned CWE and the CISA ADP CWE.

### Q4 — CVSS correctness
- One `choice` question **per base metric**, all in one request:
  - CVSS 4.0: AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA (11 questions)
  - CVSS 3.1: AV, AC, PR, UI, S, C, I, A (8 questions)
- Each metric's criteria text comes straight from the spec definitions.
- Rebuild the vector and compute the score with a CVSS library. Diff each metric against the CNA, CISA ADP and NVD vectors.
- **Flag only confident disagreements**, for example when the model's probability for the assigned value is below 0.15.
- Results to report: disagreement rate per metric (PR, UI and Scope will likely lead), inflation and deflation by CNA, and the score delta distribution.

### Q5 — Published-rules compliance (hybrid)
- **Read the current CNA Operational Rules first.** Write one checklist row per rule, then mark each row *deterministic*, *model*, or *out of scope*.
- **Deterministic examples:** required fields present, at least one public reference, `affected` populated, an English description exists, the CVSS vector is valid and its score matches, the CWE is well formed.
- **Model examples:** describes exactly one independently fixable vuln (Q10), has enough detail to distinguish it from other CVEs, is not a placeholder, references are relevant (Q12).
- Output: a pass/fail/unknown per rule for each CVE.

## Evaluation (how we know Clef is right)

- **Gold set:** hand-label about 150–200 CVEs from the 30-day slice, stratified by CNA, vuln class and severity. Use a small labeling CSV or page.
- **Free labels:** REJECTED and disputed records (Q1), CISA ADP SSVC (Q6), and CISA ADP / NVD CVSS and CWE, used as a second opinion rather than truth (Q3, Q4).
- **Metrics:** accuracy and macro-F1 per question, calibration (reliability curves, since we get probabilities), and agreement with each external source.
- **Model comparison:**

  | Model | Notes |
  |---|---|
  | Clef (27B) | primary |
  | Clef Flash (9B) | speed vs quality trade-off |
  | `qwen3.8:27b` as a generative LLM judge | Clef's base model, already installed; tests whether the decision fine-tune actually helps |
  | `foundation-sec-8b-instruct` | already installed; a security-domain baseline |

- **Prompt ablations:** try 2–3 instruction wordings per question on the gold set and keep the best. Track the version in the YAML.

## Stages

| Stage | Deliverable | Done when |
|---|---|---|
| **0. Setup and smoke test** | Ollama upgraded to ≥0.35.1, `clef` and `clef-flash` pulled, one hand-made request per question type on 3 real CVEs | Real response shapes confirmed; latency measured on this Mac |
| **1. Corpus** | Ingest from cvelistV5 (60 days + 30-day flag + REJECTED history), normalize into one table, optional NVD pull, reference catalogs downloaded | Row counts match the expected volume; every CVE has description, CNA, CWE, CVSS sources and ADP fields |
| **2. Deterministic lint** | Rules checklist, CVSS math check, CWE mapping-usage check | First findings that need no model at all (useful baseline) |
| **3. Framework and gold set** | YAML question registry, batch runner with cache, about 150 labeled CVEs, eval harness | `run --questions q1 --slice gold` prints metrics |
| **4. Core questions** | Q1, Q2, Q4 (per-metric CVSS), Q3 verify | Each beats a naive baseline on the gold set; thresholds chosen |
| **5. Rules and extended questions** | Q5 model rows, plus Q6–Q12 | SSVC agreement against CISA measured |
| **6. Model bake-off** | Clef vs Flash vs generative baselines, calibration plots | A recommendation for which model to use per question |
| **7. Full run and report** | 60-day run, per-CNA page, write-up | Shareable findings |

Stages 0–3 are the weekend's critical path. Stage 2 produces findings even if Clef disappoints.

## Open decisions (defaults in bold)
- Window: **ingest 60, develop on 30**.
- NVD second opinion: **yes, if you have an API key; otherwise skip**.
- Gold set labeler: **you, ~2 hrs, with a simple labeling page**.
- Output: **dashboard artifact + CSV/Parquet export + a short write-up**.

## Risks
- The 26-option limit makes free-form CWE prediction lossy. That's why verifying the assigned CWE is the main approach.
- External labels such as NVD and CNA vectors are themselves noisy. Report *agreement* with them, not *accuracy* against them.
- Local throughput is not yet measured. The published 209 ms median is probably server-class hardware. Stage 0 measures it here.
- A Clef answer is an opinion with a probability, not proof. Report results as "flagged for review".

# CLEFCVE results

Generated 2026-10-03 20:09 UTC from cvelistV5 `70f91a3c4fb4` (HEAD 2026-10-03 08:55 UTC). Corpus: 60-day window; model runs use a random sample of the 30-day slice plus all recovered REJECTED records.

| model | pack | CVEs | answers |
|---|---|---|---|
| clef-flash | cvss31 | 300 | 2400 |
| clef-flash | cvss40 | 300 | 3300 |
| clef-flash | cwe_verify | 211 | 522 |
| clef-flash | quality | 529 | 10853 |
| clef | cvss31 | 300 | 2400 |
| clef | cvss40 | 300 | 3300 |
| clef | cwe_verify | 210 | 520 |
| clef | quality | 529 | 10853 |

## Accuracy against hand labels (gold set)

1 CVEs labeled (Q1 and clarity; CVSS and CWE use the LLM jury below). These are scored against your judgment, unlike the agreement numbers elsewhere.

| model | n | q1_accuracy_pct | false_yes_pct | false_no_pct |
|---|---|---|---|---|
| clef-flash | 1 | 100.0 | 0 | 0 |
| clef | 1 | 100.0 | 0 | 0 |


Description clarity (0-4): mean absolute error and share within one level.

| model | n | mae | within_1_pct | pearson_r |
|---|---|---|---|---|
| clef-flash | 1 | 0.04 | 100.0 | nan |
| clef | 1 | 0.07 | 100.0 | nan |

## Q1: Does the description establish a security impact?

Rephrased from "is this a vulnerability?" after the first run: the text alone couldn't separate CVEs later rejected as invalid from valid ones (p = 0.93 vs 0.89), because the reasons for rejection are rarely visible in the description. Rejected records use their last published text from git history.

| grp | model | n | mean_p_impact | pct_no_impact_stated |
|---|---|---|---|---|
| published | clef-flash | 428 | 0.71 | 20.1 |
| published | clef | 428 | 0.809 | 14.5 |
| rejected_duplicate | clef-flash | 30 | 0.693 | 16.7 |
| rejected_duplicate | clef | 30 | 0.824 | 16.7 |
| rejected_invalid | clef-flash | 23 | 0.846 | 4.3 |
| rejected_invalid | clef | 23 | 0.911 | 4.3 |
| rejected_other | clef-flash | 48 | 0.612 | 33.3 |
| rejected_other | clef | 48 | 0.667 | 33.3 |


How the impact is supported (`impact_basis`), published CVEs:

| model | basis | n | pct |
|---|---|---|---|
| clef-flash | stated_explicitly | 239 | 55.8 |
| clef-flash | bug_fix_only | 122 | 28.5 |
| clef-flash | implied_by_weakness | 62 | 14.5 |
| clef-flash | not_security_relevant | 4 | 0.9 |
| clef-flash | insufficient_information | 1 | 0.2 |
| clef | stated_explicitly | 286 | 66.8 |
| clef | implied_by_weakness | 80 | 18.7 |
| clef | bug_fix_only | 58 | 13.6 |
| clef | not_security_relevant | 4 | 0.9 |


By CNA: share of descriptions with no security impact established (Clef 27B, ≥ 5 sampled CVEs):

| assigner | n | pct_no_impact_stated |
|---|---|---|
| mozilla | 6 | 100.0 |
| Linux | 42 | 95.2 |
| cisco | 6 | 33.3 |
| apache | 8 | 25.0 |
| Patchstack | 10 | 10.0 |
| apple | 11 | 9.1 |
| mitre | 13 | 7.7 |
| VulDB | 28 | 7.1 |
| ibm | 17 | 5.9 |
| VulnCheck | 34 | 0 |
| GitHub_M | 29 | 0 |
| microsoft | 26 | 0 |
| WPScan | 17 | 0 |
| Chrome | 16 | 0 |
| oracle | 14 | 0 |
| redhat | 9 | 0 |
| adobe | 8 | 0 |
| hpe | 8 | 0 |
| nvidia | 7 | 0 |
| dell | 7 | 0 |
| Wordfence | 6 | 0 |
| CIRCL | 6 | 0 |
| cisa-cg | 5 | 0 |


Published CVEs where Clef 27B finds the least stated impact:

| cve_id | assigner | p_impact | basis | description |
|---|---|---|---|---|
| CVE-2026-90027 | Linux | 0.038 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

usb: typec: qcom-pmic-typec: disable cc_debounce_dw |
| CVE-2026-90222 | Linux | 0.042 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

nfc: pn533: hold a reference to the request skb dur |
| CVE-2026-89447 | Linux | 0.042 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

iommufd: Avoid locking internal accesses during unm |
| CVE-2026-93244 | Linux | 0.058 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

drm/sysfb: simpledrm: Improve stride validation

Va |
| CVE-2026-98054 | Linux | 0.059 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

ASoC: Intel: avs: Fix unbalanced module reference c |
| CVE-2026-90242 | Linux | 0.061 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

iommu/vt-d: Fix iopf_refcount leak on RID domain re |
| CVE-2026-97532 | Linux | 0.065 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

scsi: qla2xxx: Null out freed pointers in qla2x00_m |
| CVE-2026-89938 | Linux | 0.065 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

iio: chemical: atlas-sensor: use iio_trigger_poll_n |
| CVE-2026-93275 | Linux | 0.07 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

perf/x86/intel/pt: Fix stop/start with no update

I |
| CVE-2026-89595 | Linux | 0.071 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

fsnotify: Fix stale object mask after concurrent ma |

## Q2: Description quality

Element presence = share of descriptions where Clef says p ≥ 0.5. `clarity` is the expected level on a 0-4 scale (Unusable, Poor, Adequate, Good, Excellent).

| model | n | clarity | product | versions | vuln_type | attacker | impact | vector | commit_msg | boilerplate |
|---|---|---|---|---|---|---|---|---|---|---|
| clef-flash | 428 | 2.5 | 90.0 | 59.0 | 58.0 | 64.0 | 60.0 | 78.0 | 19.0 | 5.0 |
| clef | 428 | 2.6 | 95.0 | 59.0 | 68.0 | 63.0 | 75.0 | 78.0 | 11.0 | 12.0 |


By CNA (Clef 27B if available, CNAs with ≥ 5 sampled CVEs):

| assigner | n | clarity | impact_pct | attacker_pct | commit_msg_pct |
|---|---|---|---|---|---|
| mozilla | 6 | 1.8 | 0 | 0 | 0 |
| Patchstack | 10 | 2.0 | 10.0 | 50.0 | 0 |
| nvidia | 7 | 2.0 | 100.0 | 14.0 | 0 |
| microsoft | 26 | 2.1 | 100.0 | 96.0 | 0 |
| adobe | 8 | 2.1 | 100.0 | 75.0 | 0 |
| Linux | 42 | 2.1 | 17.0 | 2.0 | 100.0 |
| apple | 11 | 2.1 | 100.0 | 27.0 | 0 |
| cisco | 6 | 2.2 | 67.0 | 67.0 | 0 |
| hpe | 8 | 2.4 | 100.0 | 88.0 | 0 |
| VulDB | 28 | 2.5 | 21.0 | 57.0 | 0 |
| ibm | 17 | 2.5 | 94.0 | 88.0 | 0 |
| apache | 8 | 2.6 | 38.0 | 38.0 | 0 |
| cisa-cg | 5 | 2.6 | 100.0 | 100.0 | 0 |
| redhat | 9 | 2.6 | 100.0 | 67.0 | 0 |
| oracle | 14 | 2.8 | 100.0 | 100.0 | 0 |
| mitre | 13 | 2.8 | 77.0 | 31.0 | 0 |
| dell | 7 | 2.8 | 100.0 | 100.0 | 0 |
| CIRCL | 6 | 2.9 | 83.0 | 83.0 | 17.0 |
| Chrome | 16 | 2.9 | 100.0 | 100.0 | 0 |
| WPScan | 17 | 3.3 | 94.0 | 100.0 | 0 |
| GitHub_M | 29 | 3.3 | 83.0 | 55.0 | 0 |
| VulnCheck | 34 | 3.4 | 100.0 | 91.0 | 0 |
| Wordfence | 6 | 3.6 | 100.0 | 100.0 | 0 |


Lowest-clarity descriptions (Clef 27B):

| cve_id | assigner | clarity | description |
|---|---|---|---|
| CVE-2025-59607 | qualcomm | 1.1 | Memory Corruption when copying large input data exceeds normal allocation limits. |
| CVE-2026-93310 | VulDB | 1.2 | A vulnerability was identified in O-RAN-SC SMO OAM 2025-06-10. This affects an unknown part of the component VES Collector. The manipulation |
| CVE-2026-20335 | cisco | 1.2 | As part of Cisco's ongoing commitment to proactive security and product quality, the Cisco Secure Adaptive Security Appliance Software, Cisc |
| CVE-2026-14441 | brocade | 1.2 | A logic flaw in Java cache key handling object comparison handling could lead to improper identifier resolution when processing specific use |
| CVE-2026-93244 | Linux | 1.3 | In the Linux kernel, the following vulnerability has been resolved:

drm/sysfb: simpledrm: Improve stride validation

Validate the computed  |
| CVE-2026-20330 | cisco | 1.4 | As part of Cisco's ongoing commitment to proactive security and product quality, the Cisco Secure Adaptive Security Appliance Software, Cisc |
| CVE-2026-80915 | Linux | 1.4 | In the Linux kernel, the following vulnerability has been resolved:

drm/xe: Fix DPT allocation paths.

Remove the fallback for VRAM to syst |
| CVE-2026-87019 | Tanium | 1.4 | Tanium addressed an improper access controls vulnerability in Comply. |

## Q3: Is the CWE correct?

Fit of each CNA-assigned CWE, judged against its CWE definition:

| model | fit | n | pct |
|---|---|---|---|
| clef-flash | exact | 219 | 83.9 |
| clef-flash | too_general | 21 | 8.0 |
| clef-flash | related_but_wrong | 10 | 3.8 |
| clef-flash | wrong | 6 | 2.3 |
| clef-flash | impact_not_cause | 5 | 1.9 |
| clef | exact | 180 | 69.2 |
| clef | too_general | 54 | 20.8 |
| clef | wrong | 9 | 3.5 |
| clef | impact_not_cause | 9 | 3.5 |
| clef | related_but_wrong | 8 | 3.1 |


Sanity check: CWE mapping usage (from the CWE catalog) vs Clef's acceptance. Discouraged entries (e.g. CWE-20, CWE-200, CWE-284) should be accepted less often.

| model | mapping_usage | n | accepted_pct | too_general_pct |
|---|---|---|---|---|
| clef-flash | Allowed | 162 | 94.4 | 4.9 |
| clef-flash | Allowed-with-Review | 56 | 96.4 | 12.5 |
| clef-flash | Discouraged | 43 | 95.3 | 14.0 |
| clef | Allowed | 161 | 94.4 | 13.0 |
| clef | Allowed-with-Review | 56 | 91.1 | 21.4 |
| clef | Discouraged | 43 | 97.7 | 48.8 |


Most-rejected CWE assignments (Clef 27B):

| cve_id | assigner | cwe | name | p_accept | description |
|---|---|---|---|---|---|
| CVE-2026-12269 | Zohocorp | CWE-434 | Unrestricted Upload of File with Dangerous Type | 0.037 | Zohocorp ManageEngine DDI Central 6.2.0 build below 6201 had a Keepalived configuration injection vu |
| CVE-2026-56660 | GitHub_M | CWE-352 | Cross-Site Request Forgery (CSRF) | 0.062 | GetSimple CMS is a content management system (CMS), and GetSimple CMS CE is the community edition of |
| CVE-2026-69421 | microsoft | CWE-122 | Heap-based Buffer Overflow | 0.098 | Integer underflow (wrap or wraparound) in Windows Kernel Mode Driver allows an authorized attacker t |
| CVE-2026-16346 | ibm | CWE-285 | Improper Authorization | 0.107 | IBM DataStage on Cloud Pak for Data 5.4.0.0 could allow a remote authenticated attacker to execute a |
| CVE-2026-69308 | microsoft | CWE-843 | Access of Resource Using Incompatible Type ('Type Confusion') | 0.135 | Out-of-bounds read in Microsoft Standard XPS allows an authorized attacker to disclose information l |
| CVE-2026-56660 | GitHub_M | CWE-918 | Server-Side Request Forgery (SSRF) | 0.149 | GetSimple CMS is a content management system (CMS), and GetSimple CMS CE is the community edition of |
| CVE-2026-94426 | VulDB | CWE-94 | Improper Control of Generation of Code ('Code Injection') | 0.16 | A vulnerability was determined in xuxueli xxl-job up to 3.5.0. The impacted element is an unknown fu |
| CVE-2026-93977 | VulDB | CWE-94 | Improper Control of Generation of Code ('Code Injection') | 0.191 | A vulnerability was determined in code-projects Assessment Management 1.0. Affected by this vulnerab |
| CVE-2026-49314 | huawei | CWE-125 | Out-of-bounds Read | 0.21 | OOB write vulnerability in the rendering and composition module.
Impact: Successful exploitation of  |
| CVE-2026-69876 | microsoft | CWE-415 | Double Free | 0.216 | Use after free in Windows DHCP Server allows an authorized attacker to execute code over an adjacent |

## Q4: Is the CVSS correct?

## LLM jury: reference labels for CVSS and CWE

150 CVEs, 5 jurors (foundation-sec-8b-instruct:latest, gpt-oss:20b, granite4.2:30b, nemotron-3.5-lightning:30b, qwen3.6:35b), from the same text Clef sees. The reference for each field is the strict-majority vote; fields without one are excluded.


**How much the jury agrees with itself:**

| field | n | unanimous_pct | has_majority_pct |
|---|---|---|---|
| AV | 150 | 64.0 | 98.7 |
| AC | 150 | 98.7 | 100.0 |
| PR | 150 | 54.0 | 98.7 |
| UI | 150 | 78.7 | 100.0 |
| S | 150 | 22.0 | 100.0 |
| C | 150 | 52.0 | 95.3 |
| I | 150 | 36.7 | 88.0 |
| A | 150 | 15.3 | 92.7 |
| cwe_fit | 109 | 67.9 | 97.2 |
| best_cwe | 150 | 54.0 | 85.3 |


**Who agrees with the jury: Clef, Flash, or the CNA?** (CVSS v3.1, per metric, where the jury has a majority)

| metric | n_clef | clef_pct | n_flash | flash_pct | n_cna | cna_pct |
|---|---|---|---|---|---|---|
| AV | 148 | 90.5 | 148 | 82.4 | 92 | 94.6 |
| AC | 150 | 85.3 | 150 | 82.7 | 92 | 84.8 |
| PR | 148 | 69.6 | 148 | 70.3 | 91 | 78.0 |
| UI | 150 | 92.0 | 150 | 96.0 | 92 | 93.5 |
| S | 150 | 83.3 | 150 | 71.3 | 92 | 75.0 |
| C | 143 | 56.6 | 143 | 49.7 | 88 | 59.1 |
| I | 132 | 56.1 | 132 | 65.2 | 81 | 59.3 |
| A | 139 | 75.5 | 139 | 77.0 | 86 | 74.4 |


Same comparison restricted to CVEs that have all three (Clef 27B, CNA vector, jury majority), so the columns are directly comparable:

| metric | n | clef_pct | cna_pct | clef_right_cna_wrong | cna_right_clef_wrong |
|---|---|---|---|---|---|
| AV | 92 | 94.6 | 94.6 | 2 | 2 |
| AC | 92 | 92.4 | 84.8 | 14 | 7 |
| PR | 91 | 79.1 | 78.0 | 7 | 6 |
| UI | 92 | 92.4 | 93.5 | 4 | 5 |
| S | 92 | 81.5 | 75.0 | 10 | 4 |
| C | 88 | 62.5 | 59.1 | 12 | 9 |
| I | 81 | 63.0 | 59.3 | 10 | 7 |
| A | 86 | 74.4 | 74.4 | 16 | 16 |


**CWE:** fit of the CNA-assigned CWE, and whether the jury's preferred CWE matches it.

| model | n | same_fit_pct | exact_vs_not_pct | jury_best_is_cna_cwe_pct |
|---|---|---|---|---|
| clef-flash | 109 | 86.8 | 86.8 | 95.4 |
| clef | 109 | 76.4 | 76.4 | 95.4 |


**Each juror vs the others' majority** (leave-one-out; how good a single general-purpose model is):

| juror | answers | cvss_metric_pct | cwe_fit_pct |
|---|---|---|---|
| granite4.2:30b | 1309 | 78.3 | 93.6 |
| qwen3.6:35b | 1309 | 78.3 | 73.4 |
| nemotron-3.5-lightning:30b | 1309 | 78.2 | 93.6 |
| gpt-oss:20b | 1309 | 76.5 | 88.1 |
| foundation-sec-8b-instruct:latest | 1309 | 70.4 | 94.5 |


CVEs where the jury and Clef 27B agree with each other but not with the CNA (likely CNA errors):

| cve_id | assigner | changes | description |
|---|---|---|---|
| CVE-2026-86267 | VulDB | A L→N, C L→H, I L→H, PR L→N | A security vulnerability has been detected in itsourcecode Information System Society Membership System 1.0. T |
| CVE-2026-18185 | ibm | A L→N, C L→H, I L→H | IBM Financial Transaction Manager (FTM) for RedHat OpenShift could allow a remote attacker to access sensitive |
| CVE-2026-23792 | mitre | A L→H, AC H→L, S C→U | An issue was discovered in NR RRC in Samsung Mobile Processor and Modem Exynos 1080, 2100, 1280, 2200, 1330, 1 |
| CVE-2026-49314 | huawei | A L→H, C H→N, I L→N | OOB write vulnerability in the rendering and composition module.
Impact: Successful exploitation of this vulne |
| CVE-2026-79918 | GitHub_M | C L→H, I L→H, S U→C | MaxKB is an open-source AI assistant for enterprise. Prior to version 2.10.6-lts, the ToolExecutor LD_PRELOAD  |
| CVE-2026-94015 | VulDB | A L→N, C L→H, I L→H | A vulnerability was identified in SourceCodester Drug Recommendation System 1.0. This affects an unknown funct |
| CVE-2023-22631 | mitre | I L→H, PR H→N | PRTG Network Monitor before 23.1.82 allows remote attackers to write to files via the HTTP XML/REST Sensor. |
| CVE-2026-100589 | VulnCheck | A L→N, S U→C | OpenClaw versions before 2026.7.1 contain a sandbox bypass vulnerability in the browser tool that allows sandb |
| CVE-2026-100837 | VulnCheck | AC H→L, C L→H | Contrast (Edgeless Systems) through 1.20.0 performs unanchored suffix matching when selecting per-registry con |
| CVE-2026-101013 | VulDB | C L→H, I L→H | A security vulnerability has been detected in mathurvishal CloudClassroom-PHP-Project up to 5dadec098bfbbf3300 |
| CVE-2026-101042 | VulnCheck | AC H→L, UI R→N | Parse Server is an open-source backend server. In versions >= 9.0.0 < 9.10.1-alpha.10 and >= 8.0.2 < 8.6.91, t |
| CVE-2026-12759 | ibm | A N→H, C H→N | IBM Cloud Pak for Business Automation could allow an authenticated user to cause a denial of service due to un |

### Severity band agreement

Clef's metric choices assembled into a full vector and scored, vs the CNA's vector.

| version | model | n | same_band_pct | mean_abs_score_diff | cna_higher_by_1plus_pct | cna_lower_by_1plus_pct |
|---|---|---|---|---|---|---|
| 3.1 | clef-flash | 192 | 45.3 | 1.8 | 27.6 | 30.2 |
| 3.1 | clef | 192 | 64.6 | 1.2 | 20.3 | 24.0 |
| 4.0 | clef-flash | 85 | 48.2 | 1.7 | 25.9 | 30.6 |
| 4.0 | clef | 85 | 56.5 | 1.4 | 24.7 | 20.0 |


By CNA (Clef 27B, ≥ 5 sampled CVEs). Positive `cna_minus_clef` = CNA scores higher than Clef:

| assigner | version | n | cna_minus_clef | same_band_pct |
|---|---|---|---|---|
| Linux | 3.1 | 9 | 3.5 | 11.1 |
| VulnCheck | 4.0 | 31 | 1.4 | 54.8 |
| microsoft | 3.1 | 23 | 0.63 | 69.6 |
| GitHub_M | 4.0 | 10 | 0.43 | 80.0 |
| VulnCheck | 3.1 | 30 | 0.22 | 73.3 |
| Patchstack | 3.1 | 8 | 0.14 | 75.0 |
| ibm | 3.1 | 14 | 0.09 | 78.6 |
| oracle | 3.1 | 11 | 0 | 100.0 |
| adobe | 3.1 | 5 | -0.08 | 80.0 |
| redhat | 3.1 | 6 | -0.08 | 33.3 |
| hpe | 3.1 | 5 | -0.22 | 40.0 |
| GitHub_M | 3.1 | 16 | -0.53 | 75.0 |
| VulDB | 3.1 | 25 | -1.0 | 36.0 |
| VulDB | 4.0 | 25 | -1.2 | 48.0 |

### CVSS v3.1

Per-metric agreement between Clef's independent answer and the assigned vector. `confident_disagree` = Clef gave the assigned value < 15% probability.

| metric | model | source | n | agree_pct | confident_disagree_pct |
|---|---|---|---|---|---|
| AV | clef-flash | cna | 192 | 92.7 | 1.0 |
| AV | clef-flash | CISA-ADP | 51 | 74.5 | 5.9 |
| AV | clef | cna | 192 | 95.8 | 1.6 |
| AV | clef | CISA-ADP | 51 | 88.2 | 7.8 |
| AC | clef-flash | cna | 192 | 78.6 | 3.6 |
| AC | clef-flash | CISA-ADP | 51 | 80.4 | 3.9 |
| AC | clef | cna | 192 | 80.2 | 7.8 |
| AC | clef | CISA-ADP | 51 | 76.5 | 7.8 |
| PR | clef-flash | cna | 192 | 77.1 | 4.2 |
| PR | clef-flash | CISA-ADP | 51 | 62.7 | 11.8 |
| PR | clef | cna | 192 | 80.7 | 4.7 |
| PR | clef | CISA-ADP | 51 | 70.6 | 9.8 |
| UI | clef-flash | cna | 192 | 90.6 | 3.6 |
| UI | clef-flash | CISA-ADP | 51 | 88.2 | 5.9 |
| UI | clef | cna | 192 | 91.1 | 2.1 |
| UI | clef | CISA-ADP | 51 | 92.2 | 2.0 |
| S | clef-flash | cna | 192 | 65.6 | 3.1 |
| S | clef-flash | CISA-ADP | 51 | 45.1 | 5.9 |
| S | clef | cna | 192 | 82.8 | 5.2 |
| S | clef | CISA-ADP | 51 | 78.4 | 5.9 |
| C | clef-flash | cna | 192 | 52.1 | 14.6 |
| C | clef-flash | CISA-ADP | 51 | 60.8 | 3.9 |
| C | clef | cna | 192 | 67.7 | 12.5 |
| C | clef | CISA-ADP | 51 | 56.9 | 7.8 |
| I | clef-flash | cna | 192 | 69.8 | 15.6 |
| I | clef-flash | CISA-ADP | 51 | 72.5 | 7.8 |
| I | clef | cna | 192 | 75.5 | 5.7 |
| I | clef | CISA-ADP | 51 | 76.5 | 3.9 |
| A | clef-flash | cna | 192 | 60.9 | 28.6 |
| A | clef-flash | CISA-ADP | 51 | 62.7 | 33.3 |
| A | clef | cna | 192 | 60.4 | 18.2 |
| A | clef | CISA-ADP | 51 | 60.8 | 23.5 |


**Human-vs-human reference:** CNA vs CISA ADP agreement over the whole 60-day corpus (CISA usually adds CVSS only when the CNA didn't, so overlap is small).

| metric | n | cna_vs_cisa_agree_pct |
|---|---|---|
| AV | 8 | 75.0 |
| AC | 8 | 75.0 |
| PR | 8 | 87.5 |
| UI | 8 | 75.0 |
| S | 8 | 100.0 |
| C | 8 | 62.5 |
| I | 8 | 75.0 |
| A | 8 | 37.5 |


Where Clef most confidently disagrees with the CNA (metric value it rated least likely):

| cve_id | assigner | metric | cna | clef | p_cna_value | description |
|---|---|---|---|---|---|---|
| CVE-2026-12759 | ibm | C | H | N | 0.009 | IBM Cloud Pak for Business Automation could allow an authenticated user to cause a denial of service due to un |
| CVE-2026-103056 | VulnCheck | UI | R | N | 0.009 | AiSOC versions 7.2.0 before 12.0.0 contain a command injection vulnerability in the actions service that build |
| CVE-2026-47596 | nvidia | AV | P | L | 0.011 | NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer where an unprivileged us |
| CVE-2026-73784 | hpe | A | H | N | 0.012 | A potential security vulnerability in HPE IceWall products could be exploited to tamper SAML response, allowin |
| CVE-2026-97268 | Patchstack | A | L | N | 0.015 | Unauthenticated Cross Site Scripting (XSS) in Premmerce Wishlist for WooCommerce <= 1.1.13 versions. |
| CVE-2026-62110 | Patchstack | A | L | N | 0.016 | Contributor Cross Site Scripting (XSS) in Bold Page Builder <= 5.9.9 versions. |
| CVE-2026-92780 | VulnCheck | A | H | N | 0.017 | KnowStreaming through 3.4.1 fails to enforce role-based access control on REST API endpoints, allowing any aut |
| CVE-2026-12759 | ibm | A | N | H | 0.018 | IBM Cloud Pak for Business Automation could allow an authenticated user to cause a denial of service due to un |
| CVE-2026-100589 | VulnCheck | S | U | C | 0.021 | OpenClaw versions before 2026.7.1 contain a sandbox bypass vulnerability in the browser tool that allows sandb |
| CVE-2026-103281 | VulnCheck | I | L | N | 0.022 | Ghost (npm package 'ghost') versions from 3.23.0 up to, but not including, 6.23.0 expose API keys to users wit |
| CVE-2026-94177 | Patchstack | PR | L | N | 0.022 | Unauthenticated SQL Injection in GamiPress <= 8.0.2 versions. |
| CVE-2026-76699 | hpe | C | L | N | 0.025 | A buffer overflow vulnerability exists in a system service within the underlying operating system of HPE Netwo |

### CVSS v4.0

Per-metric agreement between Clef's independent answer and the assigned vector. `confident_disagree` = Clef gave the assigned value < 15% probability.

| metric | model | source | n | agree_pct | confident_disagree_pct |
|---|---|---|---|---|---|
| AV | clef-flash | cna | 85 | 83.5 | 1.2 |
| AV | clef | cna | 85 | 94.1 | 2.4 |
| AC | clef-flash | cna | 85 | 94.1 | 3.5 |
| AC | clef | cna | 85 | 94.1 | 2.4 |
| AT | clef-flash | cna | 85 | 81.2 | 1.2 |
| AT | clef | cna | 85 | 85.9 | 2.4 |
| PR | clef-flash | cna | 85 | 78.8 | 7.1 |
| PR | clef | cna | 85 | 84.7 | 3.5 |
| UI | clef-flash | cna | 85 | 88.2 | 4.7 |
| UI | clef | cna | 85 | 85.9 | 7.1 |
| VC | clef-flash | cna | 85 | 51.8 | 3.5 |
| VC | clef | cna | 85 | 67.1 | 8.2 |
| VI | clef-flash | cna | 85 | 68.2 | 10.6 |
| VI | clef | cna | 85 | 74.1 | 1.2 |
| VA | clef-flash | cna | 85 | 62.4 | 31.8 |
| VA | clef | cna | 85 | 58.8 | 30.6 |
| SC | clef-flash | cna | 85 | 78.8 | 2.4 |
| SC | clef | cna | 85 | 83.5 | 11.8 |
| SI | clef-flash | cna | 85 | 77.6 | 7.1 |
| SI | clef | cna | 85 | 87.1 | 12.9 |
| SA | clef-flash | cna | 85 | 91.8 | 8.2 |
| SA | clef | cna | 85 | 91.8 | 7.1 |



Where Clef most confidently disagrees with the CNA (metric value it rated least likely):

| cve_id | assigner | metric | cna | clef | p_cna_value | description |
|---|---|---|---|---|---|---|
| CVE-2026-88817 | airbus | VA | H | N | 0.007 | An authenticated, non-guest user of Curiosity Workspace could enroll themselves as an administrator and member |
| CVE-2026-90691 | VulDB | SA | L | N | 0.008 | A security vulnerability has been detected in 0x4m4 HexStrike AI up to d689933ff579d839c676c82b231f8e98326c5f0 |
| CVE-2026-87912 | AMZN | SI | L | N | 0.011 | A missing S3 bucket ownership verification in the AWS Security Agent plugin in Amazon aws-agents-for-devsecops |
| CVE-2026-103056 | VulnCheck | UI | P | N | 0.011 | AiSOC versions 7.2.0 before 12.0.0 contain a command injection vulnerability in the actions service that build |
| CVE-2026-86306 | VulDB | VA | L | N | 0.011 | A weakness has been identified in light0011 cms c774dce31c6df0055568a8d5c53d964d99be199d/f72cf46f601efb2a0618c |
| CVE-2026-100589 | VulnCheck | VA | L | N | 0.011 | OpenClaw versions before 2026.7.1 contain a sandbox bypass vulnerability in the browser tool that allows sandb |
| CVE-2026-86674 | VulDB | VA | L | N | 0.013 | A vulnerability was found in ningzichun Student Management System up to 98760f5711cf6dc8b4adca53a9e207ca49b02e |
| CVE-2026-90520 | VulDB | VA | L | N | 0.013 | A vulnerability has been found in jaychouchannel Tourism-Management-System up to 84d8ec384f669df3985293dab293b |
| CVE-2026-93968 | VulDB | VA | L | N | 0.014 | A vulnerability was determined in aiyiyi121 SxDevOps 1.0/1.1. This affects the function update of the file bac |
| CVE-2026-86810 | VulDB | VA | L | N | 0.014 | A vulnerability was detected in Open-Web-Analytics up to 1.9.1. The impacted element is the function checkCapa |
| CVE-2026-103281 | VulnCheck | VI | L | N | 0.016 | Ghost (npm package 'ghost') versions from 3.23.0 up to, but not including, 6.23.0 expose API keys to users wit |
| CVE-2026-102249 | VulDB | VA | L | N | 0.017 | A security flaw has been discovered in REBUILD up to 4.4.11. This vulnerability affects unknown code of the fi |

## SSVC vs CISA Vulnrichment

`baseline` = always predicting CISA's most common value in this sample.

| point | model | n | agree_pct | baseline_pct |
|---|---|---|---|---|
| automatable | clef-flash | 454 | 74.9 | 77.1 |
| automatable | clef | 454 | 77.5 | 77.1 |
| exploitation | clef-flash | 454 | 89.0 | 84.4 |
| exploitation | clef | 454 | 89.2 | 84.4 |
| technical_impact | clef-flash | 454 | 80.8 | 61.5 |
| technical_impact | clef | 454 | 82.4 | 61.5 |

## Q5: CNA Operational Rules 4.1.0 (full corpus, deterministic)

| check_id | rule | level | flagged | evaluated | pct |
|---|---|---|---|---|---|
| fixed_version | 5.1.5 | SHOULD | 12780 | 27489 | 46.5 |
| cwe_structured | 5.1.7 | SHOULD | 8389 | 27489 | 30.5 |
| vuln_type | 5.1.7 | MUST | 5097 | 27489 | 18.5 |
| cwe_mapping_allowed | 5.1.7 | SHOULD | 3384 | 22320 | 15.2 |
| desc_unique | 5.1.1 | SHOULD | 1947 | 27489 | 7.1 |
| affected_vendor | 5.1.3 | SHOULD | 1403 | 26751 | 5.2 |
| affected_product | 5.1.3 | MUST | 738 | 27489 | 2.7 |
| desc_no_credits | 5.2.4 | MUST NOT | 243 | 27489 | 0.9 |
| desc_no_other_ids | 5.2.11 | SHOULD NOT | 113 | 27489 | 0.4 |
| affected_status | 5.1.4 | MUST | 10 | 27489 | 0 |
| desc_min_length | 5.1.1 | SHOULD | 6 | 27489 | 0 |
| desc_not_only_diff | 5.2.7 | SHOULD NOT | 3 | 27489 | 0 |
| cwe_not_text_only | format | format | 1261 | 27489 | 4.6 |
| cvss_score_matches | format | format | 200 | 29692 | 0.7 |
| cvss_severity_matches | format | format | 107 | 28105 | 0.4 |


MUST-level failures by CNA (CNAs with ≥ 100 CVEs in the 60-day window):

| assigner | cves | pct_must_fail | most_common_failure |
|---|---|---|---|
| Linux | 3753 | 100.0 | vuln_type |
| mozilla | 250 | 100.0 | vuln_type |
| hpe | 165 | 97.0 | vuln_type |
| mitre | 1011 | 73.0 | affected_product, vuln_type |
| apache | 454 | 4.4 | vuln_type |
| ibm | 794 | 1.0 | vuln_type |
| redhat | 497 | 1.0 | vuln_type |
| CIRCL | 166 | 0.6 | affected_status |
| oracle | 1524 | 0 |  |
| Patchstack | 943 | 0 |  |
| VulnCheck | 2874 | 0 |  |
| VulDB | 1587 | 0 |  |
| TuranSec | 163 | 0 |  |
| icscert | 160 | 0 |  |
| adobe | 318 | 0 |  |


Judgment-based rules (Clef, sampled CVEs; % with p ≥ 0.5):

| model | multi_vuln_4_2_11 | credits_5_2_4 | irrelevant_5_2_6 | hosted_only_5_1_11 |
|---|---|---|---|---|
| clef-flash | 4.2 | 1.6 | 0 | 0.5 |
| clef | 5.6 | 1.4 | 0.2 | 0.2 |

## Clef vs Clef Flash

How often the two models give the same answer on the same question:

| pack | n | same_answer_pct | flash_ms | clef_ms |
|---|---|---|---|---|
| cvss31 | 2400 | 82.6 | 1221.0 | 4946.0 |
| cvss40 | 3300 | 83.3 | 1623.0 | 6479.0 |
| cwe_verify | 520 | 86.5 | 1181.0 | 1929.0 |
| quality | 10853 | 92.3 | 3137.0 | 11414.0 |

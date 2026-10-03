# CLEFCVE results

Generated 2026-10-03 17:40 UTC from cvelistV5 `70f91a3c4fb4` (HEAD 2026-10-03 08:55 UTC). Corpus: 60-day window; model runs use a random sample of the 30-day slice plus all recovered REJECTED records.

| model | pack | CVEs | answers |
|---|---|---|---|
| clef-flash | cvss31 | 300 | 2400 |
| clef-flash | cvss40 | 300 | 3300 |
| clef-flash | cwe_verify | 211 | 522 |
| clef-flash | quality | 401 | 7619 |
| clef | cvss31 | 150 | 1200 |
| clef | cvss40 | 150 | 1650 |
| clef | cwe_verify | 109 | 280 |
| clef | quality | 401 | 7619 |

## Q1: Is this a vulnerability?

Rejected records use their last published text, recovered from git history. `rejected_invalid` = rejection reason says it isn't a valid vulnerability; duplicates are separate because they *are* real vulnerabilities.

| grp | model | n | mean_p_vuln | pct_flagged_not_vuln |
|---|---|---|---|---|
| published | clef-flash | 300 | 0.846 | 9.3 |
| published | clef | 300 | 0.893 | 3.3 |
| rejected_duplicate | clef-flash | 30 | 0.863 | 3.3 |
| rejected_duplicate | clef | 30 | 0.906 | 3.3 |
| rejected_invalid | clef-flash | 23 | 0.922 | 0 |
| rejected_invalid | clef | 23 | 0.924 | 0 |
| rejected_other | clef-flash | 48 | 0.751 | 25.0 |
| rejected_other | clef | 48 | 0.832 | 6.3 |


Why (vuln_reason), published CVEs only:

| model | reason | n |
|---|---|---|
| clef-flash | real_vulnerability | 250 |
| clef-flash | no_security_impact | 50 |
| clef | real_vulnerability | 284 |
| clef | no_security_impact | 16 |


Published CVEs Clef (27B) is least convinced are vulnerabilities:

| cve_id | assigner | p_vuln | reason | description |
|---|---|---|---|---|
| CVE-2026-80910 | Linux | 0.303 | no_security_impact | In the Linux kernel, the following vulnerability has been resolved:

ASoC: codecs: lpass-wsa-macro: Fix enum kcontrol ac |
| CVE-2026-93275 | Linux | 0.352 | no_security_impact | In the Linux kernel, the following vulnerability has been resolved:

perf/x86/intel/pt: Fix stop/start with no update

I |
| CVE-2026-97566 | Linux | 0.378 | no_security_impact | In the Linux kernel, the following vulnerability has been resolved:

mptcp: pm: kernel: drop pending ADD_ADDR when remov |
| CVE-2026-80915 | Linux | 0.394 | no_security_impact | In the Linux kernel, the following vulnerability has been resolved:

drm/xe: Fix DPT allocation paths.

Remove the fallb |
| CVE-2026-90242 | Linux | 0.413 | no_security_impact | In the Linux kernel, the following vulnerability has been resolved:

iommu/vt-d: Fix iopf_refcount leak on RID domain re |
| CVE-2026-89595 | Linux | 0.451 | no_security_impact | In the Linux kernel, the following vulnerability has been resolved:

fsnotify: Fix stale object mask after concurrent ma |
| CVE-2026-93244 | Linux | 0.455 | no_security_impact | In the Linux kernel, the following vulnerability has been resolved:

drm/sysfb: simpledrm: Improve stride validation

Va |
| CVE-2026-98054 | Linux | 0.468 | no_security_impact | In the Linux kernel, the following vulnerability has been resolved:

ASoC: Intel: avs: Fix unbalanced module reference c |
| CVE-2026-89447 | Linux | 0.491 | no_security_impact | In the Linux kernel, the following vulnerability has been resolved:

iommufd: Avoid locking internal accesses during unm |
| CVE-2026-93804 | Linux | 0.492 | no_security_impact | In the Linux kernel, the following vulnerability has been resolved:

wifi: mac80211: ibss: wait for in-flight TX on disc |

## Q2: Description quality

Element presence = share of descriptions where Clef says p ≥ 0.5. `clarity` is the expected level on a 0-4 scale (Unusable, Poor, Adequate, Good, Excellent).

| model | n | clarity | product | versions | vuln_type | attacker | impact | vector | commit_msg | boilerplate |
|---|---|---|---|---|---|---|---|---|---|---|
| clef-flash | 300 | 2.5 | 90.0 | 61.0 | 53.0 | 67.0 | 56.0 | 79.0 | 20.0 | 5.0 |
| clef | 300 | 2.6 | 95.0 | 61.0 | 65.0 | 65.0 | 74.0 | 78.0 | 13.0 | 14.0 |


By CNA (Clef 27B if available, CNAs with ≥ 5 sampled CVEs):

| assigner | n | clarity | impact_pct | attacker_pct | commit_msg_pct |
|---|---|---|---|---|---|
| Patchstack | 8 | 1.9 | 13.0 | 63.0 | 0 |
| apple | 8 | 2.0 | 100.0 | 38.0 | 0 |
| microsoft | 23 | 2.1 | 100.0 | 96.0 | 0 |
| adobe | 5 | 2.1 | 100.0 | 100.0 | 0 |
| Linux | 39 | 2.1 | 18.0 | 3.0 | 100.0 |
| hpe | 5 | 2.4 | 100.0 | 80.0 | 0 |
| VulDB | 25 | 2.5 | 24.0 | 64.0 | 0 |
| ibm | 14 | 2.5 | 93.0 | 93.0 | 0 |
| redhat | 6 | 2.6 | 100.0 | 67.0 | 0 |
| oracle | 11 | 2.7 | 100.0 | 100.0 | 0 |
| apache | 5 | 2.7 | 40.0 | 40.0 | 0 |
| mitre | 10 | 2.8 | 80.0 | 40.0 | 0 |
| Chrome | 13 | 2.9 | 100.0 | 100.0 | 0 |
| WPScan | 14 | 3.3 | 100.0 | 100.0 | 0 |
| GitHub_M | 26 | 3.3 | 92.0 | 58.0 | 0 |
| VulnCheck | 31 | 3.4 | 100.0 | 90.0 | 0 |


Lowest-clarity descriptions (Clef 27B):

| cve_id | assigner | clarity | description |
|---|---|---|---|
| CVE-2026-93310 | VulDB | 1.2 | A vulnerability was identified in O-RAN-SC SMO OAM 2025-06-10. This affects an unknown part of the component VES Collector. The manipulation |
| CVE-2026-20335 | cisco | 1.2 | As part of Cisco's ongoing commitment to proactive security and product quality, the Cisco Secure Adaptive Security Appliance Software, Cisc |
| CVE-2026-93244 | Linux | 1.3 | In the Linux kernel, the following vulnerability has been resolved:

drm/sysfb: simpledrm: Improve stride validation

Validate the computed  |
| CVE-2026-80915 | Linux | 1.4 | In the Linux kernel, the following vulnerability has been resolved:

drm/xe: Fix DPT allocation paths.

Remove the fallback for VRAM to syst |
| CVE-2026-87019 | Tanium | 1.4 | Tanium addressed an improper access controls vulnerability in Comply. |
| CVE-2026-49314 | huawei | 1.4 | OOB write vulnerability in the rendering and composition module.
Impact: Successful exploitation of this vulnerability may affect availabili |
| CVE-2026-100798 | mozilla | 1.5 | Cryptography misuse in Storage: Quota Manager component. This vulnerability was fixed in Firefox ESR 153.4, Thunderbird 157, Thunderbird 153 |
| CVE-2026-98054 | Linux | 1.5 | In the Linux kernel, the following vulnerability has been resolved:

ASoC: Intel: avs: Fix unbalanced module reference count

strace_open()  |

## Q3: Is the CWE correct?

Fit of each CNA-assigned CWE, judged against its CWE definition:

| model | fit | n | pct |
|---|---|---|---|
| clef-flash | exact | 219 | 83.9 |
| clef-flash | too_general | 21 | 8.0 |
| clef-flash | related_but_wrong | 10 | 3.8 |
| clef-flash | wrong | 6 | 2.3 |
| clef-flash | impact_not_cause | 5 | 1.9 |
| clef | exact | 100 | 71.4 |
| clef | too_general | 28 | 20.0 |
| clef | related_but_wrong | 6 | 4.3 |
| clef | impact_not_cause | 3 | 2.1 |
| clef | wrong | 3 | 2.1 |


Sanity check: CWE mapping usage (from the CWE catalog) vs Clef's acceptance. Discouraged entries (e.g. CWE-20, CWE-200, CWE-284) should be accepted less often.

| model | mapping_usage | n | accepted_pct | too_general_pct |
|---|---|---|---|---|
| clef-flash | Allowed | 162 | 94.4 | 4.9 |
| clef-flash | Allowed-with-Review | 56 | 96.4 | 12.5 |
| clef-flash | Discouraged | 43 | 95.3 | 14.0 |
| clef | Allowed | 79 | 94.9 | 13.9 |
| clef | Allowed-with-Review | 34 | 91.2 | 17.6 |
| clef | Discouraged | 27 | 100.0 | 40.7 |


Most-rejected CWE assignments (Clef 27B):

| cve_id | assigner | cwe | name | p_accept | description |
|---|---|---|---|---|---|
| CVE-2026-12269 | Zohocorp | CWE-434 | Unrestricted Upload of File with Dangerous Type | 0.037 | Zohocorp ManageEngine DDI Central 6.2.0 build below 6201 had a Keepalived configuration injection vu |
| CVE-2026-69421 | microsoft | CWE-122 | Heap-based Buffer Overflow | 0.098 | Integer underflow (wrap or wraparound) in Windows Kernel Mode Driver allows an authorized attacker t |
| CVE-2026-49314 | huawei | CWE-125 | Out-of-bounds Read | 0.21 | OOB write vulnerability in the rendering and composition module.
Impact: Successful exploitation of  |
| CVE-2026-93643 | rapid7 | CWE-863 | Incorrect Authorization | 0.218 | When OnlyOffice/Document Editing is available, an unauthenticated remote attacker with access to an  |
| CVE-2023-22631 | mitre | CWE-88 | Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') | 0.326 | PRTG Network Monitor before 23.1.82 allows remote attackers to write to files via the HTTP XML/REST  |
| CVE-2026-90528 | VulDB | CWE-94 | Improper Control of Generation of Code ('Code Injection') | 0.399 | A flaw has been found in TDuckApp tduck-platform up to 5.3. Affected by this vulnerability is an unk |
| CVE-2026-12354 | ibm | CWE-913 | Improper Control of Dynamically-Managed Code Resources | 0.419 | IBM MQ 9.1.0.0 through 9.1.0.37 LTS, 9.2.0.0 through 9.2.0.43 LTS, 9.3.0.0 through 9.3.0.41 LTS, 9.3 |
| CVE-2026-85590 | VulnCheck | CWE-308 | Use of Single-factor Authentication | 0.506 | phpMyFAQ before 4.1.8 contains an authentication bypass vulnerability in its two-factor authenticati |
| CVE-2026-96513 | VulDB | CWE-284 | Improper Access Control | 0.531 | A security flaw has been discovered in Neethuharii CafeManagement. This issue affects some unknown p |
| CVE-2026-100837 | VulnCheck | CWE-1289 | Improper Validation of Unsafe Equivalence in Input | 0.54 | Contrast (Edgeless Systems) through 1.20.0 performs unanchored suffix matching when selecting per-re |

## Q4: Is the CVSS correct?

### Severity band agreement

Clef's metric choices assembled into a full vector and scored, vs the CNA's vector.

| version | model | n | same_band_pct | mean_abs_score_diff | cna_higher_by_1plus_pct | cna_lower_by_1plus_pct |
|---|---|---|---|---|---|---|
| 3.1 | clef-flash | 192 | 45.3 | 1.8 | 27.6 | 30.2 |
| 3.1 | clef | 92 | 62.0 | 1.3 | 25.0 | 25.0 |
| 4.0 | clef-flash | 85 | 48.2 | 1.7 | 25.9 | 30.6 |
| 4.0 | clef | 47 | 53.2 | 1.4 | 27.7 | 21.3 |


By CNA (Clef 27B, ≥ 5 sampled CVEs). Positive `cna_minus_clef` = CNA scores higher than Clef:

| assigner | version | n | cna_minus_clef | same_band_pct |
|---|---|---|---|---|
| Linux | 3.1 | 6 | 2.9 | 0 |
| VulnCheck | 4.0 | 17 | 1.9 | 41.2 |
| microsoft | 3.1 | 13 | 0.7 | 76.9 |
| VulnCheck | 3.1 | 16 | 0.22 | 56.3 |
| GitHub_M | 4.0 | 7 | 0.17 | 85.7 |
| ibm | 3.1 | 7 | -0.04 | 85.7 |
| GitHub_M | 3.1 | 9 | -0.49 | 88.9 |
| VulDB | 3.1 | 13 | -0.9 | 38.5 |
| VulDB | 4.0 | 13 | -1.1 | 46.2 |

### CVSS v3.1

Per-metric agreement between Clef's independent answer and the assigned vector. `confident_disagree` = Clef gave the assigned value < 15% probability.

| metric | model | source | n | agree_pct | confident_disagree_pct |
|---|---|---|---|---|---|
| AV | clef-flash | cna | 192 | 92.7 | 1.0 |
| AV | clef-flash | CISA-ADP | 51 | 74.5 | 5.9 |
| AV | clef | cna | 92 | 95.7 | 2.2 |
| AV | clef | CISA-ADP | 25 | 84.0 | 8.0 |
| AC | clef-flash | cna | 192 | 78.6 | 3.6 |
| AC | clef-flash | CISA-ADP | 51 | 80.4 | 3.9 |
| AC | clef | cna | 92 | 77.2 | 8.7 |
| AC | clef | CISA-ADP | 25 | 76.0 | 8.0 |
| PR | clef-flash | cna | 192 | 77.1 | 4.2 |
| PR | clef-flash | CISA-ADP | 51 | 62.7 | 11.8 |
| PR | clef | cna | 92 | 80.4 | 3.3 |
| PR | clef | CISA-ADP | 25 | 64.0 | 8.0 |
| UI | clef-flash | cna | 192 | 90.6 | 3.6 |
| UI | clef-flash | CISA-ADP | 51 | 88.2 | 5.9 |
| UI | clef | cna | 92 | 90.2 | 3.3 |
| UI | clef | CISA-ADP | 25 | 88.0 | 4.0 |
| S | clef-flash | cna | 192 | 65.6 | 3.1 |
| S | clef-flash | CISA-ADP | 51 | 45.1 | 5.9 |
| S | clef | cna | 92 | 84.8 | 4.3 |
| S | clef | CISA-ADP | 25 | 76.0 | 4.0 |
| C | clef-flash | cna | 192 | 52.1 | 14.6 |
| C | clef-flash | CISA-ADP | 51 | 60.8 | 3.9 |
| C | clef | cna | 92 | 67.4 | 15.2 |
| C | clef | CISA-ADP | 25 | 60.0 | 4.0 |
| I | clef-flash | cna | 192 | 69.8 | 15.6 |
| I | clef-flash | CISA-ADP | 51 | 72.5 | 7.8 |
| I | clef | cna | 92 | 73.9 | 5.4 |
| I | clef | CISA-ADP | 25 | 68.0 | 8.0 |
| A | clef-flash | cna | 192 | 60.9 | 28.6 |
| A | clef-flash | CISA-ADP | 51 | 62.7 | 33.3 |
| A | clef | cna | 92 | 57.6 | 19.6 |
| A | clef | CISA-ADP | 25 | 60.0 | 24.0 |


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
| CVE-2026-47596 | nvidia | AV | P | L | 0.011 | NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer where an unprivileged us |
| CVE-2026-92780 | VulnCheck | A | H | N | 0.017 | KnowStreaming through 3.4.1 fails to enforce role-based access control on REST API endpoints, allowing any aut |
| CVE-2026-12759 | ibm | A | N | H | 0.018 | IBM Cloud Pak for Business Automation could allow an authenticated user to cause a denial of service due to un |
| CVE-2026-100589 | VulnCheck | S | U | C | 0.021 | OpenClaw versions before 2026.7.1 contain a sandbox bypass vulnerability in the browser tool that allows sandb |
| CVE-2026-49314 | huawei | C | H | N | 0.026 | OOB write vulnerability in the rendering and composition module.
Impact: Successful exploitation of this vulne |
| CVE-2026-12402 | Wordfence | AC | H | L | 0.026 | The OTP Login & Register Woocommerce plugin for WordPress is vulnerable to Stored Cross-Site Scripting via 'fb |
| CVE-2026-86306 | VulDB | A | L | N | 0.027 | A weakness has been identified in light0011 cms c774dce31c6df0055568a8d5c53d964d99be199d/f72cf46f601efb2a0618c |
| CVE-2026-18185 | ibm | A | L | N | 0.029 | IBM Financial Transaction Manager (FTM) for RedHat OpenShift could allow a remote attacker to access sensitive |
| CVE-2026-87912 | AMZN | I | L | N | 0.031 | A missing S3 bucket ownership verification in the AWS Security Agent plugin in Amazon aws-agents-for-devsecops |
| CVE-2026-81802 | Patchstack | A | L | N | 0.032 | Unauthenticated Insecure Direct Object References (IDOR) in WpEvently <= 5.6.0 versions. |
| CVE-2023-22631 | mitre | PR | H | N | 0.034 | PRTG Network Monitor before 23.1.82 allows remote attackers to write to files via the HTTP XML/REST Sensor. |

### CVSS v4.0

Per-metric agreement between Clef's independent answer and the assigned vector. `confident_disagree` = Clef gave the assigned value < 15% probability.

| metric | model | source | n | agree_pct | confident_disagree_pct |
|---|---|---|---|---|---|
| AV | clef-flash | cna | 85 | 83.5 | 1.2 |
| AV | clef | cna | 47 | 95.7 | 2.1 |
| AC | clef-flash | cna | 85 | 94.1 | 3.5 |
| AC | clef | cna | 47 | 93.6 | 4.3 |
| AT | clef-flash | cna | 85 | 81.2 | 1.2 |
| AT | clef | cna | 47 | 89.4 | 2.1 |
| PR | clef-flash | cna | 85 | 78.8 | 7.1 |
| PR | clef | cna | 47 | 83.0 | 4.3 |
| UI | clef-flash | cna | 85 | 88.2 | 4.7 |
| UI | clef | cna | 47 | 83.0 | 8.5 |
| VC | clef-flash | cna | 85 | 51.8 | 3.5 |
| VC | clef | cna | 47 | 61.7 | 10.6 |
| VI | clef-flash | cna | 85 | 68.2 | 10.6 |
| VI | clef | cna | 47 | 72.3 | 0 |
| VA | clef-flash | cna | 85 | 62.4 | 31.8 |
| VA | clef | cna | 47 | 53.2 | 29.8 |
| SC | clef-flash | cna | 85 | 78.8 | 2.4 |
| SC | clef | cna | 47 | 83.0 | 14.9 |
| SI | clef-flash | cna | 85 | 77.6 | 7.1 |
| SI | clef | cna | 47 | 87.2 | 12.8 |
| SA | clef-flash | cna | 85 | 91.8 | 8.2 |
| SA | clef | cna | 47 | 93.6 | 6.4 |



Where Clef most confidently disagrees with the CNA (metric value it rated least likely):

| cve_id | assigner | metric | cna | clef | p_cna_value | description |
|---|---|---|---|---|---|---|
| CVE-2026-88817 | airbus | VA | H | N | 0.007 | An authenticated, non-guest user of Curiosity Workspace could enroll themselves as an administrator and member |
| CVE-2026-87912 | AMZN | SI | L | N | 0.011 | A missing S3 bucket ownership verification in the AWS Security Agent plugin in Amazon aws-agents-for-devsecops |
| CVE-2026-86306 | VulDB | VA | L | N | 0.011 | A weakness has been identified in light0011 cms c774dce31c6df0055568a8d5c53d964d99be199d/f72cf46f601efb2a0618c |
| CVE-2026-100589 | VulnCheck | VA | L | N | 0.011 | OpenClaw versions before 2026.7.1 contain a sandbox bypass vulnerability in the browser tool that allows sandb |
| CVE-2026-90520 | VulDB | VA | L | N | 0.013 | A vulnerability has been found in jaychouchannel Tourism-Management-System up to 84d8ec384f669df3985293dab293b |
| CVE-2026-93968 | VulDB | VA | L | N | 0.014 | A vulnerability was determined in aiyiyi121 SxDevOps 1.0/1.1. This affects the function update of the file bac |
| CVE-2026-86810 | VulDB | VA | L | N | 0.014 | A vulnerability was detected in Open-Web-Analytics up to 1.9.1. The impacted element is the function checkCapa |
| CVE-2026-97163 | Joomla | SA | H | N | 0.017 | Joomla Extension - lomart.fr - Unauthenticated remote code installation in UP plugin extension 5.0.0-5.2.0, 6. |
| CVE-2026-92780 | VulnCheck | VA | H | N | 0.017 | KnowStreaming through 3.4.1 fails to enforce role-based access control on REST API endpoints, allowing any aut |
| CVE-2026-76142 | krcert | SA | H | N | 0.018 | Insufficient authentication and access control on the internal-only IPC SOAP endpoint of the Genian NAC/ZTNA p |
| CVE-2026-97360 | VulnCheck | SA | H | N | 0.019 | HFS2 version 2.4.0 and earlier contains an unauthenticated arbitrary file access vulnerability that allows una |
| CVE-2026-97360 | VulnCheck | SI | H | N | 0.022 | HFS2 version 2.4.0 and earlier contains an unauthenticated arbitrary file access vulnerability that allows una |

## SSVC vs CISA Vulnrichment

`baseline` = always predicting CISA's most common value in this sample.

| point | model | n | agree_pct | baseline_pct |
|---|---|---|---|---|
| automatable | clef-flash | 331 | 73.1 | 74.3 |
| automatable | clef | 331 | 75.8 | 74.3 |
| exploitation | clef-flash | 331 | 85.8 | 80.4 |
| exploitation | clef | 331 | 86.1 | 80.4 |
| technical_impact | clef-flash | 331 | 80.1 | 59.5 |
| technical_impact | clef | 331 | 83.4 | 59.5 |

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
| mitre | 1011 | 73.0 | vuln_type, affected_product |
| apache | 454 | 4.4 | vuln_type |
| ibm | 794 | 1.0 | vuln_type |
| redhat | 497 | 1.0 | vuln_type |
| CIRCL | 166 | 0.6 | affected_status |
| Chrome | 874 | 0 |  |
| jpcert | 111 | 0 |  |
| GitHub_M | 2836 | 0 |  |
| icscert | 160 | 0 |  |
| adobe | 318 | 0 |  |
| VulDB | 1587 | 0 |  |
| EEF | 163 | 0 |  |


Judgment-based rules (Clef, sampled CVEs; % with p ≥ 0.5):

| model | multi_vuln_4_2_11 | credits_5_2_4 | irrelevant_5_2_6 | hosted_only_5_1_11 |
|---|---|---|---|---|
| clef-flash | 4.7 | 1.7 | 0 | 0.3 |
| clef | 6.0 | 1.3 | 0.3 | 0 |

## Clef vs Clef Flash

How often the two models give the same answer on the same question:

| pack | n | same_answer_pct | flash_ms | clef_ms |
|---|---|---|---|---|
| cvss31 | 1200 | 81.3 | 1211.0 | 4592.0 |
| cvss40 | 1650 | 84.2 | 1633.0 | 6072.0 |
| cwe_verify | 280 | 87.9 | 582.0 | 1919.0 |
| quality | 7619 | 92.6 | 3120.0 | 11341.0 |

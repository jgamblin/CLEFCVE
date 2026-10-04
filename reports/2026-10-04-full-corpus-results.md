# CLEFCVE results

Generated 2026-10-04 09:40 UTC from cvelistV5 `70f91a3c4fb4` (HEAD 2026-10-03 08:55 UTC), 60-day window.

The tool does three things: deterministic rule checks on every record, and two Clef questions about the description: does it establish a security impact, and how clear is it.

**Coverage:** clef-flash has answered the core questions for 27,489 of 27,489 published CVEs (100%), in random order, so partial results are a random sample.

## Rule checks: CNA Operational Rules 4.1.0 (full corpus, no model)

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
| desc_min_length | 5.1.1 | SHOULD | 6 | 27489 | 0 |
| desc_not_only_diff | 5.2.7 | SHOULD NOT | 3 | 27489 | 0 |
| affected_status | 5.1.4 | MUST | 10 | 27489 | 0 |
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
| Wordfence | 773 | 0 |  |
| jpcert | 111 | 0 |  |
| apple | 295 | 0 |  |
| GitHub_M | 2836 | 0 |  |
| oracle | 1524 | 0 |  |
| WPScan | 1039 | 0 |  |
| dell | 276 | 0 |  |

## Q1: Does the description establish a security impact?

Rephrased from "is this a vulnerability?" after the first run: the text alone couldn't separate CVEs later rejected as invalid from valid ones (p = 0.93 vs 0.89), because the reasons for rejection are rarely visible in the description. Rejected records use their last published text from git history.

| grp | model | n | mean_p_impact | pct_no_impact_stated |
|---|---|---|---|---|
| published | clef-flash | 27489 | 0.696 | 21.3 |
| published | clef | 2868 | 0.542 | 45.5 |
| rejected_duplicate | clef-flash | 30 | 0.693 | 16.7 |
| rejected_duplicate | clef | 30 | 0.824 | 16.7 |
| rejected_invalid | clef-flash | 23 | 0.846 | 4.3 |
| rejected_invalid | clef | 23 | 0.911 | 4.3 |
| rejected_other | clef-flash | 48 | 0.612 | 33.3 |
| rejected_other | clef | 48 | 0.667 | 33.3 |


How the impact is supported (`impact_basis`), published CVEs:

| model | basis | n | pct |
|---|---|---|---|
| clef-flash | stated_explicitly | 15210 | 55.3 |
| clef-flash | bug_fix_only | 7686 | 28.0 |
| clef-flash | implied_by_weakness | 4216 | 15.3 |
| clef-flash | not_security_relevant | 335 | 1.2 |
| clef-flash | insufficient_information | 42 | 0.2 |
| clef | bug_fix_only | 1011 | 35.3 |
| clef | implied_by_weakness | 931 | 32.5 |
| clef | stated_explicitly | 836 | 29.1 |
| clef | not_security_relevant | 61 | 2.1 |
| clef | insufficient_information | 29 | 1.0 |


The cascade: Flash reads everything, Clef 27B re-checks Flash's "no impact" calls.

| linux | answered | flash_no_impact | rechecked_by_27b | overturned | overturned_pct |
|---|---|---|---|---|---|
| False | 23736 | 2187 | 2187 | 1198 | 54.8 |
| True | 3753 | 3680 | 333 | 19 | 5.7 |


By CNA: share of descriptions with no security impact established (cascade, ≥ 25 answered CVEs):

| assigner | n | pct_no_impact_stated | flash_only_pct |
|---|---|---|---|
| Linux | 3753 | 97.5 | 98.1 |
| Tanium | 30 | 93.3 | 93.3 |
| qualcomm | 31 | 71.0 | 83.9 |
| mozilla | 250 | 57.6 | 70.8 |
| vmware | 99 | 29.3 | 43.4 |
| drupal | 43 | 27.9 | 27.9 |
| eclipse | 65 | 21.5 | 38.5 |
| cisco | 254 | 20.9 | 20.9 |
| apache | 454 | 16.3 | 26.4 |
| HCL | 63 | 14.3 | 25.4 |
| CPANSec | 74 | 13.5 | 40.5 |
| Arista | 46 | 13.0 | 28.3 |
| JetBrains | 85 | 11.8 | 16.5 |
| mitre | 1011 | 11.4 | 17.1 |
| apple | 295 | 10.2 | 42.7 |
| OX | 25 | 8.0 | 12.0 |
| bcorg | 38 | 7.9 | 36.8 |
| hackerone | 65 | 7.7 | 9.2 |
| TuranSec | 163 | 7.4 | 11.0 |
| rapid7 | 28 | 7.1 | 14.3 |
| VulDB | 1587 | 6.7 | 9.8 |
| Gitea | 47 | 6.4 | 23.4 |
| Zohocorp | 36 | 5.6 | 8.3 |
| Secur0 | 26 | 3.8 | 3.8 |
| openjs | 54 | 3.7 | 16.7 |


Published CVEs where Clef 27B finds the least stated impact:

| cve_id | assigner | p_impact | basis | description |
|---|---|---|---|---|
| CVE-2026-72032 | Linux | 0.031 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

net/mlx5: HWS, fix matcher leak on resize target se |
| CVE-2026-72271 | Linux | 0.032 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

fbdev: i740fb: fix potential memory leak in i740fb_ |
| CVE-2026-68227 | Linux | 0.035 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

media: cx231xx: fix devres lifetime

USB drivers bi |
| CVE-2026-68410 | Linux | 0.035 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

wifi: libertas: fix memory leak in helper_firmware_ |
| CVE-2026-68345 | Linux | 0.036 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

arm_mpam: guard MBWU state before adding it to garb |
| CVE-2026-72258 | Linux | 0.037 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

ASoC: mediatek: mt8183: Release reserved memory on  |
| CVE-2026-72167 | Linux | 0.038 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

mtd: rawnand: pl353: fix probe resource allocation
 |
| CVE-2026-72308 | Linux | 0.038 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

mlxsw: fix refcount leak in mlxsw_sp_port_lag_join( |
| CVE-2026-89644 | Linux | 0.038 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

btrfs: fix extent map leak in NOCOW direct I/O writ |
| CVE-2026-90027 | Linux | 0.038 | bug_fix_only | In the Linux kernel, the following vulnerability has been resolved:

usb: typec: qcom-pmic-typec: disable cc_debounce_dw |

## Q2: How clear is the description?

`clarity` is the expected level on Clef's 0-4 scale (Unusable, Poor, Adequate, Good, Excellent). `commit_msg` = reads as a developer commit message rather than a vulnerability description.

| model | n | clarity | poor_or_worse_pct | good_or_better_pct | commit_msg_pct |
|---|---|---|---|---|---|
| clef-flash | 27489 | 2.7 | 0.7 | 69.7 | 18.3 |
| clef | 2868 | 2.6 | 2.3 | 55.1 | 10.5 |


By CNA (clef-flash, CNAs with ≥ 25 answered CVEs):

| assigner | n | clarity | commit_msg_pct |
|---|---|---|---|
| qualcomm | 31 | 1.7 | 100.0 |
| Tanium | 30 | 1.9 | 100.0 |
| Linux | 3753 | 1.9 | 100.0 |
| mozilla | 250 | 1.9 | 71.0 |
| Gitea | 47 | 1.9 |  |
| HCL | 63 | 2.1 | 0 |
| JFROG | 43 | 2.3 | 0 |
| apple | 295 | 2.3 | 91.0 |
| intel | 71 | 2.3 |  |
| drupal | 43 | 2.3 |  |
| OX | 25 | 2.4 |  |
| Google_Devices | 99 | 2.4 | 0 |
| Foxit | 33 | 2.4 | 0 |
| JetBrains | 85 | 2.4 | 100.0 |
| Arista | 46 | 2.4 | 0 |
| nvidia | 219 | 2.4 | 0 |
| microsoft | 1456 | 2.5 | 0 |
| google_android | 90 | 2.5 | 0 |
| TR-CERT | 114 | 2.5 | 0 |
| sap | 53 | 2.5 | 0 |
| vmware | 99 | 2.5 |  |
| adobe | 318 | 2.5 | 0 |
| mongodb | 126 | 2.5 | 0 |
| VulDB | 1587 | 2.5 | 3.0 |
| Patchstack | 943 | 2.6 | 0 |
| Ubiquiti | 29 | 2.6 |  |
| twcert | 44 | 2.6 | 0 |
| jpcert | 111 | 2.6 | 0 |
| rapid7 | 28 | 2.6 | 0 |
| icscert | 160 | 2.6 | 0 |
| freebsd | 32 | 2.6 |  |
| WSO2 | 26 | 2.6 |  |
| elastic | 102 | 2.6 | 0 |
| wikimedia-foundation | 45 | 2.7 |  |
| hpe | 165 | 2.7 | 0 |
| eclipse | 65 | 2.7 | 25.0 |
| hackerone | 65 | 2.7 | 0 |
| SamsungMobile | 57 | 2.7 | 0 |
| cisa-cg | 99 | 2.7 | 0 |
| INCIBE | 56 | 2.7 | 0 |
| cisco | 254 | 2.8 | 11.0 |
| GitLab | 113 | 2.8 | 50.0 |
| fedora | 27 | 2.8 | 0 |
| Zohocorp | 36 | 2.8 | 0 |
| TYPO3 | 27 | 2.8 | 0 |
| ibm | 794 | 2.8 | 5.0 |
| certcc | 46 | 2.8 | 0 |
| redhat | 497 | 2.8 | 0 |
| CPANSec | 74 | 2.8 | 0 |
| apache | 454 | 2.8 | 10.0 |
| WatchGuard | 51 | 2.8 |  |
| bcorg | 38 | 2.8 | 100.0 |
| mitre | 1011 | 2.8 | 12.0 |
| suse | 53 | 2.9 | 0 |
| TuranSec | 163 | 2.9 | 0 |
| Joomla | 189 | 2.9 | 25.0 |
| Chrome | 874 | 2.9 | 0 |
| CERTVDE | 39 | 2.9 | 0 |
| PostgreSQL | 40 | 2.9 |  |
| Fluid Attacks | 27 | 2.9 | 0 |
| Mattermost | 36 | 2.9 | 0 |
| GV | 27 | 2.9 |  |
| jenkins | 76 | 3.0 | 0 |
| AMZN | 63 | 3.0 | 0 |
| GitHub_M | 2836 | 3.0 | 23.0 |
| zdi | 62 | 3.0 |  |
| dell | 276 | 3.0 | 0 |
| CERT-PL | 69 | 3.0 | 0 |
| canonical | 28 | 3.0 |  |
| openssl | 25 | 3.0 |  |
| TPLink | 47 | 3.0 | 0 |
| openjs | 54 | 3.0 | 0 |
| NCSC.ch | 33 | 3.0 |  |
| siemens | 33 | 3.0 | 0 |
| EEF | 163 | 3.1 | 50.0 |
| WPScan | 1039 | 3.1 | 0 |
| VulnCheck | 2874 | 3.1 | 3.0 |
| CIRCL | 166 | 3.1 | 0 |
| Secur0 | 26 | 3.2 | 0 |
| ConcreteCMS | 65 | 3.2 | 0 |
| Nozomi | 28 | 3.2 |  |
| zephyr | 79 | 3.2 | 100.0 |
| Wordfence | 773 | 3.3 | 0 |
| oracle | 1524 | 3.3 | 0 |


Lowest-clarity descriptions (clef-flash):

| cve_id | assigner | clarity | description |
|---|---|---|---|
| CVE-2026-40018 | OX | 0.57 | None None None No publicly available exploits are known. |
| CVE-2026-40204 | OX | 0.57 | None None None No publicly available exploits are known. |
| CVE-2026-84135 | mozilla | 0.93 | Other issue in Firefox Focus for Android. This vulnerability was fixed in Firefox 155. |
| CVE-2026-100810 | mozilla | 1.1 | Other issue in the DevTools component. This vulnerability was fixed in Thunderbird 157 and Firefox 157. |
| CVE-2026-84134 | mozilla | 1.1 | Other issue in the Profile Backup component. This vulnerability was fixed in Firefox 155, Firefox ESR 153.2, Thunderbird 155, and Thunderbir |
| CVE-2026-93309 | VulDB | 1.2 | A vulnerability was determined in O-RAN-SC SMO OAM 2025-06-10. Affected by this issue is some unknown functionality of the component VES Col |
| CVE-2026-49314 | huawei | 1.2 | OOB write vulnerability in the rendering and composition module.
Impact: Successful exploitation of this vulnerability may affect availabili |
| CVE-2026-76756 | drupal | 1.2 | Vulnerability in Drupal Gammu SMS Daemon. This issue affects Gammu SMS Daemon versions: *.*. |

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

## Clef 27B vs Clef Flash

How often the two models give the same answer on the same CVE (clarity: within half a level):

| question | n | same_answer_pct | flash_ms | clef_ms |
|---|---|---|---|---|
| desc_clarity | 529 | 89.2 | 3146.0 | 11436.0 |
| desc_is_commit_message | 529 | 91.7 | 3146.0 | 11436.0 |
| impact_basis | 2969 | 56.2 | 954.0 | 4365.0 |
| security_impact_stated | 2969 | 58.8 | 954.0 | 4365.0 |

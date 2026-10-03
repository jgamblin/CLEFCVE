import json

from clefcve.lint import cvss4_base_vector, lint_record

CATALOG = {"CWE-79": {"kind": "weakness", "usage": "Allowed"},
           "CWE-20": {"kind": "weakness", "usage": "Discouraged"},
           "CWE-1035": {"kind": "category", "usage": "Prohibited"}}


def run(desc="Stored XSS in the Foo plugin for WordPress before 1.2 allows attackers to inject script.",
        affected=None, refs=("https://example.com/advisory",), cwes=(), metrics=(), cve_id="CVE-2026-0001"):
    if affected is None:
        affected = [{"vendor": "Foo", "product": "Foo",
                     "versions": [{"version": "0", "lessThan": "1.2", "status": "affected"}]}]
    record = {"containers": {"cna": {
        "descriptions": [{"lang": "en", "value": desc}],
        "affected": affected,
        "references": [{"url": u} for u in refs]}}}
    cve = {"cve_id": cve_id, "description": desc, "record": json.dumps(record)}
    return {c: s for c, s, _ in lint_record(cve, list(cwes), list(metrics), CATALOG)}


def test_clean_record_passes_core_checks():
    r = run(cwes=[{"cwe_id": "CWE-79", "description": "CWE-79 Cross-site Scripting"}])
    for check in ("desc_present", "affected_product", "affected_status", "fixed_version",
                  "vuln_type", "cwe_structured", "cwe_mapping_allowed", "reference_not_self"):
        assert r[check] == "pass", check


def test_cvss4_base_ignores_threat_metrics():
    vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P"
    assert cvss4_base_vector(vec) == vec.removesuffix("/E:P")
    r = run(metrics=[{"version": "4.0", "vector": vec, "base_score": 5.3, "severity": "MEDIUM"}])
    assert r["cvss_score_matches"] == "pass"


def test_cvss31_temporal_score_in_base_field_fails():
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L/E:P/RL:O/RC:C"  # base 9.6
    r = run(metrics=[{"version": "3.1", "vector": vec, "base_score": 9.1, "severity": "CRITICAL"}])
    assert r["cvss_vector_valid"] == "pass" and r["cvss_score_matches"] == "fail"


def test_cwe_problems():
    assert run(cwes=[{"cwe_id": None, "description": "CWE-79 XSS"}])["cwe_not_text_only"] == "fail"
    assert run(cwes=[{"cwe_id": None, "description": "n/a"}])["vuln_type"] == "fail"
    assert run(cwes=[{"cwe_id": "CWE-20", "description": ""}])["cwe_mapping_allowed"] == "warn"
    assert run(cwes=[{"cwe_id": "CWE-1035", "description": ""}])["cwe_mapping_allowed"] == "fail"
    assert run(cwes=[{"cwe_id": "CWE-99999", "description": ""}])["cwe_known"] == "fail"


def test_affected_and_references():
    r = run(affected=[{"vendor": "Unknown", "product": "Foo", "versions": [{"version": "1.0", "status": "affected"}]}])
    assert r["affected_product"] == "pass" and r["affected_vendor"] == "warn" and r["fixed_version"] == "fail"
    assert run(affected=[{"vendor": "n/a", "product": "n/a", "defaultStatus": "affected"}])["affected_product"] == "fail"
    assert run(affected=[{"vendor": "Foo", "product": "Foo", "defaultStatus": "unaffected"}])["affected_status"] == "fail"
    assert run(refs=["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"])["reference_not_self"] == "fail"


def test_heuristic_description_warnings():
    assert run(desc="XSS in Foo. Reported by Jane Doe of Acme Labs.")["desc_no_credits"] == "warn"
    assert run(desc="XSS in Foo, see GHSA-2c8m-7xqr-9p4w for details.")["desc_no_other_ids"] == "warn"

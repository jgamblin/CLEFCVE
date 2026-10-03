import json
import subprocess
from datetime import timezone

from clefcve.gitrepo import BlobReader, changed_paths, head_info
from clefcve.ingest import last_published_version
from clefcve.normalize import normalize, parse_ts


def record(state="PUBLISHED", desc="SQL injection in Foo 1.0 lets remote attackers run SQL."):
    meta = {"cveId": "CVE-2026-0001", "state": state, "assignerShortName": "example",
            "datePublished": "2026-09-01T00:00:00.000Z"}
    if state == "REJECTED":
        meta["dateRejected"] = "2026-09-10T00:00:00"  # no offset, as in some real records
        return {"cveMetadata": meta, "containers": {"cna": {
            "rejectedReasons": [{"lang": "en", "value": "Not a vulnerability."}]}}}
    return {"cveMetadata": meta, "containers": {
        "cna": {
            "descriptions": [{"lang": "es", "value": "otro"}, {"lang": "en-US", "value": desc}],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-89", "description": "SQLi", "lang": "en"}]}],
            "metrics": [{"cvssV3_1": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                      "baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
            "references": [{"url": "https://example.com/advisory", "tags": ["vendor-advisory"]}],
            "affected": [{"vendor": "Foo", "product": "Foo", "versions": [{"version": "1.0", "status": "affected"}]}],
        },
        "adp": [{
            "providerMetadata": {"shortName": "CISA-ADP"},
            "metrics": [
                {"other": {"type": "ssvc", "content": {"timestamp": "2026-09-02T00:00:00Z", "options": [
                    {"Exploitation": "none"}, {"Automatable": "yes"}, {"Technical Impact": "total"}]}}},
                {"other": {"type": "kev", "content": {"dateAdded": "2026-09-03"}}},
            ],
        }],
    }}


def test_parse_ts_assumes_utc_when_offset_missing():
    assert parse_ts("2026-09-10T00:00:00").tzinfo == timezone.utc
    assert parse_ts(None) is None


def test_normalize_published():
    r = record()
    rows = normalize(r, r, path="p.json", content_sha256="abc")
    cve = rows["cves"][0]
    assert cve["description"].startswith("SQL injection")  # English picked over Spanish
    assert cve["rejected_reason"] is None
    assert rows["cwes"] == [{"cve_id": "CVE-2026-0001", "source": "cna", "cwe_id": "CWE-89", "description": "SQLi"}]
    assert rows["metrics"][0]["version"] == "3.1" and rows["metrics"][0]["base_score"] == 9.8
    ssvc = rows["ssvc"][0]
    assert (ssvc["source"], ssvc["exploitation"], ssvc["automatable"], ssvc["technical_impact"]) == \
        ("CISA-ADP", "none", "yes", "total")
    assert rows["kev"][0]["date_added"] == "2026-09-03"
    assert rows["refs"][0]["tags"] == ["vendor-advisory"]


def test_normalize_rejected_uses_original_content():
    rows = normalize(record("REJECTED"), record(), path="p.json", content_sha256="abc", original_commit="c1")
    cve = rows["cves"][0]
    assert cve["state"] == "REJECTED"
    assert cve["rejected_reason"] == "Not a vulnerability."
    assert cve["description"].startswith("SQL injection")
    assert cve["date_rejected"].tzinfo == timezone.utc
    assert cve["original_commit"] == "c1"


def _commit(repo, path, rec, msg):
    f = repo / path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(rec))
    subprocess.run(["git", "-C", repo, "add", "-A"], check=True)
    subprocess.run(["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", msg],
                   check=True)


def test_recovers_last_published_version_from_history(tmp_path):
    subprocess.run(["git", "init", "-q", tmp_path], check=True)
    path = "cves/2026/0xxx/CVE-2026-0001.json"
    _commit(tmp_path, path, record(desc="first"), "publish")
    _commit(tmp_path, path, record(desc="second"), "update")
    _commit(tmp_path, path, record("REJECTED"), "reject")
    _commit(tmp_path, "cves/delta.json", {}, "not a record")

    _, head_time = head_info(tmp_path)
    paths = changed_paths(tmp_path, head_time.replace(year=2000))
    assert list(paths) == [path] and len(paths[path]) == 3

    with BlobReader(tmp_path) as reader:
        rec, raw, commit = last_published_version(reader, path, paths[path])
        assert reader.read(f"HEAD:cves/missing.json") is None
    assert rec["containers"]["cna"]["descriptions"][1]["value"] == "second"
    assert commit == paths[path][0]  # the rejecting commit

"""Stage 2: deterministic checks (no model) against CNA Operational Rules 4.1.0 and data formats.

Usage: python -m clefcve.lint [--db data/clefcve.duckdb]

Writes `lint` (one row per CVE x check) and `cwe_catalog`. Statuses: pass | fail | warn | na.
`warn` marks heuristic checks (regex) whose failures need review rather than being definitive.
"""

import argparse
import json
import re
from dataclasses import dataclass

import duckdb
import pyarrow as pa
from cvss import CVSS2, CVSS3, CVSS4

from . import config, cwe


@dataclass(frozen=True)
class Check:
    check_id: str
    rule: str   # CNA Operational Rules 4.1.0 section, or "format" for data-quality checks
    level: str  # MUST | SHOULD | MUST NOT | SHOULD NOT | format
    summary: str


CHECKS = {c.check_id: c for c in [
    Check("desc_present", "5.1.9", "MUST", "Has a prose description"),
    Check("desc_english", "5.2.5", "MUST", "Has an English description"),
    Check("desc_min_length", "5.1.1", "SHOULD", "Description is at least 50 characters"),
    Check("desc_unique", "5.1.1", "SHOULD", "Description text is not identical to another CVE's"),
    Check("desc_no_credits", "5.2.4", "MUST NOT", "Description doesn't credit people/orgs/tools (heuristic)"),
    Check("desc_no_other_ids", "5.2.11", "SHOULD NOT", "Description has no non-CVE vulnerability IDs (heuristic)"),
    Check("desc_not_only_diff", "5.2.7", "SHOULD NOT", "Description isn't only 'different than CVE-X' (heuristic)"),
    Check("affected_product", "5.1.3", "MUST", "Identifies at least one affected product by name"),
    Check("affected_vendor", "5.1.3", "SHOULD", "Names the supplier/vendor of an affected product"),
    Check("affected_status", "5.1.4", "MUST", "At least one product is affected or unknown (5.1.8)"),
    Check("fixed_version", "5.1.5", "SHOULD", "Identifies fixed versions"),
    Check("vuln_type", "5.1.7", "MUST", "Identifies the vulnerability type (problemTypes)"),
    Check("cwe_structured", "5.1.7", "SHOULD", "Uses a structured CWE ID"),
    Check("cwe_not_text_only", "format", "format", "CWE isn't only written in free text without cweId"),
    Check("cwe_known", "format", "format", "CWE ID exists in the CWE catalog"),
    Check("cwe_mapping_allowed", "5.1.7", "SHOULD", "CWE mapping usage isn't Prohibited/Discouraged"),
    Check("cwe_text_matches_id", "format", "format", "CWE named in text matches cweId"),
    Check("reference_present", "5.1.10", "MUST", "Has at least one public reference"),
    Check("reference_not_self", "5.3.3.5", "MUST NOT", "Has a reference that isn't the CVE record itself"),
    Check("cvss_present", "format", "format", "Has a CNA CVSS score (not required by rules)"),
    Check("cvss_vector_valid", "format", "format", "CVSS vector parses"),
    Check("cvss_score_matches", "format", "format", "CVSS base score matches the vector's base metrics"),
    Check("cvss_severity_matches", "format", "format", "CVSS severity matches the score"),
]}

NA_VALUES = {"", "n/a", "na", "none", "unknown", "-"}
CREDIT_RE = re.compile(
    r"\b(reported|discovered|found|identified|credited)\s+by\b|\bthanks?\s+to\b|\bcredits?\s+(to|go)\b", re.I)
OTHER_ID_RE = re.compile(
    r"\b(GHSA(-[23456789cfghjmpqrvwx]{4}){3}|ZDI-(CAN-)?\d{2,}-?\d*|VDB-\d+|JVN#?\d+|TALOS-\d{4}-\d+|"
    r"SNYK-[A-Z]+-[A-Z0-9-]+|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+|GO-\d{4}-\d+|OSV-\d{4}-\d+)\b")
DIFF_ONLY_RE = re.compile(r"different\s+(vulnerability\s+)?than\s+CVE-\d{4}-\d+", re.I)
CWE_TEXT_RE = re.compile(r"\bCWE-(\d+)\b")
SELF_REF_RE = r"(cve\.org/CVERecord\?id=|nvd\.nist\.gov/vuln/detail/|cve\.mitre\.org/cgi-bin/cvename\.cgi\?name=){id}\b"

CVSS_CLASSES = {"2.0": CVSS2, "3.0": CVSS3, "3.1": CVSS3, "4.0": CVSS4}
CVSS4_BASE = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


def cvss4_base_vector(vector: str) -> str:
    """Drop threat/environmental/supplemental metrics so the score is CVSS-B, not CVSS-BT/BE."""
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
    return "CVSS:4.0/" + "/".join(f"{k}:{parts[k]}" for k in CVSS4_BASE if k in parts)


def _status(ok: bool, fail: str = "fail") -> str:
    return "pass" if ok else fail


def _cvss_findings(m: dict) -> list[tuple[str, str, str]]:
    """(check, status, detail) for one CNA CVSS metric block."""
    version, vector, score, severity = m["version"], m["vector"], m["base_score"], m["severity"]
    try:
        c = CVSS_CLASSES[version](vector)
    except Exception as e:  # cvss raises several exception types for malformed vectors
        return [("cvss_vector_valid", "fail", f"v{version} {vector!r}: {e}")]
    out = [("cvss_vector_valid", "pass", f"v{version}")]
    if version == "4.0":
        base = CVSS4(cvss4_base_vector(vector))
        calc_score, calc_sev = base.base_score, base.severity
    elif version == "2.0":
        calc_score, calc_sev = c.scores()[0], None  # v2 has no official severity bands
    else:
        calc_score, calc_sev = c.scores()[0], c.severities()[0]
    calc_score = float(calc_score)
    if score is None:
        out.append(("cvss_score_matches", "na", f"v{version} no baseScore"))
    else:
        out.append(("cvss_score_matches", _status(abs(calc_score - score) < 0.05),
                    f"v{version} stated {score} computed {calc_score} {vector}"))
    if calc_sev and severity:
        out.append(("cvss_severity_matches", _status(severity.upper() == calc_sev.upper()),
                    f"v{version} stated {severity} computed {calc_sev}"))
    return out


def lint_record(cve: dict, cna_cwes: list[dict], cna_metrics: list[dict], catalog: dict) -> list[tuple[str, str, str]]:
    """Return (check, status, detail) tuples for one CVE."""
    rec = json.loads(cve["record"])
    cna = rec.get("containers", {}).get("cna", {})
    desc = cve["description"] or ""
    out = []

    descs = cna.get("descriptions", [])
    out.append(("desc_present", _status(bool(desc.strip())), ""))
    out.append(("desc_english", _status(any(d.get("lang", "").lower().startswith("en") for d in descs)),
                ",".join(d.get("lang", "") for d in descs)))
    out.append(("desc_min_length", _status(len(desc.strip()) >= 50), f"{len(desc.strip())} chars"))
    m = CREDIT_RE.search(desc)
    out.append(("desc_no_credits", _status(not m, "warn"), m.group(0) if m else ""))
    m = OTHER_ID_RE.search(desc)
    out.append(("desc_no_other_ids", _status(not m, "warn"), m.group(0) if m else ""))
    m = DIFF_ONLY_RE.search(desc)
    out.append(("desc_not_only_diff", _status(not m, "warn"), m.group(0) if m else ""))

    affected = cna.get("affected", [])
    named = [a for a in affected
             if (a.get("product") or a.get("packageName") or "").strip().lower() not in NA_VALUES]
    out.append(("affected_product", _status(bool(named)), f"{len(affected)} entries, {len(named)} named"))
    vendors = {(a.get("vendor") or "").strip() for a in named} - {""}
    out.append(("affected_vendor", _status(any(v.lower() not in NA_VALUES for v in vendors), "warn")
                if named else "na", ",".join(sorted(vendors))[:80]))
    statuses = {a.get("defaultStatus") for a in affected} | {
        v.get("status") for a in affected for v in a.get("versions", [])}
    out.append(("affected_status", _status(bool(statuses & {"affected", "unknown"})),
                ",".join(sorted(s for s in statuses if s))))
    has_fix = any(v.get("lessThan") or v.get("status") == "unaffected" or v.get("changes")
                  for a in affected for v in a.get("versions", []))
    out.append(("fixed_version", _status(has_fix), ""))

    structured = [c["cwe_id"] for c in cna_cwes if c["cwe_id"]]
    texts = [c["description"] or "" for c in cna_cwes]
    out.append(("vuln_type", _status(bool(structured or any(t.strip().lower() not in NA_VALUES for t in texts))),
                ""))
    out.append(("cwe_structured", _status(bool(structured)), ",".join(structured)))
    text_ids = {f"CWE-{n}" for t in texts for n in CWE_TEXT_RE.findall(t)}
    out.append(("cwe_not_text_only", _status(bool(structured) or not text_ids),
                ",".join(sorted(text_ids))))
    for cwe_id in structured:
        entry = catalog.get(cwe_id)
        out.append(("cwe_known", _status(entry is not None), cwe_id))
        if entry:
            usage = entry["usage"]
            status = "fail" if usage == "Prohibited" else "warn" if usage == "Discouraged" else "pass"
            out.append(("cwe_mapping_allowed", status, f"{cwe_id} {entry['kind']} {usage}"))
    for c in cna_cwes:
        named_ids = CWE_TEXT_RE.findall(c["description"] or "")
        if c["cwe_id"] and named_ids:
            out.append(("cwe_text_matches_id", _status(f"CWE-{named_ids[0]}" == c["cwe_id"]),
                        f"{c['cwe_id']} vs text {c['description'][:80]!r}"))

    refs = [r.get("url", "") for r in cna.get("references", [])]
    self_re = re.compile(SELF_REF_RE.format(id=re.escape(cve["cve_id"])), re.I)
    out.append(("reference_present", _status(bool(refs)), f"{len(refs)} refs"))
    out.append(("reference_not_self", _status(any(not self_re.search(u) for u in refs)), ""))

    out.append(("cvss_present", _status(bool(cna_metrics), "na"), ",".join(m["version"] for m in cna_metrics)))
    for m in cna_metrics:
        out.extend(_cvss_findings(m))
    return out


def run(con: duckdb.DuckDBPyConnection) -> int:
    cwe_version = cwe.load(con)
    catalog = {r[0]: {"kind": r[1], "usage": r[2]} for r in
               con.execute("SELECT cwe_id, kind, usage FROM cwe_catalog").fetchall()}

    cwes_by, metrics_by = {}, {}
    for cve_id, cwe_id, desc in con.execute(
            "SELECT cve_id, cwe_id, description FROM cwes WHERE source = 'cna'").fetchall():
        cwes_by.setdefault(cve_id, []).append({"cwe_id": cwe_id, "description": desc})
    for cve_id, version, vector, score, sev in con.execute(
            "SELECT cve_id, version, vector, base_score, severity FROM metrics WHERE source = 'cna'").fetchall():
        metrics_by.setdefault(cve_id, []).append(
            {"version": version, "vector": vector, "base_score": score, "severity": sev})

    rows = []
    cur = con.execute("SELECT cve_id, description, record FROM cves WHERE state = 'PUBLISHED'")
    cols = [d[0] for d in cur.description]
    for values in cur.fetchall():
        cve = dict(zip(cols, values))
        for check, status, detail in lint_record(
                cve, cwes_by.get(cve["cve_id"], []), metrics_by.get(cve["cve_id"], []), catalog):
            c = CHECKS[check]
            rows.append({"cve_id": cve["cve_id"], "check_id": check, "rule": c.rule, "level": c.level,
                         "status": status, "detail": detail})

    arrow = pa.Table.from_pylist(rows)  # noqa: F841 (referenced by name in SQL)
    con.execute("CREATE OR REPLACE TABLE lint AS SELECT * FROM arrow")
    # Corpus-level check: identical description text shared across CVEs.
    con.execute("""
        INSERT INTO lint
        SELECT c.cve_id, 'desc_unique', '5.1.1', 'SHOULD',
               CASE WHEN d.n > 1 THEN 'fail' ELSE 'pass' END,
               CASE WHEN d.n > 1 THEN d.n || ' CVEs share this description' ELSE '' END
        FROM cves c JOIN (SELECT description, count(*) n FROM cves WHERE state = 'PUBLISHED'
                          GROUP BY 1) d USING (description)
        WHERE c.state = 'PUBLISHED'
    """)
    checks = pa.Table.from_pylist([vars(c) for c in CHECKS.values()])  # noqa: F841
    con.execute("CREATE OR REPLACE TABLE lint_checks AS SELECT * FROM checks")
    print(f"CWE catalog v{cwe_version}")
    return len(rows)


SUMMARY_SQL = """
SELECT check_id, rule, level,
       count(*) FILTER (status = 'fail') AS fail,
       count(*) FILTER (status = 'warn') AS warn,
       count(*) FILTER (status IN ('pass', 'fail', 'warn')) AS evaluated,
       round(100.0 * count(*) FILTER (status IN ('fail', 'warn'))
             / nullif(count(*) FILTER (status IN ('pass', 'fail', 'warn')), 0), 1) AS pct_flagged
FROM lint GROUP BY ALL ORDER BY pct_flagged DESC
"""


def main(argv: list[str] | None = None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--db", default=str(config.DB_PATH))
    args = p.parse_args(argv)
    con = duckdb.connect(args.db)
    n = run(con)
    print(f"{n} lint rows")
    print(con.sql(SUMMARY_SQL))


if __name__ == "__main__":
    main()

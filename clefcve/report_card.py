"""Build the per-CNA report card page (reports/cna_report_card.html) from the corpus, lint, Clef answers and jury.

Usage: python -m clefcve.report_card [--min-cves 25]

Grades come only from deterministic checks over the full 60-day corpus, so every CNA is graded on all its
records. The two Clef columns (security impact stated, clarity) come from Clef Flash over the corpus, answered in
random order; Clef 27B on a random sample is the spot check. The shelved CVSS/CWE experiments get a short summary.
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .evaluate import INVALID_REASON_SQL
from .evaluate import CORPUS_MODEL, connect, load_jury, severity_section

TEMPLATE = Path(__file__).with_name("report_card.html")
OUT = config.PROJECT_ROOT / "reports" / "cna_report_card.html"

# Checks that make up the completeness score. Each is the share of a CNA's records that pass; "na" is excluded.
GRADED_CHECKS = {
    "vuln_type": "States the vulnerability type (5.1.7, MUST)",
    "affected_product": "Names an affected product (5.1.3, MUST)",
    "affected_status": "Marks a product affected/unknown (5.1.4, MUST)",
    "cwe_structured": "Uses a structured CWE ID (5.1.7, SHOULD)",
    "cwe_mapping_allowed": "CWE is not Prohibited/Discouraged (CWE guidance)",
    "fixed_version": "Identifies fixed versions (5.1.5, SHOULD)",
    "desc_unique": "Description not shared with another CVE (5.1.1, SHOULD)",
    "cvss_score_matches": "CVSS score matches its vector",
}
GRADES = [(95, "A"), (88, "B"), (80, "C"), (70, "D"), (0, "F")]
MIN_ANSWERED = 10  # Clef columns need at least this many answered CVEs for a CNA


def rows(con, sql, params=None):
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def build(min_cves: int) -> dict:
    con = connect(config.DB_PATH, config.ANSWERS_DB_PATH)
    run = rows(con, "SELECT repo_sha, repo_head_time, window_days, dev_slice_days FROM ingest_run")[0]
    checks_sql = ", ".join(f"'{c}'" for c in GRADED_CHECKS)

    cnas = rows(con, f"""
        WITH n AS (SELECT assigner, count(*) AS cves FROM cves WHERE state = 'PUBLISHED' GROUP BY 1 HAVING count(*) >= ?),
        chk AS (
            SELECT c.assigner, l.check_id,
                   avg((l.status = 'pass')::INT) FILTER (l.status <> 'na') AS pass_rate
            FROM lint l JOIN cves c USING (cve_id) WHERE l.check_id IN ({checks_sql}) GROUP BY ALL),
        per_cve AS (
            SELECT c.assigner, l.cve_id,
                   bool_or(l.status = 'fail' AND l.level IN ('MUST', 'MUST NOT')) AS must_fail,
                   bool_or(l.check_id = 'cvss_present' AND l.status = 'pass') AS has_cvss,
                   bool_or(l.check_id = 'cvss_score_matches' AND l.status = 'fail') AS cvss_mismatch
            FROM lint l JOIN cves c USING (cve_id) GROUP BY ALL),
        agg AS (
            SELECT assigner, avg(must_fail::INT) AS must_fail, avg(has_cvss::INT) AS has_cvss,
                   sum(cvss_mismatch::INT) AS cvss_mismatches
            FROM per_cve GROUP BY 1)
        SELECT n.assigner AS cna, n.cves, a.must_fail, a.has_cvss, a.cvss_mismatches,
               map(list(chk.check_id), list(chk.pass_rate)) AS checks
        FROM n JOIN agg a USING (assigner) JOIN chk USING (assigner)
        GROUP BY n.assigner, n.cves, a.must_fail, a.has_cvss, a.cvss_mismatches
    """, [min_cves])
    for c in cnas:
        c["checks"] = {k: v for k, v in c["checks"].items() if v is not None}
        c["score"] = round(100 * sum(c["checks"].values()) / len(c["checks"]), 1)
        c["grade"] = next(g for t, g in GRADES if c["score"] >= t)

    # Clef columns from the corpus run, where a CNA has enough answered CVEs.
    # Impact columns use the cascade (Flash, re-checked by 27B); clarity is Flash everywhere, so CNAs compare evenly.
    clef = {r["cna"]: r for r in rows(con, f"""
        WITH cl AS (SELECT cve_id, score FROM ans WHERE model = '{CORPUS_MODEL}' AND question_id = 'desc_clarity')
        SELECT c.assigner AS cna, count(*) AS answered, avg(cl.score) AS clarity,
               avg(i.no_impact::INT) AS no_impact, avg((i.flash_p < 0.5)::INT) AS flash_no_impact,
               avg((i.basis = 'bug_fix_only')::INT) AS bug_fix_only
        FROM impact_final i JOIN cves c USING (cve_id) JOIN cl USING (cve_id)
        WHERE c.state = 'PUBLISHED' GROUP BY 1""")}
    for c in cnas:
        r = clef.get(c["cna"])
        c["clef"] = r if r and r["answered"] >= MIN_ANSWERED else None
    cnas.sort(key=lambda c: -c["cves"])

    corpus = rows(con, """
        SELECT count(*) AS cves, count(DISTINCT assigner) AS cnas,
               (SELECT count(*) FROM cves WHERE state = 'REJECTED') AS rejected
        FROM cves WHERE state = 'PUBLISHED'""")[0]
    lint_summary = rows(con, """
        SELECT check_id, rule, level, count(*) FILTER (status IN ('fail', 'warn')) AS flagged,
               count(*) FILTER (status IN ('pass', 'fail', 'warn')) AS evaluated
        FROM lint GROUP BY ALL HAVING flagged > 0 ORDER BY flagged DESC""")

    coverage = rows(con, f"""
        WITH cl AS (SELECT cve_id, score, request_ms FROM ans
                    WHERE model = '{CORPUS_MODEL}' AND question_id = 'desc_clarity')
        SELECT count(*) AS answered, avg(i.no_impact::INT) AS no_impact,
               avg((i.flash_p < 0.5)::INT) AS flash_no_impact, avg(cl.score) AS clarity,
               avg((cl.score < 1.5)::INT) AS poor, avg((cl.score >= 2.5)::INT) AS good, median(cl.request_ms) AS ms
        FROM impact_final i JOIN cves c USING (cve_id) JOIN cl USING (cve_id) WHERE c.state = 'PUBLISHED'""")[0]
    # Share of all no-impact descriptions that come from each CNA.
    no_impact_share = rows(con, """
        SELECT assigner AS cna, count(*) AS n FROM impact_final JOIN cves USING (cve_id)
        WHERE state = 'PUBLISHED' AND no_impact GROUP BY 1 ORDER BY n DESC LIMIT 5""")
    basis = rows(con, """
        SELECT basis, count(*) AS n FROM impact JOIN cves USING (cve_id)
        WHERE state = 'PUBLISHED' AND basis IS NOT NULL GROUP BY 1 ORDER BY n DESC""")
    cascade = rows(con, """
        SELECT assigner = 'Linux' AS linux, count(*) FILTER (flash_p < 0.5) AS flash_flagged,
               count(*) FILTER (rechecked) AS rechecked, count(*) FILTER (rechecked AND clef_p >= 0.5) AS overturned,
               count(*) FILTER (clef_p IS NOT NULL) AS clef_checked,
               count(*) FILTER (clef_p IS NOT NULL AND (clef_p < 0.5) = (flash_p < 0.5)) AS clef_agrees
        FROM impact JOIN cves USING (cve_id) WHERE state = 'PUBLISHED' GROUP BY 1""")
    # Spot check: Clef 27B vs Flash on the same CVEs.
    spot = rows(con, """
        SELECT f.question_id AS question, count(*) AS n,
               avg(CASE WHEN f.type = 'noul' THEN ((f.p_true >= 0.5) = (c.p_true >= 0.5))::INT
                        ELSE (abs(f.score - c.score) < 0.5)::INT END) AS agree,
               avg(((f.p_true < 0.5) AND (c.p_true >= 0.5))::INT) AS flash_stricter
        FROM ans f JOIN ans c USING (cve_id, item, question_id)
        WHERE f.model = 'clef-flash' AND c.model = 'clef' AND f.question_id IN ('security_impact_stated', 'desc_clarity')
        GROUP BY 1""")
    rejected = rows(con, f"""
        SELECT avg(p_true) FILTER (state = 'PUBLISHED') AS published,
               avg(p_true) FILTER (state = 'REJECTED' AND {INVALID_REASON_SQL}) AS rejected_invalid
        FROM ans JOIN cves USING (cve_id) WHERE model = 'clef' AND question_id = 'is_vuln'""")[0]
    # One clear, impact-stating description and one fix log with no stated impact, as the page's examples.
    examples = rows(con, f"""
        WITH a AS (
            SELECT cve_id, max(p_true) FILTER (question_id = 'security_impact_stated') AS p_impact,
                   max(score) FILTER (question_id = 'desc_clarity') AS clarity
            FROM ans WHERE model = '{CORPUS_MODEL}' GROUP BY 1)
        (SELECT 'good' AS kind, cve_id, assigner AS cna, p_impact, clarity, description FROM a JOIN cves USING (cve_id)
         WHERE state = 'PUBLISHED' AND length(description) BETWEEN 200 AND 420 ORDER BY clarity DESC, p_impact DESC LIMIT 1)
        UNION ALL
        (SELECT 'weak', cve_id, assigner, p_impact, clarity, description FROM a JOIN cves USING (cve_id)
         WHERE state = 'PUBLISHED' AND assigner = 'Linux' AND length(description) < 600 ORDER BY p_impact LIMIT 1)""")
    lowest = rows(con, f"""
        SELECT cve_id, assigner AS cna, score AS clarity, description FROM ans JOIN cves USING (cve_id)
        WHERE model = '{CORPUS_MODEL}' AND state = 'PUBLISHED' AND question_id = 'desc_clarity'
          AND assigner <> 'Linux' ORDER BY score LIMIT 3""")

    # Shelved experiments: headline numbers only.
    severity_section(con)  # builds temp table `sev`
    bands = rows(con, """
        SELECT model, count(*) AS n, avg((upper(clef_sev) = upper(cna_sev))::INT) AS same_band
        FROM sev WHERE version = '3.1' GROUP BY model""")
    jury_n = load_jury(con)
    jury = {"n": jury_n}
    if jury_n:
        from .evaluate import jury_section
        jury_section(con)  # builds temp tables jury_cmp, jury_votes
        m = rows(con, """
            SELECT count(*) FILTER (clef >= cna) AS clef_tied_or_ahead, count(*) AS metrics, avg(clef) AS clef_avg
            FROM (SELECT field, avg((clef = jury)::INT) AS clef, avg((cna = jury)::INT) AS cna
                  FROM jury_cmp WHERE clef IS NOT NULL AND cna IS NOT NULL GROUP BY field)""")[0]
        loo = rows(con, """
            WITH loo AS (
                SELECT v.juror, v.value, (SELECT mode(o.value) FROM jury_votes o WHERE o.cve_id = v.cve_id
                                          AND o.field = v.field AND o.juror <> v.juror) AS others
                FROM jury_votes v WHERE v.field IN ('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'))
            SELECT min(a) AS lo, max(a) AS hi FROM (SELECT juror, avg((value = others)::INT) AS a FROM loo GROUP BY 1)""")[0]
        jurors = [r["juror"].split(":")[0] for r in rows(con, "SELECT DISTINCT juror FROM jury_votes ORDER BY 1")]
        jury |= m | {"juror_lo": loo["lo"], "juror_hi": loo["hi"], "jurors": jurors}
    cwe = rows(con, """
        SELECT avg((choice <> 'exact')::INT) AS not_exact FROM ans WHERE question_id = 'cwe_fit' AND model = 'clef'""")[0]
    cwe_examples = rows(con, """
        SELECT x.cve_id, cv.assigner AS cna, x.item AS cwe, k.name, cv.description
        FROM ans x JOIN cves cv USING (cve_id) LEFT JOIN cwe_catalog k ON k.cwe_id = x.item
        WHERE x.question_id = 'cwe_acceptable' AND x.model = 'clef' AND x.p_true < 0.5
          AND x.cve_id IN ('CVE-2026-69421', 'CVE-2026-49314')""")
    corpus_total = corpus["cves"]

    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "repo_sha": run["repo_sha"][:12], "repo_head": run["repo_head_time"].strftime("%Y-%m-%d"),
        "window_days": run["window_days"], "corpus": corpus, "min_cves": min_cves, "min_answered": MIN_ANSWERED,
        "graded_checks": GRADED_CHECKS, "cnas": cnas, "lint": lint_summary,
        "coverage": coverage | {"total": corpus_total}, "no_impact_share": no_impact_share, "basis": basis,
        "spot": spot, "lowest": lowest, "examples": examples, "cascade": cascade,
        "shelved": {"bands": bands, "jury": jury, "cwe_not_exact": cwe["not_exact"], "cwe_examples": cwe_examples,
                    "is_vuln": rejected},
    }


def main(argv: list[str] | None = None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--min-cves", type=int, default=25)
    p.add_argument("--out", type=Path, default=OUT)
    args = p.parse_args(argv)
    data = build(args.min_cves)
    payload = json.dumps(data, default=str).replace("</", "<\\/")  # safe inside a <script> tag
    html = TEMPLATE.read_text().replace("/*__DATA__*/null", payload)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(html)
    print(f"wrote {args.out} ({len(data['cnas'])} CNAs, {len(html) // 1024} KB)")


if __name__ == "__main__":
    main()

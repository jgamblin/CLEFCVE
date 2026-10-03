"""Build the per-CNA report card page (reports/cna_report_card.html) from the corpus, lint, Clef answers and jury.

Usage: python -m clefcve.report_card [--min-cves 25]

Grades come only from deterministic checks over the full 60-day corpus, so every CNA is graded on all its
records. Clef-based columns come from the random sample and are shown only where a CNA has ≥ 5 sampled CVEs.
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .evaluate import connect, cvss_section, load_jury, severity_section

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

    # Clef-based columns from the sample (Clef 27B), only where a CNA has enough sampled CVEs.
    severity_section(con)  # builds temp table `sev`
    sample = {r["cna"]: r for r in rows(con, """
        WITH q AS (
            SELECT assigner AS cna, count(DISTINCT cve_id) AS sample_n,
                   avg(score) FILTER (question_id = 'desc_clarity') AS clarity,
                   avg((p_true < 0.5)::INT) FILTER (question_id = 'security_impact_stated') AS no_impact,
                   avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_is_commit_message') AS commit_msg
            FROM ans JOIN cves USING (cve_id)
            WHERE model = 'clef' AND pack = 'quality' AND state = 'PUBLISHED' GROUP BY 1),
        s AS (SELECT assigner AS cna, count(*) AS sev_n, avg((upper(clef_sev) = upper(cna_sev))::INT) AS same_band,
                     avg(cna_score - clef_score) AS cna_minus_clef
              FROM sev JOIN cves USING (cve_id) WHERE model = 'clef' AND version = '3.1' GROUP BY 1)
        SELECT q.*, s.sev_n, s.same_band, s.cna_minus_clef FROM q LEFT JOIN s USING (cna)
    """)}
    for c in cnas:
        s = sample.get(c["cna"])
        c["sample"] = ({k: s[k] for k in ("sample_n", "clarity", "no_impact", "commit_msg")}
                       | ({"sev_n": s["sev_n"], "same_band": s["same_band"], "cna_minus_clef": s["cna_minus_clef"]}
                          if (s["sev_n"] or 0) >= 5 else {})) if s and s["sample_n"] >= 5 else None
    cnas.sort(key=lambda c: -c["cves"])

    corpus = rows(con, """
        SELECT count(*) AS cves, count(DISTINCT assigner) AS cnas,
               (SELECT count(*) FROM cves WHERE state = 'REJECTED') AS rejected
        FROM cves WHERE state = 'PUBLISHED'""")[0]
    lint_summary = rows(con, """
        SELECT check_id, rule, level, count(*) FILTER (status IN ('fail', 'warn')) AS flagged,
               count(*) FILTER (status IN ('pass', 'fail', 'warn')) AS evaluated
        FROM lint GROUP BY ALL HAVING flagged > 0 ORDER BY flagged DESC""")

    # Q1 / quality overall by model; CVSS band agreement by model.
    quality = rows(con, """
        SELECT model, count(DISTINCT cve_id) AS n,
               avg(score) FILTER (question_id = 'desc_clarity') AS clarity,
               avg((p_true < 0.5)::INT) FILTER (question_id = 'security_impact_stated') AS no_impact,
               avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_is_commit_message') AS commit_msg,
               median(request_ms) FILTER (question_id = 'desc_clarity') AS ms
        FROM ans JOIN cves USING (cve_id) WHERE pack = 'quality' AND state = 'PUBLISHED' GROUP BY model""")
    bands = rows(con, """
        SELECT version, model, count(*) AS n, avg((upper(clef_sev) = upper(cna_sev))::INT) AS same_band,
               avg(abs(clef_score - cna_score)) AS mean_abs_diff
        FROM sev GROUP BY ALL ORDER BY version, model""")

    # Jury: Clef vs CNA closeness per metric, on CVEs that have all three.
    jury_n = load_jury(con)
    jury_metrics, likely_errors, jurors = [], [], []
    if jury_n:
        from .evaluate import jury_section
        jury_section(con)  # builds temp table jury_cmp
        jurors = [r["juror"] for r in rows(con, "SELECT DISTINCT juror FROM jury_votes ORDER BY 1")]
        jury_metrics = rows(con, """
            SELECT field AS metric, count(*) AS n, avg((clef = jury)::INT) AS clef, avg((cna = jury)::INT) AS cna,
                   (SELECT avg((votes = jurors)::INT) FROM jury_cons c WHERE c.field = j.field) AS unanimous
            FROM jury_cmp j WHERE clef IS NOT NULL AND cna IS NOT NULL GROUP BY field""")
        order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        jury_metrics.sort(key=lambda r: order.index(r["metric"]))
        likely_errors = rows(con, """
            SELECT j.cve_id, cv.assigner AS cna, list(struct_pack(metric := j.field, cna := j.cna, ref := j.jury)
                                                ORDER BY j.field) AS changes, cv.description
            FROM jury_cmp j JOIN cves cv USING (cve_id)
            WHERE j.clef = j.jury AND j.cna IS NOT NULL AND j.cna <> j.jury
            GROUP BY j.cve_id, cv.assigner, cv.description ORDER BY count(*) DESC, j.cve_id LIMIT 15""")

    cwe_fit = rows(con, """
        SELECT model, choice AS fit, count(*) AS n FROM ans WHERE question_id = 'cwe_fit'
        GROUP BY ALL ORDER BY model, n DESC""")
    cwe_rejections = rows(con, """
        SELECT x.cve_id, cv.assigner AS cna, x.item AS cwe, k.name, x.p_true AS p_accept,
               (SELECT choice FROM ans f WHERE f.cve_id = x.cve_id AND f.item = x.item AND f.model = 'clef'
                AND f.question_id = 'cwe_fit') AS fit, cv.description
        FROM ans x JOIN cves cv USING (cve_id) LEFT JOIN cwe_catalog k ON k.cwe_id = x.item
        WHERE x.question_id = 'cwe_acceptable' AND x.model = 'clef' ORDER BY x.p_true LIMIT 10""")
    no_impact_examples = rows(con, """
        SELECT cve_id, assigner AS cna, p_true AS p_impact, description
        FROM ans JOIN cves USING (cve_id)
        WHERE question_id = 'security_impact_stated' AND model = 'clef' AND state = 'PUBLISHED'
        ORDER BY p_true LIMIT 4""")
    sample_n = rows(con, "SELECT count(DISTINCT cve_id) AS n FROM ans WHERE model = 'clef' AND pack = 'cvss31'")[0]["n"]

    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "repo_sha": run["repo_sha"][:12], "repo_head": run["repo_head_time"].strftime("%Y-%m-%d"),
        "window_days": run["window_days"], "dev_days": run["dev_slice_days"],
        "corpus": corpus, "min_cves": min_cves, "graded_checks": GRADED_CHECKS,
        "grades": [{"min": t, "grade": g} for t, g in GRADES],
        "cnas": cnas, "lint": lint_summary, "quality": quality, "bands": bands, "sample_n": sample_n,
        "jury": {"n": jury_n, "jurors": jurors, "metrics": jury_metrics, "likely_errors": likely_errors},
        "cwe_fit": cwe_fit, "cwe_rejections": cwe_rejections, "no_impact_examples": no_impact_examples,
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

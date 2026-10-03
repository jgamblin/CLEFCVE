"""Stages 4-6: score Clef's answers against CNA, CISA ADP, and rejection signals; write a Markdown report.

Usage: python -m clefcve.evaluate [--out data/reports/first_results.md]

Every comparison here is *agreement* with another source, not accuracy: CNA and CISA values are themselves
noisy, which is why CNA-vs-CISA agreement is reported alongside as a human-vs-human reference point.
"""

import argparse
from datetime import datetime, timezone
from pathlib import Path

import duckdb

from . import config
from .run import connect_retry

CVSS31 = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
CVSS40 = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
# Rejection reasons that say the issue isn't a valid vulnerability (vs. duplicates or withdrawn-for-other-reasons).
INVALID_REASON_SQL = r"""regexp_matches(lower(rejected_reason),
    'not (a )?(valid|vulnerab|security)|not needed|is false|further research|no security impact|not a security|issued in error|invalid')"""


def connect(db: Path, answers_db: Path) -> duckdb.DuckDBPyConnection:
    con = connect_retry(db, read_only=True)
    con.execute(f"ATTACH '{answers_db}' AS a (READ_ONLY)")
    # Latest answer per (cve, item, model, question) for the current record version.
    con.execute("""
        CREATE TEMP VIEW ans AS
        SELECT x.* FROM a.answers x JOIN cves c ON c.cve_id = x.cve_id AND c.record_sha256 = x.record_sha256
        QUALIFY row_number() OVER (PARTITION BY x.cve_id, x.item, x.model, x.question_id
                                   ORDER BY x.answered_at DESC) = 1
    """)
    return con


def md_table(con, sql: str, params=None) -> str:
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    if not rows:
        return "_(no data yet)_\n"

    def fmt(v):
        if v is None:
            return ""
        if isinstance(v, float):
            return f"{v:.3g}" if abs(v) < 1 else f"{v:.1f}"
        return str(v).replace("|", "\\|")
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join(fmt(v) for v in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def models(con) -> list[str]:
    return [r[0] for r in con.execute("SELECT DISTINCT model FROM ans ORDER BY model DESC").fetchall()]


def cvss_section(con, version: str) -> str:
    metrics = CVSS31 if version == "3.1" else CVSS40
    prefix = "cvss31" if version == "3.1" else "cvss40"
    versions = "('3.0', '3.1')" if version == "3.1" else "('4.0')"
    # One row per (cve, source) with the metric values parsed out of the vector.
    parsed = ", ".join(f"regexp_extract(vector, '/{m}:([A-Z])', 1) AS \"{m}\"" for m in metrics)
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE ref_{prefix} AS
        SELECT cve_id, source, {parsed} FROM metrics
        WHERE version IN {versions} AND source IN ('cna', 'CISA-ADP')
        QUALIFY row_number() OVER (PARTITION BY cve_id, source ORDER BY version DESC) = 1
    """)
    unpivot = " UNION ALL ".join(f"SELECT cve_id, source, '{m}' AS metric, \"{m}\" AS value FROM ref_{prefix}"
                                 for m in metrics)
    con.execute(f"CREATE OR REPLACE TEMP TABLE reflong_{prefix} AS {unpivot}")
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE cmp_{prefix} AS
        SELECT r.cve_id, r.source, r.metric, r.value AS ref_value, x.model, x.choice AS model_value,
               coalesce(json_extract(x.probabilities, '$."' || r.value || '"')::DOUBLE, 0) AS p_ref
        FROM reflong_{prefix} r
        JOIN ans x ON x.cve_id = r.cve_id AND x.question_id = '{prefix}_' || r.metric
        WHERE r.value <> ''
    """)
    out = [f"### CVSS v{version}\n"]
    out.append("Per-metric agreement between Clef's independent answer and the assigned vector. "
               "`confident_disagree` = Clef gave the assigned value < 15% probability.\n")
    out.append(md_table(con, f"""
        SELECT metric, model, source,
               count(*) AS n,
               round(100.0 * avg((ref_value = model_value)::INT), 1) AS agree_pct,
               round(100.0 * avg((p_ref < 0.15)::INT), 1) AS confident_disagree_pct
        FROM cmp_{prefix} GROUP BY metric, model, source
        ORDER BY array_position({metrics}, metric), model DESC, source DESC
    """))
    out.append("\n**Human-vs-human reference:** CNA vs CISA ADP agreement on the same CVEs (v3.x only; CISA "
               "publishes v3.1).\n" if version == "3.1" else "")
    if version == "3.1":
        out.append(md_table(con, f"""
            SELECT a.metric, count(*) AS n, round(100.0 * avg((a.value = b.value)::INT), 1) AS cna_vs_cisa_agree_pct
            FROM reflong_{prefix} a JOIN reflong_{prefix} b USING (cve_id, metric)
            WHERE a.source = 'cna' AND b.source = 'CISA-ADP' AND a.value <> '' AND b.value <> ''
              AND a.cve_id IN (SELECT cve_id FROM ans)
            GROUP BY a.metric ORDER BY array_position({metrics}, a.metric)
        """))
    out.append("\nWhere Clef most confidently disagrees with the CNA (metric value it rated least likely):\n")
    out.append(md_table(con, f"""
        SELECT c.cve_id, cv.assigner, metric, ref_value AS cna, model_value AS clef, round(p_ref, 3) AS p_cna_value,
               left(cv.description, 110) AS description
        FROM cmp_{prefix} c JOIN cves cv USING (cve_id)
        WHERE source = 'cna' AND model = (SELECT max(model) FILTER (model = 'clef') FROM ans)
        ORDER BY p_ref LIMIT 12
    """))
    return "\n".join(out)


def severity_section(con) -> str:
    """Rebuild Clef's full vector per CVE, score it, and compare severity bands with the CNA's."""
    from cvss import CVSS3, CVSS4  # local: only needed here

    rows = []
    for version, prefix, metrics in (("3.1", "cvss31", CVSS31), ("4.0", "cvss40", CVSS40)):
        versions = ("3.0", "3.1") if version == "3.1" else ("4.0",)
        picks = con.execute(f"""
            SELECT x.model, x.cve_id, map(list(substr(x.question_id, 8)), list(x.choice)) AS m,
                   any_value(r.base_score) AS cna_score, any_value(r.vector) AS cna_vector
            FROM ans x JOIN metrics r ON r.cve_id = x.cve_id AND r.source = 'cna'
                                     AND r.version IN {versions!r}
            WHERE x.pack = '{prefix}' GROUP BY x.model, x.cve_id
        """.replace(",)", ")")).fetchall()
        for model, cve_id, m, cna_score, cna_vector in picks:
            if len(m) != len(metrics) or cna_score is None:
                continue
            vector = f"CVSS:{version}/" + "/".join(f"{k}:{m[k]}" for k in metrics)
            try:
                if version == "3.1":
                    c = CVSS3(vector)
                    score, sev = float(c.scores()[0]), c.severities()[0]
                    ref = CVSS3(cna_vector)
                    cna_sev = ref.severities()[0]
                else:
                    c = CVSS4(vector)
                    score, sev = float(c.base_score), c.severity
                    from .lint import cvss4_base_vector
                    cna_sev = CVSS4(cvss4_base_vector(cna_vector)).severity
            except Exception:  # malformed CNA vector: covered by lint, skip here
                continue
            rows.append((version, model, cve_id, score, sev, cna_score, cna_sev))
    if not rows:
        return "### Severity band agreement\n\n_(no data yet)_\n"
    con.execute("CREATE OR REPLACE TEMP TABLE sev (version VARCHAR, model VARCHAR, cve_id VARCHAR, "
                "clef_score DOUBLE, clef_sev VARCHAR, cna_score DOUBLE, cna_sev VARCHAR)")
    con.executemany("INSERT INTO sev VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
    out = ["### Severity band agreement\n",
           "Clef's metric choices assembled into a full vector and scored, vs the CNA's vector.\n"]
    out.append(md_table(con, """
        SELECT version, model, count(*) AS n,
               round(100.0 * avg((upper(clef_sev) = upper(cna_sev))::INT), 1) AS same_band_pct,
               round(avg(abs(clef_score - cna_score)), 2) AS mean_abs_score_diff,
               round(100.0 * avg((clef_score < cna_score - 1)::INT), 1) AS cna_higher_by_1plus_pct,
               round(100.0 * avg((clef_score > cna_score + 1)::INT), 1) AS cna_lower_by_1plus_pct
        FROM sev GROUP BY version, model ORDER BY version, model DESC
    """))
    out.append("\nBy CNA (Clef 27B, ≥ 5 sampled CVEs). Positive `cna_minus_clef` = CNA scores higher than Clef:\n")
    out.append(md_table(con, """
        SELECT assigner, version, count(*) AS n, round(avg(cna_score - clef_score), 2) AS cna_minus_clef,
               round(100.0 * avg((upper(clef_sev) = upper(cna_sev))::INT), 1) AS same_band_pct
        FROM sev JOIN cves USING (cve_id) WHERE model = 'clef'
        GROUP BY assigner, version HAVING count(*) >= 5 ORDER BY cna_minus_clef DESC
    """))
    return "\n".join(out)


def ssvc_section(con) -> str:
    out = ["## SSVC vs CISA Vulnrichment\n",
           "`baseline` = always predicting CISA's most common value in this sample.\n"]
    out.append(md_table(con, """
        WITH s AS (SELECT * FROM ssvc WHERE source = 'CISA-ADP'
                   QUALIFY row_number() OVER (PARTITION BY cve_id ORDER BY timestamp DESC) = 1),
        j AS (
            SELECT x.model, 'automatable' AS point, s.automatable AS cisa,
                   CASE WHEN x.p_true >= 0.5 THEN 'yes' ELSE 'no' END AS clef
            FROM ans x JOIN s USING (cve_id) WHERE x.question_id = 'ssvc_automatable'
            UNION ALL
            SELECT x.model, 'technical_impact', s.technical_impact, x.choice
            FROM ans x JOIN s USING (cve_id) WHERE x.question_id = 'ssvc_technical_impact'
            UNION ALL
            SELECT x.model, 'exploitation', s.exploitation, x.choice
            FROM ans x JOIN s USING (cve_id) WHERE x.question_id = 'ssvc_exploitation'
        )
        SELECT point, model, count(*) AS n, round(100.0 * avg((lower(cisa) = clef)::INT), 1) AS agree_pct,
               round(100.0 * max(cnt) / count(*), 1) AS baseline_pct
        FROM (SELECT *, count(*) OVER (PARTITION BY point, model, cisa) AS cnt FROM j)
        GROUP BY point, model ORDER BY point, model DESC
    """))
    return "\n".join(out)


def vuln_section(con) -> str:
    out = ["## Q1: Is this a vulnerability?\n",
           "Rejected records use their last published text, recovered from git history. "
           "`rejected_invalid` = rejection reason says it isn't a valid vulnerability; duplicates are separate "
           "because they *are* real vulnerabilities.\n"]
    out.append(md_table(con, f"""
        WITH g AS (
            SELECT cve_id, CASE WHEN state = 'PUBLISHED' THEN 'published'
                                WHEN {INVALID_REASON_SQL} THEN 'rejected_invalid'
                                WHEN lower(rejected_reason) LIKE '%duplicate%' THEN 'rejected_duplicate'
                                ELSE 'rejected_other' END AS grp
            FROM cves)
        SELECT grp, model, count(*) AS n, round(avg(p_true), 3) AS mean_p_vuln,
               round(100.0 * avg((p_true < 0.5)::INT), 1) AS pct_flagged_not_vuln
        FROM ans JOIN g USING (cve_id) WHERE question_id = 'is_vuln'
        GROUP BY ALL ORDER BY grp, model DESC
    """))
    out.append("\nWhy (vuln_reason), published CVEs only:\n")
    out.append(md_table(con, """
        SELECT model, choice AS reason, count(*) AS n
        FROM ans JOIN cves USING (cve_id) WHERE question_id = 'vuln_reason' AND state = 'PUBLISHED'
        GROUP BY ALL ORDER BY model DESC, n DESC
    """))
    out.append("\nPublished CVEs Clef (27B) is least convinced are vulnerabilities:\n")
    out.append(md_table(con, """
        SELECT cve_id, assigner, round(p_true, 3) AS p_vuln,
               (SELECT choice FROM ans r WHERE r.cve_id = x.cve_id AND r.model = x.model
                AND r.question_id = 'vuln_reason') AS reason, left(description, 120) AS description
        FROM ans x JOIN cves USING (cve_id)
        WHERE question_id = 'is_vuln' AND state = 'PUBLISHED' AND model = 'clef'
        ORDER BY p_true LIMIT 10
    """))
    return "\n".join(out)


def description_section(con) -> str:
    out = ["## Q2: Description quality\n",
           "Element presence = share of descriptions where Clef says p ≥ 0.5. `clarity` is the expected level "
           "on a 0-4 scale (Unusable, Poor, Adequate, Good, Excellent).\n"]
    out.append(md_table(con, """
        SELECT model,
               count(DISTINCT cve_id) AS n,
               round(avg(score) FILTER (question_id = 'desc_clarity'), 2) AS clarity,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_product'), 0) AS product,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_versions'), 0) AS versions,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_vuln_type'), 0) AS vuln_type,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_attacker'), 0) AS attacker,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_impact'), 0) AS impact,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_vector'), 0) AS vector,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_is_commit_message'), 0) AS commit_msg,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_is_boilerplate'), 0) AS boilerplate
        FROM ans JOIN cves USING (cve_id) WHERE state = 'PUBLISHED' AND pack = 'quality'
        GROUP BY model ORDER BY model DESC
    """))
    out.append("\nBy CNA (Clef 27B if available, CNAs with ≥ 5 sampled CVEs):\n")
    out.append(md_table(con, """
        WITH m AS (SELECT coalesce(max(model) FILTER (model = 'clef'), max(model)) AS m FROM ans)
        SELECT assigner, count(DISTINCT cve_id) AS n,
               round(avg(score) FILTER (question_id = 'desc_clarity'), 2) AS clarity,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_impact'), 0) AS impact_pct,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_attacker'), 0) AS attacker_pct,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_is_commit_message'), 0) AS commit_msg_pct
        FROM ans JOIN cves USING (cve_id)
        WHERE state = 'PUBLISHED' AND pack = 'quality' AND model = (SELECT m FROM m)
        GROUP BY 1 HAVING count(DISTINCT cve_id) >= 5 ORDER BY clarity
    """))
    out.append("\nLowest-clarity descriptions (Clef 27B):\n")
    out.append(md_table(con, """
        SELECT cve_id, assigner, round(score, 2) AS clarity, left(description, 140) AS description
        FROM ans JOIN cves USING (cve_id)
        WHERE question_id = 'desc_clarity' AND model = 'clef' AND state = 'PUBLISHED'
        ORDER BY score LIMIT 8
    """))
    return "\n".join(out)


def cwe_section(con) -> str:
    out = ["## Q3: Is the CWE correct?\n", "Fit of each CNA-assigned CWE, judged against its CWE definition:\n"]
    out.append(md_table(con, """
        SELECT model, choice AS fit, count(*) AS n, round(100.0 * count(*) / sum(count(*)) OVER (PARTITION BY model), 1) AS pct
        FROM ans WHERE question_id = 'cwe_fit' GROUP BY model, choice ORDER BY model DESC, n DESC
    """))
    out.append("\nSanity check: CWE mapping usage (from the CWE catalog) vs Clef's acceptance. Discouraged entries "
               "(e.g. CWE-20, CWE-200, CWE-284) should be accepted less often.\n")
    out.append(md_table(con, """
        SELECT model, coalesce(k.usage, '?') AS mapping_usage, count(*) AS n,
               round(100.0 * avg((p_true >= 0.5)::INT), 1) AS accepted_pct,
               round(100.0 * avg((choice_fit = 'too_general')::INT), 1) AS too_general_pct
        FROM (SELECT x.*, (SELECT choice FROM ans f WHERE f.cve_id = x.cve_id AND f.item = x.item
                           AND f.model = x.model AND f.question_id = 'cwe_fit') AS choice_fit
              FROM ans x WHERE question_id = 'cwe_acceptable') x
        LEFT JOIN cwe_catalog k ON k.cwe_id = x.item
        GROUP BY ALL ORDER BY model DESC, mapping_usage
    """))
    out.append("\nMost-rejected CWE assignments (Clef 27B):\n")
    out.append(md_table(con, """
        SELECT x.cve_id, assigner, x.item AS cwe, k.name, round(x.p_true, 3) AS p_accept,
               left(cves.description, 100) AS description
        FROM ans x JOIN cves USING (cve_id) LEFT JOIN cwe_catalog k ON k.cwe_id = x.item
        WHERE question_id = 'cwe_acceptable' AND model = 'clef' ORDER BY p_true LIMIT 10
    """))
    return "\n".join(out)


def rules_section(con) -> str:
    out = ["## Q5: CNA Operational Rules 4.1.0 (full corpus, deterministic)\n"]
    out.append(md_table(con, """
        SELECT check_id, rule, level, count(*) FILTER (status IN ('fail', 'warn')) AS flagged,
               count(*) FILTER (status IN ('pass', 'fail', 'warn')) AS evaluated,
               round(100.0 * count(*) FILTER (status IN ('fail', 'warn'))
                     / nullif(count(*) FILTER (status IN ('pass', 'fail', 'warn')), 0), 1) AS pct
        FROM lint GROUP BY check_id, rule, level HAVING flagged > 0 ORDER BY level = 'format', pct DESC
    """))
    out.append("\nMUST-level failures by CNA (CNAs with ≥ 100 CVEs in the 60-day window):\n")
    out.append(md_table(con, """
        WITH per AS (
            SELECT c.assigner, l.cve_id, bool_or(l.status = 'fail' AND l.level IN ('MUST', 'MUST NOT')) AS must_fail,
                   string_agg(DISTINCT l.check_id, ', ') FILTER (l.status = 'fail' AND l.level IN ('MUST', 'MUST NOT')) AS checks
            FROM lint l JOIN cves c USING (cve_id) GROUP BY ALL)
        SELECT assigner, count(*) AS cves, round(100.0 * avg(must_fail::INT), 1) AS pct_must_fail,
               mode(checks) AS most_common_failure
        FROM per GROUP BY 1 HAVING count(*) >= 100 ORDER BY pct_must_fail DESC LIMIT 15
    """))
    out.append("\nJudgment-based rules (Clef, sampled CVEs; % with p ≥ 0.5):\n")
    out.append(md_table(con, """
        SELECT model,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'multiple_vulns'), 1) AS multi_vuln_4_2_11,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_has_credits'), 1) AS credits_5_2_4,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_has_irrelevant_info'), 1) AS irrelevant_5_2_6,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'hosted_service_only'), 1) AS hosted_only_5_1_11
        FROM ans JOIN cves USING (cve_id) WHERE state = 'PUBLISHED' GROUP BY model ORDER BY model DESC
    """))
    return "\n".join(out)


def models_section(con) -> str:
    out = ["## Clef vs Clef Flash\n", "How often the two models give the same answer on the same question:\n"]
    out.append(md_table(con, """
        SELECT f.pack, count(*) AS n,
               round(100.0 * avg(CASE WHEN f.type = 'noul' THEN ((f.p_true >= 0.5) = (c.p_true >= 0.5))::INT
                                      WHEN f.type = 'choice' THEN (f.choice = c.choice)::INT
                                      ELSE (abs(f.score - c.score) < 0.5)::INT END), 1) AS same_answer_pct,
               round(median(f.request_ms), 0) AS flash_ms, round(median(c.request_ms), 0) AS clef_ms
        FROM ans f JOIN ans c USING (cve_id, item, question_id)
        WHERE f.model = 'clef-flash' AND c.model = 'clef' GROUP BY 1 ORDER BY 1
    """))
    return "\n".join(out)


def report(con) -> str:
    run = con.execute("SELECT repo_sha, repo_head_time, window_days, dev_slice_days FROM ingest_run").fetchone()
    counts = con.execute("""SELECT model, pack, count(DISTINCT cve_id) cves, count(*) answers
                            FROM ans GROUP BY ALL ORDER BY model DESC, pack""").fetchall()
    parts = [
        "# CLEFCVE results\n",
        f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC from cvelistV5 `{run[0][:12]}` "
        f"(HEAD {run[1]:%Y-%m-%d %H:%M} UTC). Corpus: {run[2]}-day window; model runs use a random sample of "
        f"the {run[3]}-day slice plus all recovered REJECTED records.\n",
        "| model | pack | CVEs | answers |\n|---|---|---|---|\n" +
        "\n".join(f"| {m} | {p} | {c} | {a} |" for m, p, c, a in counts) + "\n",
        vuln_section(con), description_section(con), cwe_section(con),
        "## Q4: Is the CVSS correct?\n", severity_section(con), cvss_section(con, "3.1"), cvss_section(con, "4.0"),
        ssvc_section(con), rules_section(con), models_section(con),
    ]
    return "\n".join(parts)


def main(argv: list[str] | None = None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--db", type=Path, default=config.DB_PATH)
    p.add_argument("--answers-db", type=Path, default=config.ANSWERS_DB_PATH)
    p.add_argument("--out", type=Path, default=config.PROJECT_ROOT / "data" / "reports" / "first_results.md")
    args = p.parse_args(argv)
    con = connect(args.db, args.answers_db)
    text = report(con)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text)
    print(text)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()

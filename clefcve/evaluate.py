"""Score Clef's answers and the rule checks; write a Markdown report.

Usage: python -m clefcve.evaluate [--experimental] [--out data/reports/results.md]

Every comparison here is *agreement* with another source, not accuracy: CNA and CISA values are themselves
noisy, which is why CNA-vs-CISA agreement is reported alongside as a human-vs-human reference point.
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import duckdb

from . import config
from .run import connect_retry

# The model that answers the core questions over the whole corpus; Clef 27B is used on samples as a check.
CORPUS_MODEL = "clef-flash"
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
    # The security-impact cascade: Clef Flash reads everything; where Flash says "no impact stated" and Clef 27B
    # has re-checked the CVE (scripts/confirm_flagged.sh), 27B's answer is final.
    con.execute("""
        CREATE TEMP VIEW impact AS
        WITH f AS (SELECT cve_id, max(p_true) FILTER (question_id = 'security_impact_stated') AS p,
                          max(choice) FILTER (question_id = 'impact_basis') AS b
                   FROM ans WHERE model = 'clef-flash' AND item = ''
                     AND question_id IN ('security_impact_stated', 'impact_basis') GROUP BY 1),
             k AS (SELECT cve_id, max(p_true) FILTER (question_id = 'security_impact_stated') AS p,
                          max(choice) FILTER (question_id = 'impact_basis') AS b
                   FROM ans WHERE model = 'clef' AND item = ''
                     AND question_id IN ('security_impact_stated', 'impact_basis') GROUP BY 1)
        SELECT f.cve_id, f.p AS flash_p, k.p AS clef_p,
               (f.p < 0.5 AND k.p IS NOT NULL) AS rechecked,
               CASE WHEN f.p < 0.5 AND k.p IS NOT NULL THEN k.p ELSE f.p END AS p_true,
               CASE WHEN f.p < 0.5 AND k.p IS NOT NULL THEN coalesce(k.b, f.b) ELSE f.b END AS basis
        FROM f LEFT JOIN k USING (cve_id) WHERE f.p IS NOT NULL
    """)
    # The headline measure: "no security impact established" only when both answers agree, so a terse record that
    # names a vulnerability class (e.g. "a SQL injection vulnerability in Asset") isn't counted.
    con.execute("""
        CREATE TEMP VIEW impact_final AS
        SELECT *, (p_true < 0.5 AND basis IN ('bug_fix_only', 'not_security_relevant', 'insufficient_information'))
                  AS no_impact
        FROM impact
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
    out.append("\n**Human-vs-human reference:** CNA vs CISA ADP agreement over the whole 60-day corpus "
               "(CISA usually adds CVSS only when the CNA didn't, so overlap is small).\n" if version == "3.1" else "")
    if version == "3.1":
        out.append(md_table(con, f"""
            SELECT a.metric, count(*) AS n, round(100.0 * avg((a.value = b.value)::INT), 1) AS cna_vs_cisa_agree_pct
            FROM reflong_{prefix} a JOIN reflong_{prefix} b USING (cve_id, metric)
            WHERE a.source = 'cna' AND b.source = 'CISA-ADP' AND a.value <> '' AND b.value <> ''
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
            WITH r AS (
                SELECT cve_id, base_score, vector FROM metrics
                WHERE source = 'cna' AND version IN {versions!r}
                QUALIFY row_number() OVER (PARTITION BY cve_id ORDER BY version DESC, vector) = 1)
            SELECT x.model, x.cve_id, map(list(substr(x.question_id, 8)), list(x.choice)) AS m,
                   any_value(r.base_score) AS cna_score, any_value(r.vector) AS cna_vector
            FROM ans x JOIN r USING (cve_id)
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


def load_jury(con) -> int:
    """Majority vote per (CVE, field) across the LLM jury → temp table `jury_cons`; raw votes → `jury_votes`."""
    from .jury import PROMPT_HASH, consensus
    con.execute("CREATE OR REPLACE TEMP TABLE jury_votes (cve_id VARCHAR, juror VARCHAR, cwe_id VARCHAR, field VARCHAR, value VARCHAR)")
    con.execute("CREATE OR REPLACE TEMP TABLE jury_cons (cve_id VARCHAR, cwe_id VARCHAR, field VARCHAR, value VARCHAR, "
                "votes INTEGER, jurors INTEGER)")
    try:
        rows = con.execute("""
            SELECT j.cve_id, j.juror, j.cwe_id, j.answer FROM a.jury j
            JOIN cves c ON c.cve_id = j.cve_id AND c.record_sha256 = j.record_sha256
            WHERE j.prompt_hash = ?
            QUALIFY row_number() OVER (PARTITION BY j.cve_id, j.juror ORDER BY j.answered_at DESC) = 1
        """, [PROMPT_HASH]).fetchall()
    except duckdb.CatalogException:
        return 0
    by_cve: dict = {}
    for cve_id, juror, cwe_id, answer in rows:
        ans = json.loads(answer)
        for field, value in ans.items():
            con.execute("INSERT INTO jury_votes VALUES (?, ?, ?, ?, ?)", [cve_id, juror, cwe_id, field, value])
            by_cve.setdefault((cve_id, cwe_id), {}).setdefault(field, []).append(value)
    for (cve_id, cwe_id), fields in by_cve.items():
        for field, votes in fields.items():
            value = consensus(votes, quorum=len(votes) // 2 + 1)
            con.execute("INSERT INTO jury_cons VALUES (?, ?, ?, ?, ?, ?)",
                        [cve_id, cwe_id, field, value, votes.count(value) if value else 0, len(votes)])
    return len({r[0] for r in rows})


def jury_section(con) -> str:
    n = load_jury(con)
    out = ["## LLM jury: reference labels for CVSS and CWE\n"]
    if not n:
        return out[0] + "\n_No jury answers yet: run `python -m clefcve.jury`._\n"
    jurors = [r[0] for r in con.execute("SELECT DISTINCT juror FROM jury_votes ORDER BY 1").fetchall()]
    out.append(f"{n} CVEs, {len(jurors)} jurors ({', '.join(jurors)}), from the same text Clef sees. "
               "The reference for each field is the strict-majority vote; fields without one are excluded.\n")
    metrics_sql = "[" + ", ".join(f"'{m}'" for m in CVSS31) + ", 'cwe_fit', 'best_cwe']"
    out.append("\n**How much the jury agrees with itself:**\n")
    out.append(md_table(con, f"""
        SELECT field, count(*) AS n, round(100.0 * avg((votes = jurors)::INT), 1) AS unanimous_pct,
               round(100.0 * avg((value IS NOT NULL)::INT), 1) AS has_majority_pct
        FROM jury_cons WHERE jurors >= 3 GROUP BY field ORDER BY array_position({metrics_sql}, field)
    """))
    out.append("\n**Who agrees with the jury: Clef, Flash, or the CNA?** (CVSS v3.1, per metric, where the jury has a "
               "majority)\n")
    cna_parsed = " UNION ALL ".join(
        f"SELECT cve_id, '{m}' AS field, regexp_extract(vector, '/{m}:([A-Z])', 1) AS value FROM cna31" for m in CVSS31)
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE jury_cmp AS
        WITH cna31 AS (SELECT cve_id, vector FROM metrics WHERE source = 'cna' AND version IN ('3.0', '3.1')
                       QUALIFY row_number() OVER (PARTITION BY cve_id ORDER BY version DESC) = 1),
             cna AS ({cna_parsed})
        SELECT j.cve_id, j.field, j.value AS jury,
               max(x.choice) FILTER (x.model = 'clef') AS clef,
               max(x.choice) FILTER (x.model = 'clef-flash') AS flash,
               any_value(c.value) AS cna
        FROM jury_cons j
        LEFT JOIN ans x ON x.cve_id = j.cve_id AND x.question_id = 'cvss31_' || j.field
        LEFT JOIN cna c ON c.cve_id = j.cve_id AND c.field = j.field AND c.value <> ''
        WHERE j.value IS NOT NULL AND j.field IN ({", ".join(f"'{m}'" for m in CVSS31)})
        GROUP BY j.cve_id, j.field, j.value
    """)
    out.append(md_table(con, f"""
        SELECT field AS metric,
               count(clef) AS n_clef, round(100.0 * avg((clef = jury)::INT), 1) AS clef_pct,
               count(flash) AS n_flash, round(100.0 * avg((flash = jury)::INT), 1) AS flash_pct,
               count(cna) AS n_cna, round(100.0 * avg((cna = jury)::INT), 1) AS cna_pct
        FROM jury_cmp GROUP BY field ORDER BY array_position({metrics_sql}, field)
    """))
    out.append("\nSame comparison restricted to CVEs that have all three (Clef 27B, CNA vector, jury majority), "
               "so the columns are directly comparable:\n")
    out.append(md_table(con, f"""
        SELECT field AS metric, count(*) AS n, round(100.0 * avg((clef = jury)::INT), 1) AS clef_pct,
               round(100.0 * avg((cna = jury)::INT), 1) AS cna_pct,
               count(*) FILTER (clef = jury AND cna <> jury) AS clef_right_cna_wrong,
               count(*) FILTER (cna = jury AND clef <> jury) AS cna_right_clef_wrong
        FROM jury_cmp WHERE clef IS NOT NULL AND cna IS NOT NULL
        GROUP BY field ORDER BY array_position({metrics_sql}, field)
    """))
    out.append("\n**CWE:** fit of the CNA-assigned CWE, and whether the jury's preferred CWE matches it.\n")
    out.append(md_table(con, """
        WITH f AS (SELECT cve_id, cwe_id, value FROM jury_cons WHERE field = 'cwe_fit'),
             b AS (SELECT cve_id, value FROM jury_cons WHERE field = 'best_cwe')
        SELECT x.model, count(*) AS n,
               round(100.0 * avg((x.choice = f.value)::INT) FILTER (f.value IS NOT NULL), 1) AS same_fit_pct,
               round(100.0 * avg(((x.choice = 'exact') = (f.value = 'exact'))::INT) FILTER (f.value IS NOT NULL), 1)
                   AS exact_vs_not_pct,
               round(100.0 * avg((b.value = f.cwe_id)::INT) FILTER (b.value IS NOT NULL), 1) AS jury_best_is_cna_cwe_pct
        FROM f JOIN ans x ON x.cve_id = f.cve_id AND x.item = f.cwe_id AND x.question_id = 'cwe_fit'
        LEFT JOIN b ON b.cve_id = f.cve_id
        GROUP BY x.model ORDER BY x.model DESC
    """))
    out.append("\n**Each juror vs the others' majority** (leave-one-out; how good a single general-purpose model is):\n")
    out.append(md_table(con, f"""
        WITH loo AS (
            SELECT v.juror, v.field, v.value,
                   (SELECT mode(o.value) FROM jury_votes o
                    WHERE o.cve_id = v.cve_id AND o.field = v.field AND o.juror <> v.juror) AS others
            FROM jury_votes v WHERE v.field IN ({", ".join(f"'{m}'" for m in CVSS31)}, 'cwe_fit'))
        SELECT juror, count(*) AS answers,
               round(100.0 * avg((value = others)::INT) FILTER (field <> 'cwe_fit'), 1) AS cvss_metric_pct,
               round(100.0 * avg((value = others)::INT) FILTER (field = 'cwe_fit'), 1) AS cwe_fit_pct
        FROM loo GROUP BY juror ORDER BY cvss_metric_pct DESC
    """))
    out.append("\nCVEs where the jury and Clef 27B agree with each other but not with the CNA (likely CNA errors):\n")
    out.append(md_table(con, """
        SELECT j.cve_id, cv.assigner, string_agg(j.field || ' ' || j.cna || '→' || j.jury, ', ' ORDER BY j.field) AS changes,
               left(cv.description, 110) AS description
        FROM jury_cmp j JOIN cves cv USING (cve_id)
        WHERE j.clef = j.jury AND j.cna IS NOT NULL AND j.cna <> j.jury
        GROUP BY j.cve_id, cv.assigner, cv.description ORDER BY count(*) DESC, j.cve_id LIMIT 12
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
    out = ["## Q1: Does the description establish a security impact?\n",
           "Rephrased from \"is this a vulnerability?\" after the first run: the text alone couldn't separate CVEs later "
           "rejected as invalid from valid ones (p = 0.93 vs 0.89), because the reasons for rejection are rarely "
           "visible in the description. Rejected records use their last published text from git history.\n"]
    out.append(md_table(con, f"""
        WITH g AS (
            SELECT cve_id, CASE WHEN state = 'PUBLISHED' THEN 'published'
                                WHEN {INVALID_REASON_SQL} THEN 'rejected_invalid'
                                WHEN lower(rejected_reason) LIKE '%duplicate%' THEN 'rejected_duplicate'
                                ELSE 'rejected_other' END AS grp
            FROM cves)
        SELECT grp, model, count(*) AS n, round(avg(p_true), 3) AS mean_p_impact,
               round(100.0 * avg((p_true < 0.5)::INT), 1) AS pct_no_impact_stated
        FROM ans JOIN g USING (cve_id) WHERE question_id = 'security_impact_stated'
        GROUP BY ALL ORDER BY grp, model DESC
    """))
    out.append("\nHow the impact is supported (`impact_basis`), published CVEs:\n")
    out.append(md_table(con, """
        SELECT model, choice AS basis, count(*) AS n,
               round(100.0 * count(*) / sum(count(*)) OVER (PARTITION BY model), 1) AS pct
        FROM ans JOIN cves USING (cve_id) WHERE question_id = 'impact_basis' AND state = 'PUBLISHED'
        GROUP BY model, choice ORDER BY model DESC, n DESC
    """))
    out.append("\nThe cascade: Flash reads everything, Clef 27B re-checks Flash's \"no impact\" calls.\n")
    out.append(md_table(con, """
        SELECT assigner = 'Linux' AS linux, count(*) AS answered,
               count(*) FILTER (flash_p < 0.5) AS flash_no_impact,
               count(*) FILTER (rechecked) AS rechecked_by_27b,
               count(*) FILTER (rechecked AND clef_p >= 0.5) AS overturned,
               round(100.0 * count(*) FILTER (rechecked AND clef_p >= 0.5) / nullif(count(*) FILTER (rechecked), 0), 1)
                   AS overturned_pct
        FROM impact JOIN cves USING (cve_id) WHERE state = 'PUBLISHED' GROUP BY 1 ORDER BY 1
    """))
    out.append("\nBy CNA: share of descriptions with no security impact established (cascade, ≥ 25 answered CVEs):\n")
    out.append(md_table(con, """
        SELECT assigner, count(*) AS n, round(100.0 * avg((p_true < 0.5)::INT), 1) AS pct_no_impact_stated,
               round(100.0 * avg((flash_p < 0.5)::INT), 1) AS flash_only_pct
        FROM impact JOIN cves USING (cve_id) WHERE state = 'PUBLISHED'
        GROUP BY 1 HAVING count(*) >= 25 ORDER BY pct_no_impact_stated DESC, n DESC LIMIT 25
    """))
    out.append("\nPublished CVEs where Clef 27B finds the least stated impact:\n")
    out.append(md_table(con, """
        SELECT cve_id, assigner, round(p_true, 3) AS p_impact,
               (SELECT choice FROM ans r WHERE r.cve_id = x.cve_id AND r.model = x.model
                AND r.question_id = 'impact_basis') AS basis, left(description, 120) AS description
        FROM ans x JOIN cves USING (cve_id)
        WHERE question_id = 'security_impact_stated' AND state = 'PUBLISHED' AND model = 'clef'
        ORDER BY p_true LIMIT 10
    """))
    return "\n".join(out)


def load_gold(con) -> int:
    """Register hand labels (Q1, clarity) from gold/labels.json as temp table `gold`."""
    from .labeler import LABELS_PATH, is_done, load_labels
    labels = {k: v for k, v in load_labels(LABELS_PATH).items() if is_done(v)}
    con.execute("""CREATE OR REPLACE TEMP TABLE gold (cve_id VARCHAR, security_impact BOOLEAN, impact_basis VARCHAR,
                   is_vuln VARCHAR, desc_clarity INTEGER, cvss_saw_cna BOOLEAN)""")
    for cve_id, l in labels.items():
        con.execute("INSERT INTO gold VALUES (?, ?, ?, ?, ?, ?)", [
            cve_id, l["security_impact"] == "y", l.get("impact_basis"), l.get("is_vuln"), l["desc_clarity"],
            bool(l.get("cvss_saw_cna"))])
    return len(labels)


def gold_section(con) -> str:
    n = load_gold(con)
    out = ["## Accuracy against hand labels (gold set)\n"]
    if not n:
        return out[0] + "\n_No labels yet: run `python -m clefcve.labeler` and label `gold/to_label.csv`._\n"
    out.append(f"{n} CVEs labeled (Q1 and clarity; CVSS and CWE use the LLM jury below). These are scored "
               "against your judgment, unlike the agreement numbers elsewhere.\n")
    out.append(md_table(con, """
        SELECT x.model, count(*) AS n,
               round(100.0 * avg(((x.p_true >= 0.5) = g.security_impact)::INT), 1) AS q1_accuracy_pct,
               round(100.0 * avg(((x.p_true >= 0.5) AND NOT g.security_impact)::INT), 1) AS false_yes_pct,
               round(100.0 * avg(((x.p_true < 0.5) AND g.security_impact)::INT), 1) AS false_no_pct
        FROM gold g JOIN ans x USING (cve_id) WHERE x.question_id = 'security_impact_stated'
        GROUP BY 1 ORDER BY 1 DESC
    """))
    out.append("\nDescription clarity (0-4): mean absolute error and share within one level.\n")
    out.append(md_table(con, """
        SELECT x.model, count(*) AS n, round(avg(abs(x.score - g.desc_clarity)), 2) AS mae,
               round(100.0 * avg((abs(x.score - g.desc_clarity) <= 1)::INT), 1) AS within_1_pct,
               round(corr(x.score, g.desc_clarity), 2) AS pearson_r
        FROM gold g JOIN ans x USING (cve_id) WHERE x.question_id = 'desc_clarity'
        GROUP BY 1 ORDER BY 1 DESC
    """))
    return "\n".join(out)


def description_section(con) -> str:
    out = ["## Q2: How clear is the description?\n",
           "`clarity` is the expected level on Clef's 0-4 scale (Unusable, Poor, Adequate, Good, Excellent). "
           "`commit_msg` = reads as a developer commit message rather than a vulnerability description.\n"]
    out.append(md_table(con, """
        SELECT model, count(DISTINCT cve_id) AS n,
               round(avg(score) FILTER (question_id = 'desc_clarity'), 2) AS clarity,
               round(100.0 * avg((score < 1.5)::INT) FILTER (question_id = 'desc_clarity'), 1) AS poor_or_worse_pct,
               round(100.0 * avg((score >= 2.5)::INT) FILTER (question_id = 'desc_clarity'), 1) AS good_or_better_pct,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_is_commit_message'), 1) AS commit_msg_pct
        FROM ans JOIN cves USING (cve_id) WHERE state = 'PUBLISHED'
        GROUP BY model ORDER BY model DESC
    """))
    out.append(f"\nBy CNA ({CORPUS_MODEL}, CNAs with ≥ 25 answered CVEs):\n")
    out.append(md_table(con, f"""
        SELECT assigner, count(DISTINCT cve_id) AS n,
               round(avg(score) FILTER (question_id = 'desc_clarity'), 2) AS clarity,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_is_commit_message'), 0) AS commit_msg_pct
        FROM ans JOIN cves USING (cve_id)
        WHERE state = 'PUBLISHED' AND model = '{CORPUS_MODEL}'
        GROUP BY 1 HAVING count(DISTINCT cve_id) >= 25 ORDER BY clarity
    """))
    out.append(f"\nLowest-clarity descriptions ({CORPUS_MODEL}):\n")
    out.append(md_table(con, f"""
        SELECT cve_id, assigner, round(score, 2) AS clarity, left(description, 140) AS description
        FROM ans JOIN cves USING (cve_id)
        WHERE question_id = 'desc_clarity' AND model = '{CORPUS_MODEL}' AND state = 'PUBLISHED'
        ORDER BY score LIMIT 8
    """))
    return "\n".join(out)


def description_elements_section(con) -> str:
    out = ["## Experimental: description elements\n",
           "Share of descriptions where Clef says each element is present (p ≥ 0.5). Sampled CVEs only.\n"]
    out.append(md_table(con, """
        SELECT model, count(DISTINCT cve_id) AS n,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_product'), 0) AS product,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_versions'), 0) AS versions,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_vuln_type'), 0) AS vuln_type,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_attacker'), 0) AS attacker,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_impact'), 0) AS impact,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_names_vector'), 0) AS vector,
               round(100.0 * avg((p_true >= 0.5)::INT) FILTER (question_id = 'desc_is_boilerplate'), 0) AS boilerplate
        FROM ans JOIN cves USING (cve_id) WHERE state = 'PUBLISHED' AND pack = 'quality'
        GROUP BY model ORDER BY model DESC
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
    out = ["## Rule checks: CNA Operational Rules 4.1.0 (full corpus, no model)\n"]
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
    return "\n".join(out)


def judgment_rules_section(con) -> str:
    out = ["## Experimental: judgment-based rules\n", "Clef, sampled CVEs; % with p ≥ 0.5.\n"]
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
    out = ["## Clef 27B vs Clef Flash\n",
           "How often the two models give the same answer on the same CVE (clarity: within half a level):\n"]
    out.append(md_table(con, """
        SELECT f.question_id AS question, count(*) AS n,
               round(100.0 * avg(CASE WHEN f.type = 'noul' THEN ((f.p_true >= 0.5) = (c.p_true >= 0.5))::INT
                                      WHEN f.type = 'choice' THEN (f.choice = c.choice)::INT
                                      ELSE (abs(f.score - c.score) < 0.5)::INT END), 1) AS same_answer_pct,
               round(median(f.request_ms), 0) AS flash_ms, round(median(c.request_ms), 0) AS clef_ms
        FROM ans f JOIN ans c USING (cve_id, item, question_id)
        WHERE f.model = 'clef-flash' AND c.model = 'clef' AND f.question_id IN ('security_impact_stated', 'impact_basis', 'desc_clarity', 'desc_is_commit_message')
        GROUP BY 1 ORDER BY 1
    """))
    return "\n".join(out)


def coverage_section(con) -> str:
    rows = con.execute(f"""
        SELECT count(*) AS published,
               count(*) FILTER (cve_id IN (SELECT cve_id FROM ans WHERE model = '{CORPUS_MODEL}'
                                           AND question_id = 'desc_clarity')) AS answered
        FROM cves WHERE state = 'PUBLISHED'""").fetchone()
    return (f"**Coverage:** {CORPUS_MODEL} has answered the core questions for {rows[1]:,} of {rows[0]:,} published CVEs "
            f"({100 * rows[1] / rows[0]:.0f}%), in random order, so partial results are a random sample.\n")


def report(con, experimental: bool = False) -> str:
    run = con.execute("SELECT repo_sha, repo_head_time, window_days, dev_slice_days FROM ingest_run").fetchone()
    parts = [
        "# CLEFCVE results\n",
        f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC from cvelistV5 `{run[0][:12]}` "
        f"(HEAD {run[1]:%Y-%m-%d %H:%M} UTC), {run[2]}-day window.\n",
        "The tool does three things: deterministic rule checks on every record, and two Clef questions about the "
        "description: does it establish a security impact, and how clear is it.\n",
        coverage_section(con), rules_section(con), vuln_section(con), description_section(con), gold_section(con),
        models_section(con),
    ]
    if experimental:
        counts = con.execute("""SELECT model, pack, count(DISTINCT cve_id) cves, count(*) answers
                                FROM ans GROUP BY ALL ORDER BY model DESC, pack""").fetchall()
        parts += [
            "\n---\n# Experimental (shelved): CVSS, CWE, SSVC, judgment rules\n",
            "| model | pack | CVEs | answers |\n|---|---|---|---|\n" +
            "\n".join(f"| {m} | {p} | {c} | {a} |" for m, p, c, a in counts) + "\n",
            "## Is the CVSS correct?\n", jury_section(con), severity_section(con), cvss_section(con, "3.1"),
            cvss_section(con, "4.0"), cwe_section(con), ssvc_section(con), judgment_rules_section(con),
            description_elements_section(con),
        ]
    return "\n".join(parts)


def main(argv: list[str] | None = None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--db", type=Path, default=config.DB_PATH)
    p.add_argument("--answers-db", type=Path, default=config.ANSWERS_DB_PATH)
    p.add_argument("--out", type=Path, default=config.PROJECT_ROOT / "data" / "reports" / "results.md")
    p.add_argument("--experimental", action="store_true", help="also report the shelved CVSS/CWE/SSVC experiments")
    args = p.parse_args(argv)
    con = connect(args.db, args.answers_db)
    text = report(con, experimental=args.experimental)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text)
    print(text)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()

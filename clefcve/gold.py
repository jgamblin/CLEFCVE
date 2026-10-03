"""Hand-labeled gold set: export a stratified sample to CSV for labeling, then import the labels.

  python -m clefcve.gold export [--n 150]   # writes data/gold/to_label.csv
  python -m clefcve.gold import FILE.csv      # loads labels into the `gold` table

Label columns (leave blank if unsure):
  is_vuln          y / n
  desc_clarity     0-4 (Unusable, Poor, Adequate, Good, Excellent)
  cwe_ok           y / n   (is the assigned CWE acceptable?)
  better_cwe       e.g. CWE-79, if cwe_ok = n
  cvss31_vector    your own CVSS:3.1/... vector, if you want to score CVSS
  notes            free text
"""

import argparse
import csv
from pathlib import Path

import duckdb

from . import config

LABEL_COLUMNS = ["is_vuln", "desc_clarity", "cwe_ok", "better_cwe", "cvss31_vector", "notes"]
GOLD_DIR = config.PROJECT_ROOT / "data" / "gold"


def export(con, n: int, seed: int, out: Path) -> int:
    # Up to 3 CVEs per CNA (random), so small CNAs are represented without the big ones (Linux, VulnCheck,
    # GitHub_M) swamping the sample; plus ~n/7 REJECTED records, whose original text tests Q1.
    n_rejected = n // 7
    rows = con.execute("""
        WITH pub AS (
            SELECT * FROM (
                SELECT cve_id, state, assigner, title, description, rejected_reason,
                       row_number() OVER (PARTITION BY assigner ORDER BY hash(cve_id || ?::VARCHAR)) AS k
                FROM cves WHERE in_dev_slice AND state = 'PUBLISHED')
            WHERE k <= 3 ORDER BY hash(cve_id || ?::VARCHAR) LIMIT ?),
        rej AS (
            SELECT cve_id, state, assigner, title, description, rejected_reason, 0 AS k
            FROM cves WHERE state = 'REJECTED' ORDER BY hash(cve_id || ?::VARCHAR) LIMIT ?),
        c AS (SELECT * FROM pub UNION ALL SELECT * FROM rej)
        SELECT c.cve_id, c.state, c.assigner, c.title, c.description,
               (SELECT string_agg(DISTINCT cwe_id, ' ') FROM cwes w
                WHERE w.cve_id = c.cve_id AND w.source = 'cna' AND w.cwe_id IS NOT NULL) AS cna_cwe,
               (SELECT any_value(vector) FROM metrics m WHERE m.cve_id = c.cve_id AND m.source = 'cna'
                AND m.version IN ('3.0', '3.1')) AS cna_cvss31,
               c.rejected_reason
        FROM c ORDER BY hash(c.cve_id || ?::VARCHAR)
    """, [seed, seed, n - n_rejected, seed, n_rejected, seed]).fetchall()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cve_id", "state", "assigner", "title", "description", "cna_cwe", "cna_cvss31",
                    "rejected_reason", *LABEL_COLUMNS])
        for r in rows:
            w.writerow([*r, *[""] * len(LABEL_COLUMNS)])
    return len(rows)


def import_labels(con, path: Path) -> int:
    with path.open(newline="") as f:
        rows = [r for r in csv.DictReader(f) if any((r.get(c) or "").strip() for c in LABEL_COLUMNS)]
    con.execute("""CREATE OR REPLACE TABLE gold (cve_id VARCHAR PRIMARY KEY, is_vuln BOOLEAN, desc_clarity INTEGER,
                   cwe_ok BOOLEAN, better_cwe VARCHAR, cvss31_vector VARCHAR, notes VARCHAR)""")

    def yn(v):
        v = (v or "").strip().lower()
        return True if v in ("y", "yes", "true", "1") else False if v in ("n", "no", "false", "0") else None

    for r in rows:
        clarity = (r.get("desc_clarity") or "").strip()
        con.execute("INSERT INTO gold VALUES (?, ?, ?, ?, ?, ?, ?)", [
            r["cve_id"], yn(r.get("is_vuln")), int(clarity) if clarity.isdigit() else None, yn(r.get("cwe_ok")),
            (r.get("better_cwe") or "").strip() or None, (r.get("cvss31_vector") or "").strip() or None,
            (r.get("notes") or "").strip() or None])
    return len(rows)


def main(argv: list[str] | None = None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("--n", type=int, default=150)
    e.add_argument("--seed", type=int, default=7)
    e.add_argument("--out", type=Path, default=GOLD_DIR / "to_label.csv")
    i = sub.add_parser("import")
    i.add_argument("file", type=Path)
    p.add_argument("--db", default=str(config.DB_PATH))
    args = p.parse_args(argv)

    if args.cmd == "export":
        con = duckdb.connect(args.db, read_only=True)
        print(f"wrote {export(con, args.n, args.seed, args.out)} rows to {args.out}")
    else:
        con = duckdb.connect(args.db)
        print(f"imported {import_labels(con, args.file)} labeled rows into `gold`")


if __name__ == "__main__":
    main()

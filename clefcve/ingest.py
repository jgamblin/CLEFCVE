"""Stage 1: load CVEs published (or rejected) in the last N days into DuckDB.

Usage: python -m clefcve.ingest [--days 60] [--repo ~/Data/cvelistV5] [--db data/clefcve.duckdb]
"""

import argparse
import json
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import duckdb
import pyarrow as pa

from . import config
from .gitrepo import BlobReader, changed_paths, head_info, since_for
from .normalize import normalize, parse_ts, sha256

SCHEMA = """
CREATE OR REPLACE TABLE ingest_run (
    ingested_at TIMESTAMPTZ, repo_path VARCHAR, repo_sha VARCHAR, repo_head_time TIMESTAMPTZ,
    window_days INTEGER, dev_slice_days INTEGER, window_start TIMESTAMPTZ, stats JSON
);
CREATE OR REPLACE TABLE cves (
    cve_id VARCHAR PRIMARY KEY, state VARCHAR, assigner VARCHAR, assigner_org_id VARCHAR,
    date_reserved TIMESTAMPTZ, date_published TIMESTAMPTZ, date_updated TIMESTAMPTZ,
    date_rejected TIMESTAMPTZ, window_date TIMESTAMPTZ, in_dev_slice BOOLEAN,
    title VARCHAR, description VARCHAR, description_langs VARCHAR[], rejected_reason VARCHAR,
    cna_tags VARCHAR[], n_affected INTEGER, n_references INTEGER, path VARCHAR,
    record_sha256 VARCHAR, original_commit VARCHAR, record JSON
);
CREATE OR REPLACE TABLE cwes (cve_id VARCHAR, source VARCHAR, cwe_id VARCHAR, description VARCHAR);
CREATE OR REPLACE TABLE metrics (
    cve_id VARCHAR, source VARCHAR, version VARCHAR, vector VARCHAR, base_score DOUBLE, severity VARCHAR
);
CREATE OR REPLACE TABLE ssvc (
    cve_id VARCHAR, source VARCHAR, exploitation VARCHAR, automatable VARCHAR,
    technical_impact VARCHAR, timestamp TIMESTAMPTZ
);
CREATE OR REPLACE TABLE kev (cve_id VARCHAR, source VARCHAR, date_added DATE);
CREATE OR REPLACE TABLE refs (cve_id VARCHAR, source VARCHAR, url VARCHAR, name VARCHAR, tags VARCHAR[]);
CREATE OR REPLACE TABLE affected (
    cve_id VARCHAR, source VARCHAR, vendor VARCHAR, product VARCHAR, default_status VARCHAR, versions JSON
);
"""


def last_published_version(reader: BlobReader, path: str, commits: list[str]) -> tuple[dict, bytes, str] | None:
    """Walk back from the newest commit touching `path` to the last PUBLISHED version."""
    for commit in commits:
        raw = reader.read(f"{commit}^:{path}")
        if raw is None:
            return None  # file didn't exist before this commit: never published
        rec = json.loads(raw)
        if rec["cveMetadata"]["state"] == "PUBLISHED":
            return rec, raw, commit
    return None


def collect(repo: Path, days: int, dev_days: int) -> tuple[dict[str, list[dict]], dict, datetime, str]:
    sha, head_time = head_info(repo)
    window_start = head_time - timedelta(days=days)
    dev_start = head_time - timedelta(days=dev_days)
    paths = changed_paths(repo, since_for(head_time, days, config.GIT_SCAN_MARGIN_DAYS))

    tables: dict[str, list[dict]] = {}
    stats = Counter(paths_touched=len(paths))
    with BlobReader(repo) as reader:
        for path, commits in paths.items():
            raw = reader.read(f"HEAD:{path}")
            if raw is None:
                stats["missing_at_head"] += 1
                continue
            current = json.loads(raw)
            meta = current["cveMetadata"]
            state = meta["state"]
            window_date = parse_ts(meta.get("dateRejected" if state == "REJECTED" else "datePublished"))
            if window_date is None:
                stats[f"no_date_{state.lower()}"] += 1
                continue
            if window_date < window_start:
                stats[f"outside_window_{state.lower()}"] += 1
                continue

            if state == "REJECTED":
                found = last_published_version(reader, path, commits)
                if found is None:
                    stats["rejected_never_published"] += 1
                    continue
                content, content_raw, commit = found
                rows = normalize(current, content, path=path,
                                 content_sha256=sha256(content_raw), original_commit=commit)
            else:
                rows = normalize(current, current, path=path, content_sha256=sha256(raw))

            rows["cves"][0]["window_date"] = window_date
            rows["cves"][0]["in_dev_slice"] = window_date >= dev_start
            stats[state.lower()] += 1
            for name, rs in rows.items():
                tables.setdefault(name, []).extend(rs)

    run = {
        "ingested_at": datetime.now(timezone.utc), "repo_path": str(repo), "repo_sha": sha,
        "repo_head_time": head_time, "window_days": days, "dev_slice_days": dev_days,
        "window_start": window_start, "stats": json.dumps(dict(stats)),
    }
    tables["ingest_run"] = [run]
    return tables, dict(stats), head_time, sha


def write(db_path: Path, tables: dict[str, list[dict]]):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(db_path))
    con.execute(SCHEMA)
    for name, rows in tables.items():
        if rows:
            arrow = pa.Table.from_pylist(rows)  # noqa: F841 (referenced by name in SQL)
            con.execute(f"INSERT INTO {name} BY NAME SELECT * FROM arrow")
    con.close()


def main(argv: list[str] | None = None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--repo", type=Path, default=config.CVELIST_REPO)
    p.add_argument("--db", type=Path, default=config.DB_PATH)
    p.add_argument("--days", type=int, default=config.WINDOW_DAYS)
    p.add_argument("--dev-days", type=int, default=config.DEV_SLICE_DAYS)
    args = p.parse_args(argv)

    t0 = time.monotonic()
    tables, stats, head_time, sha = collect(args.repo.expanduser(), args.days, args.dev_days)
    write(args.db, tables)
    print(f"repo {sha[:12]} @ {head_time.isoformat()}  window {args.days}d (dev slice {args.dev_days}d)")
    for k, v in sorted(stats.items()):
        print(f"  {k:28} {v:>7}")
    print("rows: " + ", ".join(f"{n}={len(r)}" for n, r in tables.items()))
    print(f"wrote {args.db} in {time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    main()

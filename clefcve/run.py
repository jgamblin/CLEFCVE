"""Stage 3: ask a question pack about a set of CVEs and cache the answers in DuckDB.

Usage:
  python -m clefcve.run --pack description --model clef-flash --slice all
  python -m clefcve.run --pack experimental/cvss31 --model clef --sample 300

Answers are cached per (cve, item, record hash, model, question, question hash): rerunning only asks
what is missing, and editing a question's wording re-asks just that question.

Answers live in their own DuckDB file (data/answers.duckdb), opened only briefly per flush, so the
corpus DB and results stay readable while a long run is in progress.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import pyarrow as pa

from . import config
from .clef import ClefError, decide, load_pack

ANSWERS_DDL = """
CREATE TABLE IF NOT EXISTS answers (
    cve_id VARCHAR, item VARCHAR, record_sha256 VARCHAR, model VARCHAR, pack VARCHAR,
    question_id VARCHAR, question_hash VARCHAR, type VARCHAR,
    choice VARCHAR, p_true DOUBLE, score DOUBLE, confidence DOUBLE, probabilities JSON,
    request_ms DOUBLE, answered_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS answer_errors (
    cve_id VARCHAR, item VARCHAR, model VARCHAR, pack VARCHAR, error VARCHAR, failed_at TIMESTAMPTZ
);
"""


# ---- state builders: (cve row, context) -> [(item, state)] ----

def _description_only(cve: dict, ctx: dict) -> list[tuple[str, dict]]:
    state = {"description": cve["description"]}
    if cve["title"]:
        state = {"title": cve["title"], **state}
    return [("", state)]


def _description_with_cwe(cve: dict, ctx: dict) -> list[tuple[str, dict]]:
    out = []
    for cwe_id in ctx["cna_cwes"].get(cve["cve_id"], []):
        entry = ctx["catalog"].get(cwe_id)
        if entry is None:
            continue
        out.append((cwe_id, {
            "description": cve["description"],
            "assigned_cwe": f"{cwe_id}: {entry['name']}",
            "cwe_definition": entry["description"],
        }))
    return out


STATE_BUILDERS = {"description_only": _description_only, "description_with_cwe": _description_with_cwe}


def _context(con, pack: dict) -> dict:
    ctx = {}
    if pack["state"] == "description_with_cwe":
        ctx["catalog"] = {r[0]: {"name": r[1], "description": r[2]} for r in con.execute(
            "SELECT cwe_id, name, description FROM cwe_catalog").fetchall()}
        ctx["cna_cwes"] = {}
        for cve_id, cwe_id in con.execute(
                "SELECT DISTINCT cve_id, cwe_id FROM cwes WHERE source = 'cna' AND cwe_id IS NOT NULL "
                "ORDER BY ALL").fetchall():
            ctx["cna_cwes"].setdefault(cve_id, []).append(cwe_id)
    return ctx


def select_cves(con, *, slice_: str, sample: int | None, seed: int, include_rejected: bool,
                ids: list[str] | None, assigner: str | None) -> list[dict]:
    where, params = ["state = 'PUBLISHED'"], []
    if slice_ == "dev":
        where.append("in_dev_slice")
    if assigner:
        where.append("assigner = ?")
        params.append(assigner)
    if ids:
        where = [f"cve_id IN ({','.join('?' * len(ids))})"]
        params = list(ids)
    sql = (f"SELECT cve_id, title, description, record_sha256 FROM cves WHERE {' AND '.join(where)} "
           f"ORDER BY hash(cve_id || ?::VARCHAR)")
    params.append(seed)
    if sample and not ids:
        sql += f" LIMIT {int(sample)}"
    rows = con.execute(sql, params).fetchall()
    if include_rejected and not ids:
        rows += con.execute("SELECT cve_id, title, description, record_sha256 FROM cves "
                            "WHERE state = 'REJECTED' ORDER BY cve_id").fetchall()
    return [dict(zip(("cve_id", "title", "description", "record_sha256"), r)) for r in rows]


def _answer_row(job: dict, qid: str, ans: dict, ms: float) -> dict:
    probs = ans.get("probabilities")
    return {
        "cve_id": job["cve_id"], "item": job["item"], "record_sha256": job["record_sha256"],
        "model": job["model"], "pack": job["pack"], "question_id": qid, "question_hash": job["hashes"][qid],
        "type": ans.get("type"), "choice": ans.get("choice"), "p_true": ans.get("noul"),
        "score": ans.get("score"), "confidence": ans.get("confidence"),
        "probabilities": json.dumps(probs) if probs is not None else None,
        "request_ms": ms, "answered_at": datetime.now(timezone.utc),
    }


def connect_retry(path, read_only: bool = False, attempts: int = 60) -> duckdb.DuckDBPyConnection:
    """DuckDB allows one writer process per file; wait out brief locks held by another process."""
    for i in range(attempts):
        try:
            return duckdb.connect(str(path), read_only=read_only)
        except duckdb.IOException:
            if i == attempts - 1:
                raise
            time.sleep(1)
    raise AssertionError("unreachable")


def _write(answers_db, rows: list[dict] | None = None, error: list | None = None):
    con = connect_retry(answers_db)
    try:
        con.execute(ANSWERS_DDL)
        if rows:
            arrow = pa.Table.from_pylist(rows)  # noqa: F841 (referenced by name in SQL)
            con.execute("INSERT INTO answers BY NAME SELECT * FROM arrow")
        if error:
            con.execute("INSERT INTO answer_errors VALUES (?, ?, ?, ?, ?, ?)", error)
    finally:
        con.close()


def run(corpus_db, answers_db, pack: dict, model: str, cves: list[dict], limit_s: float | None = None) -> dict:
    con = connect_retry(corpus_db, read_only=True)
    ctx = _context(con, pack)
    con.close()
    build = STATE_BUILDERS[pack["state"]]

    _write(answers_db)  # ensure tables exist
    con = connect_retry(answers_db, read_only=True)
    # Keyed by question hash, not pack name, so moving a question between packs keeps its cached answers.
    have = set(con.execute(
        "SELECT cve_id, item, record_sha256, question_id, question_hash FROM answers WHERE model = ?",
        [model]).fetchall())
    con.close()
    jobs = []
    for cve in cves:
        for item, state in build(cve, ctx):
            missing = {qid: q for qid, q in pack["questions"].items()
                       if (cve["cve_id"], item, cve["record_sha256"], qid, pack["hashes"][qid]) not in have}
            if missing:
                jobs.append({"cve_id": cve["cve_id"], "item": item, "record_sha256": cve["record_sha256"],
                             "model": model, "pack": pack["pack"], "hashes": pack["hashes"],
                             "state": state, "questions": missing})

    stats = {"cves": len(cves), "requests": len(jobs), "done": 0, "errors": 0, "ms": []}
    print(f"{pack['pack']} / {model}: {len(cves)} CVEs -> {len(jobs)} requests to send", file=sys.stderr)
    # Sequential on purpose: Ollama serializes decision requests, so parallel clients gain nothing.
    t0, pending = time.monotonic(), []
    for job in jobs:
        try:
            answers, ms = decide(model, job["state"], job["questions"])
        except ClefError as e:
            stats["errors"] += 1
            _write(answers_db, error=[job["cve_id"], job["item"], model, job["pack"], str(e)[:1000],
                                      datetime.now(timezone.utc)])
            continue
        pending.extend(_answer_row(job, qid, ans, ms) for qid, ans in answers.items())
        stats["done"] += 1
        stats["ms"].append(ms)
        if stats["done"] % 10 == 0:
            _write(answers_db, pending)
            pending.clear()
        if stats["done"] % 25 == 0:
            rate = stats["done"] / (time.monotonic() - t0)
            eta = (len(jobs) - stats["done"]) / rate
            print(f"  {stats['done']}/{len(jobs)}  {1 / rate:.1f} s/req  eta {eta / 60:.1f} min", file=sys.stderr)
        if limit_s and time.monotonic() - t0 > limit_s:
            print("  time limit reached; stopping", file=sys.stderr)
            break
    _write(answers_db, pending)
    ms = sorted(stats.pop("ms")) or [0]
    stats.update(wall_s=round(time.monotonic() - t0, 1), median_ms=round(ms[len(ms) // 2]))
    return stats


def main(argv: list[str] | None = None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--pack", required=True)
    p.add_argument("--model", default="clef-flash")
    p.add_argument("--db", default=str(config.DB_PATH))
    p.add_argument("--answers-db", default=str(config.ANSWERS_DB_PATH))
    p.add_argument("--slice", dest="slice_", choices=["dev", "all"], default="dev")
    p.add_argument("--sample", type=int)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--include-rejected", action="store_true")
    p.add_argument("--ids", help="comma-separated CVE IDs (overrides slice/sample)")
    p.add_argument("--assigner")
    p.add_argument("--time-limit-min", type=float)
    p.add_argument("--questions", help="comma-separated subset of the pack's question ids")
    p.add_argument("--ids-file", type=Path, help="file with one CVE ID per line (overrides slice/sample)")
    args = p.parse_args(argv)

    pack = load_pack(args.pack)
    if args.questions:
        keep = args.questions.split(",")
        unknown = set(keep) - set(pack["questions"])
        if unknown:
            raise SystemExit(f"not in pack {pack['pack']}: {', '.join(sorted(unknown))}")
        pack["questions"] = {q: pack["questions"][q] for q in keep}
    ids = args.ids.split(",") if args.ids else None
    if args.ids_file:
        ids = [line.strip() for line in args.ids_file.read_text().splitlines() if line.strip()]
    con = connect_retry(args.db, read_only=True)
    cves = select_cves(con, slice_=args.slice_, sample=args.sample, seed=args.seed,
                       include_rejected=args.include_rejected,
                       ids=ids, assigner=args.assigner)
    con.close()
    stats = run(args.db, args.answers_db, pack, args.model, cves,
                limit_s=args.time_limit_min * 60 if args.time_limit_min else None)
    print(json.dumps(stats))


if __name__ == "__main__":
    main()

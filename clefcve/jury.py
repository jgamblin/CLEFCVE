"""A panel of general-purpose local LLMs that scores CVSS v3.1 and CWE fit, used as a reference for Clef.

Usage:
  python -m clefcve.jury --sample 150            # the first 150 of the seed-1 dev sample (where Clef has answers)
  python -m clefcve.jury --ids CVE-2026-12037 --jurors gpt-oss:20b

Each juror answers from the same title + description Clef sees (plus the assigned CWE and its definition for the
CWE question), via Ollama's chat API with a JSON schema. The majority vote per field is the reference label;
fields without a clear majority are reported as "no consensus" rather than forced. Answers are cached in
data/answers.duckdb (table `jury`) per (cve, record hash, juror, prompt hash).
"""

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone

import pyarrow as pa

from . import config
from .clef import OLLAMA_URL
from .run import connect_retry, select_cves

# Diverse vendors on purpose. Qwen 3.8 is excluded: Clef is fine-tuned from it, so it would share Clef's biases.
DEFAULT_JURORS = ["gpt-oss:20b", "granite4.2:30b", "nemotron-3.5-lightning:30b",
                  "foundation-sec-8b-instruct:latest", "qwen3.6:35b"]

CVSS31 = {"AV": ["N", "A", "L", "P"], "AC": ["L", "H"], "PR": ["N", "L", "H"], "UI": ["N", "R"],
          "S": ["U", "C"], "C": ["N", "L", "H"], "I": ["N", "L", "H"], "A": ["N", "L", "H"]}
CWE_FIT = ["exact", "too_general", "too_specific", "impact_not_cause", "related_but_wrong", "wrong"]

SYSTEM = """You are an expert vulnerability analyst. You score CVE records strictly from the text provided.

CVSS v3.1 base metrics (choose the single best value for each):
- AV Attack Vector: N network (remotely exploitable across a routed network) | A adjacent (same local/Bluetooth/Wi-Fi network) | L local (local access, or a user opening a malicious file) | P physical.
- AC Attack Complexity: L no special conditions | H depends on conditions beyond attacker control (race, MITM position, target-specific secrets).
- PR Privileges Required: N unauthenticated | L basic user | H administrator/significant privileges.
- UI User Interaction: N none | R a victim must act (click, open, visit, view).
- S Scope: U impact limited to the vulnerable component | C impact reaches other components (e.g. XSS in the user's browser, sandbox/VM escape).
- C/I/A impact: N none | L limited | H total or serious. Infer from the stated outcome: code execution or full takeover implies H/H/H; a crash or sustained DoS implies A:H; XSS usually implies C:L/I:L/A:N; a pure information leak has I:N/A:N.

CWE fit of the assigned CWE (root cause, not consequence):
exact | too_general (a more specific CWE clearly fits better) | too_specific | impact_not_cause (names a consequence, e.g. info exposure or DoS, rather than the root cause) | related_but_wrong | wrong.
best_cwe: the single CWE ID (e.g. "CWE-787") you would assign.

Respond with JSON only."""


def schema(with_cwe: bool) -> dict:
    props = {m: {"type": "string", "enum": vals} for m, vals in CVSS31.items()}
    props["best_cwe"] = {"type": "string", "pattern": "^CWE-[0-9]+$"}
    if with_cwe:
        props["cwe_fit"] = {"type": "string", "enum": CWE_FIT}
    return {"type": "object", "properties": props, "required": list(props)}


def user_prompt(cve: dict, cwe: dict | None) -> str:
    parts = [f"Title: {cve['title']}" if cve.get("title") else "", f"Description:\n{cve['description']}"]
    if cwe:
        parts.append(f"Assigned CWE: {cwe['cwe_id']}: {cwe['name']}\nCWE definition: {cwe['definition']}")
    else:
        parts.append("No CWE is assigned; still give best_cwe.")
    return "\n\n".join(p for p in parts if p)


PROMPT_HASH = hashlib.sha256((SYSTEM + json.dumps(schema(True), sort_keys=True)).encode()).hexdigest()[:16]


def ask(juror: str, cve: dict, cwe: dict | None, timeout: float = 900) -> tuple[dict, float]:
    body = {"model": juror, "stream": False, "format": schema(cwe is not None),
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user_prompt(cve, cwe)}],
            "options": {"temperature": 0, "num_ctx": 8192}}
    # Reasoning models: keep thinking short. gpt-oss takes an effort level; the others accept false.
    body["think"] = "low" if juror.startswith("gpt-oss") else False
    req = urllib.request.Request(f"{OLLAMA_URL}/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 400 and "think" in body:  # model doesn't support the think flag
            body.pop("think")
            req = urllib.request.Request(f"{OLLAMA_URL}/api/chat", data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.load(resp)
        else:
            raise
    return json.loads(payload["message"]["content"]), (time.monotonic() - t0) * 1000


JURY_DDL = """CREATE TABLE IF NOT EXISTS jury (
    cve_id VARCHAR, record_sha256 VARCHAR, juror VARCHAR, prompt_hash VARCHAR, cwe_id VARCHAR,
    answer JSON, request_ms DOUBLE, answered_at TIMESTAMPTZ)"""


def _write(rows: list[dict]):
    con = connect_retry(config.ANSWERS_DB_PATH)
    try:
        con.execute(JURY_DDL)
        if rows:
            arrow = pa.Table.from_pylist(rows)  # noqa: F841 (referenced by name in SQL)
            con.execute("INSERT INTO jury BY NAME SELECT * FROM arrow")
    finally:
        con.close()


def run(cves: list[dict], jurors: list[str]) -> None:
    con = connect_retry(config.DB_PATH, read_only=True)
    first_cwe = {}
    for cve_id, cwe_id, name, definition in con.execute("""
            SELECT w.cve_id, w.cwe_id, k.name, k.description FROM cwes w JOIN cwe_catalog k USING (cwe_id)
            WHERE w.source = 'cna' QUALIFY row_number() OVER (PARTITION BY w.cve_id ORDER BY w.cwe_id) = 1
            """).fetchall():
        first_cwe[cve_id] = {"cwe_id": cwe_id, "name": name, "definition": definition}
    con.close()

    _write([])
    con = connect_retry(config.ANSWERS_DB_PATH, read_only=True)
    have = set(con.execute("SELECT cve_id, record_sha256, juror FROM jury WHERE prompt_hash = ?",
                           [PROMPT_HASH]).fetchall())
    con.close()

    # Juror-major order: each model loads once and stays warm for its whole batch.
    for juror in jurors:
        todo = [c for c in cves if (c["cve_id"], c["record_sha256"], juror) not in have]
        print(f"{juror}: {len(todo)} CVEs to ask", file=sys.stderr)
        pending, t0 = [], time.monotonic()
        for n, cve in enumerate(todo, 1):
            cwe = first_cwe.get(cve["cve_id"])
            try:
                answer, ms = ask(juror, cve, cwe)
            except Exception as e:  # one bad response shouldn't stop the panel
                print(f"  {cve['cve_id']}: {type(e).__name__}: {str(e)[:200]}", file=sys.stderr)
                continue
            pending.append({"cve_id": cve["cve_id"], "record_sha256": cve["record_sha256"], "juror": juror,
                            "prompt_hash": PROMPT_HASH, "cwe_id": cwe["cwe_id"] if cwe else None,
                            "answer": json.dumps(answer), "request_ms": ms,
                            "answered_at": datetime.now(timezone.utc)})
            if n % 10 == 0 or n == len(todo):
                _write(pending)
                pending.clear()
                el = time.monotonic() - t0
                print(f"  {n}/{len(todo)}  {el / n:.1f} s/CVE  eta {(len(todo) - n) * el / n / 60:.1f} min",
                      file=sys.stderr)


def consensus(votes: list[str], quorum: int) -> str | None:
    """Majority value if at least `quorum` jurors agree, else None (no consensus)."""
    if not votes:
        return None
    value, count = Counter(votes).most_common(1)[0]
    return value if count >= quorum else None


def main(argv: list[str] | None = None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--jurors", default=",".join(DEFAULT_JURORS))
    p.add_argument("--sample", type=int, default=150)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--ids")
    args = p.parse_args(argv)
    con = connect_retry(config.DB_PATH, read_only=True)
    cves = select_cves(con, slice_="dev", sample=args.sample, seed=args.seed, include_rejected=False,
                       ids=args.ids.split(",") if args.ids else None, assigner=None)
    con.close()
    run(cves, args.jurors.split(","))


if __name__ == "__main__":
    main()

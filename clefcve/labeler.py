"""Local web app for hand-labeling the gold set.

Usage: python -m clefcve.labeler [--port 8765]   then open http://127.0.0.1:8765

Labels the CVEs in gold/to_label.csv (see `clefcve.gold export`) and saves every change to
gold/labels.json. Label options mirror the Clef question packs so `clefcve.evaluate` can compare them directly.
"""

import argparse
import csv
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import config
from .run import connect_retry

GOLD_DIR = config.PROJECT_ROOT / "gold"
LABELS_PATH = GOLD_DIR / "labels.json"
SAMPLE_PATH = GOLD_DIR / "to_label.csv"
PAGE = Path(__file__).with_name("labeler.html")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# Questions whose Clef answers are shown after labeling, in display order.
REVEAL_QUESTIONS = ["security_impact_stated", "impact_basis", "desc_clarity"]

_lock = threading.Lock()


def load_labels(path: Path = LABELS_PATH) -> dict:
    return json.loads(path.read_text()) if path.exists() else {}


def save_label(cve_id: str, label: dict, path: Path = LABELS_PATH) -> dict:
    with _lock:
        labels = load_labels(path)
        if label:
            labels[cve_id] = {**label, "labeled_at": datetime.now(timezone.utc).isoformat()}
        else:
            labels.pop(cve_id, None)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(labels, f, indent=1, sort_keys=True)
        os.replace(tmp, path)  # atomic: a crash never leaves a half-written labels file
    return labels


def is_done(label: dict | None) -> bool:
    """A CVE counts as labeled once the two required answers (Q1 and clarity) are set."""
    return bool(label) and label.get("security_impact") is not None and label.get("desc_clarity") is not None


def sample_ids() -> list[str]:
    with SAMPLE_PATH.open(newline="") as f:
        return [r["cve_id"] for r in csv.DictReader(f)]


def item(cve_id: str) -> dict | None:
    con = connect_retry(config.DB_PATH, read_only=True)
    try:
        row = con.execute("""SELECT cve_id, state, assigner, title, description, rejected_reason,
                                    date_published::DATE::VARCHAR
                             FROM cves WHERE cve_id = ?""", [cve_id]).fetchone()
        if row is None:
            return None
        keys = ("cve_id", "state", "assigner", "title", "description", "rejected_reason", "published")
        out = dict(zip(keys, row))
        out["cwes"] = [dict(zip(("cwe_id", "text", "name", "definition", "usage"), r)) for r in con.execute("""
            SELECT w.cwe_id, w.description, k.name, k.description, k.usage
            FROM cwes w LEFT JOIN cwe_catalog k USING (cwe_id)
            WHERE w.cve_id = ? AND w.source = 'cna' ORDER BY w.cwe_id""", [cve_id]).fetchall()]
        out["cvss"] = [dict(zip(("version", "vector", "score", "severity"), r)) for r in con.execute("""
            SELECT version, vector, base_score, severity FROM metrics
            WHERE cve_id = ? AND source = 'cna' ORDER BY version DESC""", [cve_id]).fetchall()]
        out["affected"] = [dict(zip(("vendor", "product", "versions"), (r[0], r[1], json.loads(r[2] or "[]"))))
                           for r in con.execute("""SELECT vendor, product, versions FROM affected
                                                   WHERE cve_id = ? AND source = 'cna'""", [cve_id]).fetchall()]
        out["references"] = [r[0] for r in con.execute(
            "SELECT url FROM refs WHERE cve_id = ? AND source = 'cna' LIMIT 10", [cve_id]).fetchall()]
        out["lint_flags"] = [dict(zip(("check", "rule", "level", "status", "detail"), r)) for r in con.execute("""
            SELECT check_id, rule, level, status, detail FROM lint
            WHERE cve_id = ? AND status IN ('fail', 'warn') ORDER BY level, check_id""", [cve_id]).fetchall()]
    finally:
        con.close()
    return out


def clef_answers(cve_id: str) -> dict:
    """Latest answer per (model, question, item) from the answers DB; empty if none yet."""
    if not config.ANSWERS_DB_PATH.exists():
        return {}
    con = connect_retry(config.ANSWERS_DB_PATH, read_only=True)
    try:
        rows = con.execute(f"""
            SELECT model, question_id, item, choice, p_true, score, confidence FROM answers
            WHERE cve_id = ? AND question_id IN ({','.join('?' * len(REVEAL_QUESTIONS))})
            QUALIFY row_number() OVER (PARTITION BY model, question_id, item ORDER BY answered_at DESC) = 1
        """, [cve_id, *REVEAL_QUESTIONS]).fetchall()
    finally:
        con.close()
    out: dict = {}
    for model, qid, it, choice, p_true, score, conf in rows:
        key = f"{qid}:{it}" if it else qid
        out.setdefault(model, {})[key] = {"choice": choice, "p_true": p_true, "score": score, "confidence": conf}
    return out


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        if path == "/api/items":
            labels = load_labels()
            return self._send(200, [{"cve_id": c, "labeled": is_done(labels.get(c))} for c in sample_ids()])
        m = re.fullmatch(r"/api/item/(CVE-[\d-]+)", path)
        if m and CVE_RE.match(m.group(1)):
            data = item(m.group(1))
            if data is None:
                return self._send(404, {"error": "unknown CVE"})
            data["label"] = load_labels().get(m.group(1))
            return self._send(200, data)
        m = re.fullmatch(r"/api/clef/(CVE-[\d-]+)", path)
        if m and CVE_RE.match(m.group(1)):
            return self._send(200, clef_answers(m.group(1)))
        self._send(404, {"error": "not found"})

    def do_POST(self):
        m = re.fullmatch(r"/api/label/(CVE-[\d-]+)", self.path)
        if not (m and CVE_RE.match(m.group(1))):
            return self._send(404, {"error": "not found"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid JSON"})
        labels = save_label(m.group(1), body if isinstance(body, dict) else {})
        self._send(200, {"ok": True, "labeled": len(labels)})


def main(argv: list[str] | None = None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--port", type=int, default=8765)
    args = p.parse_args(argv)
    if not SAMPLE_PATH.exists():
        raise SystemExit(f"{SAMPLE_PATH} not found; run `python -m clefcve.gold export` first")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Labeling {len(sample_ids())} CVEs at http://127.0.0.1:{args.port}  (labels -> {LABELS_PATH})")
    server.serve_forever()


if __name__ == "__main__":
    main()

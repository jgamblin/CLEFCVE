"""Minimal client for Ollama's decision endpoint plus question-pack loading."""

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

from . import config

OLLAMA_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
QUESTIONS_DIR = config.PROJECT_ROOT / "questions"


class ClefError(RuntimeError):
    pass


def decide(model: str, state, questions: dict, timeout: float = 600, retries: int = 2) -> tuple[dict, float]:
    """POST /v1/systemone. Returns (answers keyed by question id, elapsed ms)."""
    body = json.dumps({"model": model, "state": state, "questions": questions}).encode()
    for attempt in range(retries + 1):
        req = urllib.request.Request(f"{OLLAMA_URL}/v1/systemone", data=body,
                                     headers={"Content-Type": "application/json"})
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.load(resp)
            return payload["answers"], (time.monotonic() - t0) * 1000
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            if e.code < 500 or attempt == retries:
                raise ClefError(f"HTTP {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == retries:
                raise ClefError(str(e)) from e
        time.sleep(2 ** attempt)
    raise AssertionError("unreachable")


def _normalize_question(q: dict) -> dict:
    q = dict(q)
    if isinstance(q.get("criteria"), dict):
        # YAML turns unquoted true/false keys into booleans; the API wants "true"/"false".
        q["criteria"] = {(str(k).lower() if isinstance(k, bool) else str(k)): v for k, v in q["criteria"].items()}
    return q


def question_hash(q: dict) -> str:
    return hashlib.sha256(json.dumps(q, sort_keys=True).encode()).hexdigest()[:16]


def load_pack(name_or_path: str) -> dict:
    path = Path(name_or_path)
    if not path.suffix:
        path = QUESTIONS_DIR / f"{name_or_path}.yaml"
    pack = yaml.safe_load(path.read_text())
    pack["questions"] = {qid: _normalize_question(q) for qid, q in pack["questions"].items()}
    pack["hashes"] = {qid: question_hash(q) for qid, q in pack["questions"].items()}
    if len(pack["questions"]) > 64:
        raise ValueError(f"{path}: {len(pack['questions'])} questions; the API allows at most 64 per request")
    return pack

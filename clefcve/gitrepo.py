"""Thin helpers over the cvelistV5 git clone."""

import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


def head_info(repo: Path) -> tuple[str, datetime]:
    sha, iso = _git(repo, "log", "-1", "--format=%H %cI", "HEAD").split()
    return sha, datetime.fromisoformat(iso)


def changed_paths(repo: Path, since: datetime) -> dict[str, list[str]]:
    """Map each cves/**.json path touched since `since` to its commits, newest first."""
    out = _git(
        repo, "log", f"--since={since.isoformat()}", "--format=C %H", "--name-only", "--", "cves/"
    )
    commits: dict[str, list[str]] = defaultdict(list)
    current = None
    for line in out.splitlines():
        if line.startswith("C "):
            current = line[2:]
        elif current and line.rsplit("/", 1)[-1].startswith("CVE-") and line.endswith(".json"):
            commits[line].append(current)
    return dict(commits)


class BlobReader:
    """Reads `<rev>:<path>` blobs through one long-lived `git cat-file --batch`."""

    def __init__(self, repo: Path):
        self._proc = subprocess.Popen(
            ["git", "-C", str(repo), "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

    def read(self, spec: str) -> bytes | None:
        self._proc.stdin.write(spec.encode() + b"\n")
        self._proc.stdin.flush()
        header = self._proc.stdout.readline().split()
        if len(header) < 3 or header[1] != b"blob":
            return None  # "<spec> missing" or not a blob
        data = self._proc.stdout.read(int(header[2]))
        self._proc.stdout.read(1)  # trailing newline
        return data

    def close(self):
        self._proc.stdin.close()
        self._proc.wait()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def since_for(head_time: datetime, days: int, margin_days: int) -> datetime:
    return head_time - timedelta(days=days + margin_days)

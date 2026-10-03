import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CVELIST_REPO = Path(os.environ.get("CLEFCVE_REPO", "~/Data/cvelistV5")).expanduser()
DB_PATH = Path(os.environ.get("CLEFCVE_DB", PROJECT_ROOT / "data" / "clefcve.duckdb"))

# Corpus window, in days before the repo HEAD commit time.
WINDOW_DAYS = 60
DEV_SLICE_DAYS = 30

# Extra days of git history to scan past the window, so records whose commit
# timestamp lags their datePublished/dateRejected aren't missed.
GIT_SCAN_MARGIN_DAYS = 3

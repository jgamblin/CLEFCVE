#!/usr/bin/env bash
# Cascade step 2: Clef 27B re-checks the security-impact answer wherever Clef Flash said "no impact stated",
# except the Linux kernel CNA, where 27B and Flash already agree; 300 random Linux CVEs are re-checked to confirm that.
# Run after scripts/full_corpus.sh. Cached and time-limited per chunk; rerun until 0 requests remain.
set -euo pipefail
cd "$(dirname "$0")/.."
IDS=data/confirm_ids.txt
.venv/bin/python - "$IDS" <<'PY'
import sys
from clefcve import config
from clefcve.run import connect_retry
con = connect_retry(config.DB_PATH, read_only=True)
con.execute(f"ATTACH '{config.ANSWERS_DB_PATH}' AS a (READ_ONLY)")
ids = [r[0] for r in con.execute("""
    WITH flagged AS (
        SELECT DISTINCT x.cve_id, c.assigner FROM a.answers x JOIN cves c USING (cve_id)
        WHERE x.model = 'clef-flash' AND x.question_id = 'security_impact_stated' AND x.p_true < 0.5
          AND c.state = 'PUBLISHED' AND x.record_sha256 = c.record_sha256)
    SELECT cve_id FROM flagged WHERE assigner <> 'Linux'
    UNION
    SELECT cve_id FROM (SELECT cve_id FROM cves WHERE assigner = 'Linux' AND state = 'PUBLISHED'
                        ORDER BY hash(cve_id || 'linux-check') LIMIT 300)
""").fetchall()]
open(sys.argv[1], "w").write("\n".join(ids) + "\n")
print(f"{len(ids)} CVEs to re-check with Clef 27B", file=sys.stderr)
PY
.venv/bin/python -m clefcve.run --pack description --questions security_impact_stated,impact_basis --model clef \
  --ids-file "$IDS" --time-limit-min "${CHUNK_MIN:-110}"

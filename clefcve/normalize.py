"""Flatten CVE JSON 5.x records into rows for the DuckDB tables."""

import hashlib
import json
from datetime import datetime, timezone

CVSS_KEYS = {"cvssV2_0": "2.0", "cvssV3_0": "3.0", "cvssV3_1": "3.1", "cvssV4_0": "4.0"}


def parse_ts(value: str | None) -> datetime | None:
    """Parse a CVE timestamp; a few older records omit the offset, so assume UTC."""
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _english(entries: list[dict] | None) -> str | None:
    if not entries:
        return None
    for e in entries:
        if e.get("lang", "").lower().startswith("en"):
            return e.get("value")
    return entries[0].get("value")


def _containers(record: dict) -> list[tuple[str, dict]]:
    """(source, container) pairs: 'cna' first, then each ADP by shortName."""
    c = record.get("containers", {})
    out = [("cna", c["cna"])] if "cna" in c else []
    for adp in c.get("adp", []):
        out.append((adp.get("providerMetadata", {}).get("shortName", "adp"), adp))
    return out


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def normalize(current: dict, content: dict, *, path: str, content_sha256: str,
              original_commit: str | None = None) -> dict[str, list[dict]]:
    """Build rows for one CVE.

    `current` is the record at HEAD and supplies metadata (state, dates, rejection).
    `content` supplies descriptions/CWEs/metrics/etc. For a PUBLISHED CVE it is the
    same record; for a REJECTED CVE it is the last PUBLISHED version from git history.
    """
    meta = current["cveMetadata"]
    cve_id = meta["cveId"]
    state = meta["state"]
    cna = content.get("containers", {}).get("cna", {})
    rejected_reason = (
        _english(current["containers"]["cna"].get("rejectedReasons")) if state == "REJECTED" else None
    )

    rows: dict[str, list[dict]] = {
        "cves": [{
            "cve_id": cve_id,
            "state": state,
            "assigner": meta.get("assignerShortName"),
            "assigner_org_id": meta.get("assignerOrgId"),
            "date_reserved": parse_ts(meta.get("dateReserved")),
            "date_published": parse_ts(meta.get("datePublished")),
            "date_updated": parse_ts(meta.get("dateUpdated")),
            "date_rejected": parse_ts(meta.get("dateRejected")),
            "title": cna.get("title"),
            "description": _english(cna.get("descriptions")),
            "description_langs": [d.get("lang") for d in cna.get("descriptions", [])],
            "rejected_reason": rejected_reason,
            "cna_tags": cna.get("tags", []),
            "n_affected": len(cna.get("affected", [])),
            "n_references": len(cna.get("references", [])),
            "path": path,
            "record_sha256": content_sha256,
            "original_commit": original_commit,
            "record": json.dumps(content),
        }],
        "cwes": [], "metrics": [], "ssvc": [], "kev": [], "refs": [], "affected": [],
    }

    for source, cont in _containers(content):
        for pt in cont.get("problemTypes", []):
            for d in pt.get("descriptions", []):
                rows["cwes"].append({
                    "cve_id": cve_id, "source": source,
                    "cwe_id": d.get("cweId"), "description": d.get("description"),
                })
        for m in cont.get("metrics", []):
            for key, version in CVSS_KEYS.items():
                if key in m:
                    v = m[key]
                    rows["metrics"].append({
                        "cve_id": cve_id, "source": source, "version": version,
                        "vector": v.get("vectorString"), "base_score": v.get("baseScore"),
                        "severity": v.get("baseSeverity"),
                    })
            other = m.get("other", {})
            if other.get("type") == "ssvc":
                opts = {k: v for o in other.get("content", {}).get("options", []) for k, v in o.items()}
                rows["ssvc"].append({
                    "cve_id": cve_id, "source": source,
                    "exploitation": opts.get("Exploitation"),
                    "automatable": opts.get("Automatable"),
                    "technical_impact": opts.get("Technical Impact"),
                    "timestamp": parse_ts(other["content"].get("timestamp")),
                })
            elif other.get("type") == "kev":
                rows["kev"].append({
                    "cve_id": cve_id, "source": source,
                    "date_added": other.get("content", {}).get("dateAdded"),
                })
        for ref in cont.get("references", []):
            rows["refs"].append({
                "cve_id": cve_id, "source": source, "url": ref.get("url"),
                "name": ref.get("name"), "tags": ref.get("tags", []),
            })
        for a in cont.get("affected", []):
            rows["affected"].append({
                "cve_id": cve_id, "source": source, "vendor": a.get("vendor"),
                "product": a.get("product"), "default_status": a.get("defaultStatus"),
                "versions": json.dumps(a.get("versions", [])),
            })
    return rows

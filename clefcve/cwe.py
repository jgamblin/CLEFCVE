"""Load the MITRE CWE XML catalog (data/ref/cwec_v*.xml) into a `cwe_catalog` table."""

import xml.etree.ElementTree as ET
from pathlib import Path

import duckdb
import pyarrow as pa

from . import config

NS = "{http://cwe.mitre.org/cwe-7}"
REF_DIR = config.PROJECT_ROOT / "data" / "ref"


def catalog_path() -> Path:
    paths = sorted(REF_DIR.glob("cwec_v*.xml"))
    if not paths:
        raise FileNotFoundError(
            f"No CWE catalog in {REF_DIR}. Download https://cwe.mitre.org/data/xml/cwec_latest.xml.zip and unzip it there."
        )
    return paths[-1]


def _text(el) -> str | None:
    return " ".join("".join(el.itertext()).split()) if el is not None else None


def parse(path: Path) -> tuple[str, list[dict]]:
    root = ET.parse(path).getroot()
    rows = []
    for kind, tag in (("weakness", "Weakness"), ("category", "Category"), ("view", "View")):
        for el in root.iter(f"{NS}{tag}"):
            parents = {}
            for rel in el.iter(f"{NS}Related_Weakness"):
                if rel.get("Nature") == "ChildOf" and rel.get("Ordinal") == "Primary":
                    parents.setdefault(rel.get("View_ID"), int(rel.get("CWE_ID")))
            usage = el.find(f"{NS}Mapping_Notes/{NS}Usage")
            desc = el.find(f"{NS}Description")
            if desc is None:  # categories and views use <Summary>
                desc = el.find(f"{NS}Summary")
            rows.append({
                "cwe_id": f"CWE-{el.get('ID')}",
                "kind": kind,
                "name": el.get("Name"),
                "abstraction": el.get("Abstraction"),
                "status": el.get("Status"),
                "usage": usage.text if usage is not None else None,
                "description": _text(desc),
                "parent_1000": f"CWE-{parents['1000']}" if "1000" in parents else None,
                "parent_1003": f"CWE-{parents['1003']}" if "1003" in parents else None,
            })
    return root.get("Version"), rows


def load(con: duckdb.DuckDBPyConnection) -> str:
    version, rows = parse(catalog_path())
    arrow = pa.Table.from_pylist(rows)  # noqa: F841 (referenced by name in SQL)
    con.execute("CREATE OR REPLACE TABLE cwe_catalog AS SELECT * FROM arrow")
    return version

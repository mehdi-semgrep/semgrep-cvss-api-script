#!/usr/bin/env python3
"""Test harness for verifying semgrep_cvss_cli.py output is compatible with ingestor.py."""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def ingest_record(record: List[Any]) -> Dict[str, Any]:
    """
    Ingest a single [data_pool, vuln_obj] record as produced by semgrep_cvss_cli.py.
    Mirrors the logic from ingestor.py exactly.
    """
    if not isinstance(record, list) or len(record) != 2:
        raise ValueError(f"Expected [data, vuln_obj], got: {type(record)}")

    data: List[Any] = record[0]
    vuln_obj: Dict[str, Any] = record[1]

    if not isinstance(data, list):
        raise ValueError(f"data pool must be a list, got: {type(data)}")
    if not isinstance(vuln_obj, dict):
        raise ValueError(f"vuln_obj must be a dict, got: {type(vuln_obj)}")

    result: Dict[str, Any] = {}

    # Pass through scalar fields directly from vuln_obj
    for field in (
        "finding_id",
        "issue_type",
        "severity",
        "status",
        "epss_score",
        "epss_percentile",
        "final_priority_score",
        "scoring_method",
        "rationale",
        "confidence",
    ):
        result[field] = vuln_obj.get(field)

    # Resolve CVSS vector from cvssSources (primary source)
    # --- ingestor.py (verbatim) ---
    cvss_idx = vuln_obj.get("cvssSources")
    if isinstance(cvss_idx, int) and cvss_idx < len(data):
        cvss_sources = data[cvss_idx]
        if isinstance(cvss_sources, list):
            for src_idx in cvss_sources:
                if isinstance(src_idx, int) and src_idx < len(data):
                    src_obj = data[src_idx]
                    if isinstance(src_obj, dict):
                        type_idx = src_obj.get("type")
                        type_val = data[type_idx] if isinstance(type_idx, int) and type_idx < len(data) else type_idx
                        if type_val == "primary":
                            vec_idx = src_obj.get("vector")
                            if isinstance(vec_idx, int) and vec_idx < len(data):
                                result["cvss_vector"] = data[vec_idx]
                            elif isinstance(vec_idx, str):
                                result["cvss_vector"] = vec_idx
                            score_idx = src_obj.get("score")
                            if isinstance(score_idx, int) and score_idx < len(data):
                                result["cvss_base_score"] = data[score_idx]
                            elif isinstance(score_idx, (int, float)):
                                result["cvss_base_score"] = score_idx
                            break
    # --- end ingestor.py ---

    return result


def ingest_file(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        records = json.load(f)
    if not isinstance(records, list):
        raise ValueError("Output file must contain a JSON array")
    return [ingest_record(r) for r in records]


def validate_ingested(records: List[Dict[str, Any]]) -> List[str]:
    errors: List[str] = []
    for i, rec in enumerate(records):
        fid = rec.get("finding_id", f"[{i}]")
        if not rec.get("cvss_vector"):
            errors.append(f"finding {fid}: missing cvss_vector")
        elif not str(rec["cvss_vector"]).startswith("CVSS:"):
            errors.append(f"finding {fid}: cvss_vector does not look like a CVSS vector: {rec['cvss_vector']!r}")
        if rec.get("cvss_base_score") is None:
            errors.append(f"finding {fid}: missing cvss_base_score")
        elif not isinstance(rec["cvss_base_score"], (int, float)):
            errors.append(f"finding {fid}: cvss_base_score is not numeric: {rec['cvss_base_score']!r}")
        if not rec.get("finding_id"):
            errors.append(f"finding {fid}: missing finding_id")
    return errors


def run_test(output_file: Optional[str] = None) -> int:
    if output_file:
        path = Path(output_file)
    else:
        # Default: look for the most recently written output
        candidates = list(Path(".").glob("*.json"))
        candidates = [p for p in candidates if p.name not in (".semgrep_checkpoint.json", ".cvss_cache.json")]
        if not candidates:
            print("ERROR: no output JSON file found. Pass the path as an argument or run the CLI first.")
            return 1
        path = max(candidates, key=lambda p: p.stat().st_mtime)
        print(f"Using output file: {path}")

    if not path.exists():
        print(f"ERROR: file not found: {path}")
        return 1

    try:
        ingested = ingest_file(path)
    except Exception as exc:
        print(f"ERROR: failed to ingest {path}: {exc}")
        return 1

    errors = validate_ingested(ingested)

    total = len(ingested)
    ok = total - len(errors)
    print(f"Ingested {total} records: {ok} OK, {len(errors)} errors")

    if errors:
        for err in errors[:20]:
            print(f"  - {err}")
        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} more")
        return 1

    # Print a sample of the first ingested record
    if ingested:
        print("\nSample ingested record (first):")
        print(json.dumps(ingested[0], indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(run_test(arg))

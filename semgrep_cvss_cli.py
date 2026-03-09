#!/usr/bin/env python3
"""Semgrep findings prioritizer with CVSS and EPSS scoring."""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import random
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


OUTPUT_FIELDS: Sequence[str] = (
    "finding_id",
    "issue_type",
    "severity",
    "status",
    "cvssSources",
    "epss_score",
    "epss_percentile",
    "final_priority_score",
    "scoring_method",
    "rationale",
    "confidence",
)

VALID_ISSUE_TYPES = {"sast", "sca"}
BASE_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
ENV_METRIC_ORDER = ("CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA")
DEFAULT_SAST_PRECEDENCE = (
    "vulnerability_classes",
    "cwe",
    "owasp",
    "keyword",
    "severity_default",
)
DEFAULT_SAST_FAMILY_TEMPLATES: Dict[str, str] = {
    "sql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "command_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "code_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "insecure_deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    "path_traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "improper_authorization": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "sensitive_data_exposure": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "dos": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "improper_validation": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L",
    "insecure_hashing": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
}
DEFAULT_SAST_STATUS_MULTIPLIERS: Dict[str, float] = {
    "open": 1.0,
    "provisionally_ignored": 0.60,
    "fixed": 0.25,
}
MALICIOUS_KEYS = (
    "malicious",
    "is_malicious",
    "known_malicious",
    "malicious_package",
    "is_known_malicious",
)
TIMESTAMP_KEYS = (
    "updated_at",
    "last_seen_at",
    "created_at",
    "first_seen_at",
    "timestamp",
)
DEFAULT_CHECKPOINT = "/Users/mehdimhamedi/Projects/api/.semgrep_checkpoint.json"

_requests = None
_yaml = None
_CVSS3 = None


class CliValidationError(Exception):
    """Raised for argument/config/auth validation failures."""


class ApiRuntimeError(Exception):
    """Raised for runtime/API failures."""


def ensure_dependencies() -> None:
    """Import third-party dependencies lazily so --help still works without them."""
    global _requests, _yaml, _CVSS3
    missing: List[str] = []
    if _requests is None:
        try:
            import requests as requests_mod  # type: ignore

            _requests = requests_mod
        except Exception:
            missing.append("requests")
    if _yaml is None:
        try:
            import yaml as yaml_mod  # type: ignore

            _yaml = yaml_mod
        except Exception:
            missing.append("PyYAML")
    if _CVSS3 is None:
        try:
            from cvss import CVSS3 as cvss3_cls  # type: ignore

            _CVSS3 = cvss3_cls
        except Exception:
            missing.append("cvss")
    if missing:
        raise CliValidationError(
            "Missing Python dependencies: "
            + ", ".join(missing)
            + ". Install them with: pip install requests PyYAML cvss"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Pull Semgrep findings and score priority with CVSS + EPSS."
    )
    parser.add_argument("--config", required=True, help="Path to scoring-config.yaml")
    parser.add_argument("--deployment-slug", help="Semgrep deployment slug")
    parser.add_argument(
        "--issue-types",
        default="sast,sca",
        help="Comma-separated issue types (default: sast,sca)",
    )
    parser.add_argument("--since", type=int, help="Epoch seconds lower-bound override")
    parser.add_argument(
        "--checkpoint-file",
        default=DEFAULT_CHECKPOINT,
        help=f"Checkpoint file path (default: {DEFAULT_CHECKPOINT})",
    )
    parser.add_argument("--out", help="Output file path (default: stdout)")
    parser.add_argument(
        "--page-size",
        type=int,
        help="Page size override (default: config value, hard max 3000)",
    )
    parser.add_argument("--max-pages", type=int, help="Optional safety page cap per issue type")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=20,
        help="HTTP timeout in seconds (default: 20)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("INFO", "DEBUG", "WARN", "ERROR"),
        help="Logging level (default: INFO)",
    )
    return parser


def setup_logging(level_name: str) -> logging.Logger:
    level = logging._nameToLevel.get(level_name.upper(), logging.INFO)  # type: ignore[attr-defined]
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    logging.Formatter.converter = time.gmtime
    return logging.getLogger("semgrep_cvss_cli")


def load_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise CliValidationError(f"Config file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = _yaml.safe_load(handle)  # type: ignore[union-attr]
    except Exception as exc:
        raise CliValidationError(f"Failed to read config {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CliValidationError("Config root must be a mapping/object")
    return payload


def get_required(mapping: Dict[str, Any], key: str, section: str) -> Any:
    if key not in mapping:
        raise CliValidationError(f"Missing config key '{section}.{key}'")
    return mapping[key]


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def normalize_lookup_key(value: Any) -> str:
    token = str(value or "").strip().lower()
    return re.sub(r"\s+", " ", token)


def extract_cwe_id(value: Any) -> Optional[str]:
    token = str(value or "").upper()
    match = re.search(r"\bCWE-\d+\b", token)
    return match.group(0) if match else None


def as_float(value: Any, key_name: str) -> float:
    try:
        return float(value)
    except Exception as exc:
        raise CliValidationError(f"'{key_name}' must be numeric") from exc


def as_int(value: Any, key_name: str) -> int:
    try:
        return int(value)
    except Exception as exc:
        raise CliValidationError(f"'{key_name}' must be an integer") from exc


def validate_and_finalize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    semgrep = get_required(config, "semgrep", "root")
    cvss_cfg = get_required(config, "cvss", "root")
    epss_cfg = get_required(config, "epss", "root")
    env_cfg = get_required(config, "environment", "root")
    priority = get_required(config, "priority", "root")

    if not isinstance(semgrep, dict):
        raise CliValidationError("Config 'semgrep' must be a mapping")
    if not isinstance(cvss_cfg, dict):
        raise CliValidationError("Config 'cvss' must be a mapping")
    if not isinstance(epss_cfg, dict):
        raise CliValidationError("Config 'epss' must be a mapping")
    if not isinstance(env_cfg, dict):
        raise CliValidationError("Config 'environment' must be a mapping")
    if not isinstance(priority, dict):
        raise CliValidationError("Config 'priority' must be a mapping")

    semgrep.setdefault("base_url", "https://semgrep.dev")
    semgrep.setdefault("dedup", True)
    semgrep.setdefault("page_size", 500)
    retry = semgrep.setdefault("retry", {})
    if not isinstance(retry, dict):
        raise CliValidationError("Config 'semgrep.retry' must be a mapping")
    retry.setdefault("max_attempts", 5)
    retry.setdefault("backoff_ms", 400)
    retry.setdefault("max_backoff_ms", 8000)
    retry.setdefault("retry_statuses", [429, 500, 502, 503, 504])

    deployments_path = get_required(semgrep, "deployments_path", "semgrep")
    findings_path = get_required(semgrep, "findings_path", "semgrep")
    semgrep.setdefault("auth_env_var", "SEMGREP_APP_TOKEN")
    if not isinstance(deployments_path, str) or not deployments_path:
        raise CliValidationError("'semgrep.deployments_path' must be a non-empty string")
    if not isinstance(findings_path, str) or not findings_path:
        raise CliValidationError("'semgrep.findings_path' must be a non-empty string")
    if not isinstance(semgrep["auth_env_var"], str) or not semgrep["auth_env_var"].strip():
        raise CliValidationError("'semgrep.auth_env_var' must be a non-empty string")

    for key in ("max_attempts", "backoff_ms", "max_backoff_ms"):
        if int(retry[key]) <= 0:
            raise CliValidationError(f"'semgrep.retry.{key}' must be > 0")
        retry[key] = int(retry[key])
    if not isinstance(retry.get("retry_statuses"), list) or not retry["retry_statuses"]:
        raise CliValidationError("'semgrep.retry.retry_statuses' must be a non-empty list")
    retry["retry_statuses"] = [int(code) for code in retry["retry_statuses"]]

    semgrep["page_size"] = int(semgrep["page_size"])
    if semgrep["page_size"] <= 0 or semgrep["page_size"] > 3000:
        raise CliValidationError("'semgrep.page_size' must be in range 1..3000")

    cvss_cfg.setdefault("version", "3.1")
    if cvss_cfg["version"] != "3.1":
        raise CliValidationError("Only CVSS version 3.1 is supported")
    candidates = get_required(cvss_cfg, "official_cvss_candidate_paths", "cvss")
    if not isinstance(candidates, list) or not candidates:
        raise CliValidationError("'cvss.official_cvss_candidate_paths' must be a non-empty list")
    if not all(isinstance(item, str) and item for item in candidates):
        raise CliValidationError("'cvss.official_cvss_candidate_paths' entries must be strings")

    severity_map = get_required(cvss_cfg, "severity_to_base_vector", "cvss")
    if not isinstance(severity_map, dict) or not severity_map:
        raise CliValidationError("'cvss.severity_to_base_vector' must be a non-empty mapping")
    normalized_severity_map: Dict[str, str] = {}
    for severity, vector in list(severity_map.items()):
        normalized_vector = normalize_cvss_vector(str(vector), cvss_cfg["version"])
        validate_cvss_vector(normalized_vector)
        normalized_severity_map[str(severity).upper()] = normalized_vector
    cvss_cfg["severity_to_base_vector"] = normalized_severity_map
    severity_map = normalized_severity_map
    if "MEDIUM" not in severity_map:
        raise CliValidationError("'cvss.severity_to_base_vector' must include MEDIUM")

    inference_overrides = cvss_cfg.setdefault("inference_overrides", {})
    if not isinstance(inference_overrides, dict):
        raise CliValidationError("'cvss.inference_overrides' must be a mapping")
    for key in ("reachability", "transitivity", "confidence_adjustment"):
        inference_overrides.setdefault(key, {})
        if not isinstance(inference_overrides[key], dict):
            raise CliValidationError(f"'cvss.inference_overrides.{key}' must be a mapping")
    confidence_adj = inference_overrides["confidence_adjustment"]
    for k, v in list(confidence_adj.items()):
        confidence_adj[str(k).upper()] = float(v)

    external_lookup = cvss_cfg.setdefault("external_lookup", {})
    if not isinstance(external_lookup, dict):
        raise CliValidationError("'cvss.external_lookup' must be a mapping")
    external_lookup.setdefault("enabled", False)
    external_lookup["enabled"] = parse_bool(external_lookup["enabled"])
    external_lookup.setdefault("provider_order", ["nvd"])
    if not isinstance(external_lookup["provider_order"], list) or not external_lookup["provider_order"]:
        raise CliValidationError("'cvss.external_lookup.provider_order' must be a non-empty list")
    providers = [str(item).strip().lower() for item in external_lookup["provider_order"] if str(item).strip()]
    if not providers:
        raise CliValidationError("'cvss.external_lookup.provider_order' must contain at least one provider")
    unsupported = [name for name in providers if name != "nvd"]
    if unsupported:
        raise CliValidationError(
            f"Unsupported CVSS external providers: {', '.join(sorted(set(unsupported)))}"
        )
    external_lookup["provider_order"] = providers
    external_lookup.setdefault("cache_file", ".cvss_cache.json")
    if not isinstance(external_lookup["cache_file"], str) or not external_lookup["cache_file"].strip():
        raise CliValidationError("'cvss.external_lookup.cache_file' must be a non-empty string")

    nvd_cfg = external_lookup.setdefault("nvd", {})
    if not isinstance(nvd_cfg, dict):
        raise CliValidationError("'cvss.external_lookup.nvd' must be a mapping")
    nvd_cfg.setdefault("api_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_cfg.setdefault("api_key_env", "NVD_API_KEY")
    nvd_cfg.setdefault("timeout_seconds", 8)
    nvd_cfg.setdefault("max_attempts", 4)
    nvd_cfg.setdefault("backoff_ms", 500)
    nvd_cfg.setdefault("max_backoff_ms", 6000)
    nvd_cfg.setdefault("retry_statuses", [429, 500, 502, 503, 504])
    if not isinstance(nvd_cfg["api_url"], str) or not nvd_cfg["api_url"].strip():
        raise CliValidationError("'cvss.external_lookup.nvd.api_url' must be a non-empty string")
    if not isinstance(nvd_cfg["api_key_env"], str) or not nvd_cfg["api_key_env"].strip():
        raise CliValidationError("'cvss.external_lookup.nvd.api_key_env' must be a non-empty string")
    for key in ("timeout_seconds", "max_attempts", "backoff_ms", "max_backoff_ms"):
        nvd_cfg[key] = int(nvd_cfg[key])
        if nvd_cfg[key] <= 0:
            raise CliValidationError(f"'cvss.external_lookup.nvd.{key}' must be > 0")
    if not isinstance(nvd_cfg["retry_statuses"], list) or not nvd_cfg["retry_statuses"]:
        raise CliValidationError("'cvss.external_lookup.nvd.retry_statuses' must be a non-empty list")
    nvd_cfg["retry_statuses"] = [int(code) for code in nvd_cfg["retry_statuses"]]

    sast_cfg = cvss_cfg.setdefault("sast_inference", {})
    if not isinstance(sast_cfg, dict):
        raise CliValidationError("'cvss.sast_inference' must be a mapping")
    sast_cfg.setdefault("enabled", False)
    sast_cfg["enabled"] = parse_bool(sast_cfg["enabled"])
    sast_cfg.setdefault("precedence", list(DEFAULT_SAST_PRECEDENCE))
    if not isinstance(sast_cfg["precedence"], list) or not sast_cfg["precedence"]:
        raise CliValidationError("'cvss.sast_inference.precedence' must be a non-empty list")
    precedence = [str(item).strip() for item in sast_cfg["precedence"] if str(item).strip()]
    allowed_precedence = set(DEFAULT_SAST_PRECEDENCE)
    for item in precedence:
        if item not in allowed_precedence:
            raise CliValidationError(
                f"Unsupported cvss.sast_inference.precedence entry '{item}'"
            )
    sast_cfg["precedence"] = precedence

    default_templates = {k: normalize_cvss_vector(v, cvss_cfg["version"]) for k, v in DEFAULT_SAST_FAMILY_TEMPLATES.items()}
    family_templates = sast_cfg.setdefault("family_templates", {})
    if not isinstance(family_templates, dict):
        raise CliValidationError("'cvss.sast_inference.family_templates' must be a mapping")
    merged_templates: Dict[str, Dict[str, str]] = {}
    all_families = set(default_templates.keys()) | set(str(k).strip() for k in family_templates.keys())
    for family in all_families:
        if not family:
            continue
        cfg_entry = family_templates.get(family)
        if cfg_entry is None:
            vector = default_templates.get(family)
            if vector is None:
                continue
            merged_templates[family] = {"vector": vector}
            continue
        if isinstance(cfg_entry, dict):
            vector_raw = cfg_entry.get("vector")
        else:
            vector_raw = cfg_entry
        if not vector_raw:
            raise CliValidationError(
                f"'cvss.sast_inference.family_templates.{family}.vector' is required"
            )
        vector = normalize_cvss_vector(str(vector_raw), cvss_cfg["version"])
        validate_cvss_vector(vector)
        merged_templates[family] = {"vector": vector}
    if "improper_validation" not in merged_templates:
        raise CliValidationError(
            "'cvss.sast_inference.family_templates' must include 'improper_validation'"
        )
    sast_cfg["family_templates"] = merged_templates

    severity_default_family = sast_cfg.setdefault("severity_default_family", {})
    if not isinstance(severity_default_family, dict):
        raise CliValidationError("'cvss.sast_inference.severity_default_family' must be a mapping")
    default_severity_family = {
        "CRITICAL": "code_injection",
        "HIGH": "improper_authorization",
        "MEDIUM": "improper_validation",
        "LOW": "insecure_hashing",
        "INFO": "insecure_hashing",
    }
    normalized_severity_family: Dict[str, str] = {}
    for severity, family in {**default_severity_family, **severity_default_family}.items():
        severity_key = str(severity).upper().strip()
        family_key = str(family).strip()
        if family_key not in merged_templates:
            raise CliValidationError(
                f"Unknown family '{family_key}' in cvss.sast_inference.severity_default_family.{severity_key}"
            )
        normalized_severity_family[severity_key] = family_key
    if "MEDIUM" not in normalized_severity_family:
        raise CliValidationError(
            "'cvss.sast_inference.severity_default_family' must include MEDIUM"
        )
    sast_cfg["severity_default_family"] = normalized_severity_family

    source_conf = sast_cfg.setdefault("source_confidence_multiplier", {})
    if not isinstance(source_conf, dict):
        raise CliValidationError("'cvss.sast_inference.source_confidence_multiplier' must be a mapping")
    default_source_conf = {
        "vulnerability_classes": 1.00,
        "cwe": 0.96,
        "owasp": 0.90,
        "keyword": 0.82,
        "severity_default": 0.75,
    }
    normalized_source_conf: Dict[str, float] = {}
    for source_name, default_value in default_source_conf.items():
        normalized_source_conf[source_name] = as_float(
            source_conf.get(source_name, default_value),
            f"cvss.sast_inference.source_confidence_multiplier.{source_name}",
        )
        if normalized_source_conf[source_name] <= 0:
            raise CliValidationError(
                f"'cvss.sast_inference.source_confidence_multiplier.{source_name}' must be > 0"
            )
    sast_cfg["source_confidence_multiplier"] = normalized_source_conf

    conf_multiplier = sast_cfg.setdefault("confidence_multiplier", {})
    if not isinstance(conf_multiplier, dict):
        raise CliValidationError("'cvss.sast_inference.confidence_multiplier' must be a mapping")
    default_conf_multiplier = {"HIGH": 1.0, "MEDIUM": 0.92, "LOW": 0.85}
    normalized_conf_multiplier: Dict[str, float] = {}
    for level, default_value in default_conf_multiplier.items():
        normalized_conf_multiplier[level] = as_float(
            conf_multiplier.get(level, default_value),
            f"cvss.sast_inference.confidence_multiplier.{level}",
        )
        if normalized_conf_multiplier[level] <= 0:
            raise CliValidationError(
                f"'cvss.sast_inference.confidence_multiplier.{level}' must be > 0"
            )
    sast_cfg["confidence_multiplier"] = normalized_conf_multiplier

    autotriage_multiplier = sast_cfg.setdefault("autotriage_multiplier", {})
    if not isinstance(autotriage_multiplier, dict):
        raise CliValidationError("'cvss.sast_inference.autotriage_multiplier' must be a mapping")
    default_autotriage = {"true_positive": 1.05, "false_positive": 0.65, "none": 1.00}
    normalized_autotriage: Dict[str, float] = {}
    for verdict, default_value in default_autotriage.items():
        normalized_autotriage[verdict] = as_float(
            autotriage_multiplier.get(verdict, default_value),
            f"cvss.sast_inference.autotriage_multiplier.{verdict}",
        )
        if normalized_autotriage[verdict] <= 0:
            raise CliValidationError(
                f"'cvss.sast_inference.autotriage_multiplier.{verdict}' must be > 0"
            )
    sast_cfg["autotriage_multiplier"] = normalized_autotriage

    path_exposure = sast_cfg.setdefault("path_exposure_multiplier", [])
    if not isinstance(path_exposure, list) or not path_exposure:
        raise CliValidationError("'cvss.sast_inference.path_exposure_multiplier' must be a non-empty list")
    normalized_path_exposure: List[Dict[str, Any]] = []
    for idx, entry in enumerate(path_exposure):
        if not isinstance(entry, dict):
            raise CliValidationError(
                f"'cvss.sast_inference.path_exposure_multiplier[{idx}]' must be a mapping"
            )
        pattern = str(get_required(entry, "pattern", "cvss.sast_inference.path_exposure_multiplier[]"))
        multiplier = as_float(
            get_required(entry, "multiplier", "cvss.sast_inference.path_exposure_multiplier[]"),
            f"cvss.sast_inference.path_exposure_multiplier[{idx}].multiplier",
        )
        if multiplier <= 0:
            raise CliValidationError(
                f"'cvss.sast_inference.path_exposure_multiplier[{idx}].multiplier' must be > 0"
            )
        try:
            re.compile(pattern)
        except re.error as exc:
            raise CliValidationError(
                f"Invalid regex in cvss.sast_inference.path_exposure_multiplier[{idx}]: {exc}"
            ) from exc
        normalized_path_exposure.append({"pattern": pattern, "multiplier": multiplier})
    sast_cfg["path_exposure_multiplier"] = normalized_path_exposure

    vuln_class_map = sast_cfg.setdefault("vulnerability_class_to_family", {})
    if not isinstance(vuln_class_map, dict):
        raise CliValidationError("'cvss.sast_inference.vulnerability_class_to_family' must be a mapping")
    normalized_vuln_class_map: Dict[str, str] = {}
    for raw_key, family in vuln_class_map.items():
        key = normalize_lookup_key(raw_key)
        family_key = str(family).strip()
        if not key:
            continue
        if family_key not in merged_templates:
            raise CliValidationError(
                f"Unknown family '{family_key}' in cvss.sast_inference.vulnerability_class_to_family"
            )
        normalized_vuln_class_map[key] = family_key
    sast_cfg["vulnerability_class_to_family"] = normalized_vuln_class_map

    cwe_map = sast_cfg.setdefault("cwe_to_family", {})
    if not isinstance(cwe_map, dict):
        raise CliValidationError("'cvss.sast_inference.cwe_to_family' must be a mapping")
    normalized_cwe_map: Dict[str, str] = {}
    for raw_key, family in cwe_map.items():
        key = extract_cwe_id(raw_key)
        family_key = str(family).strip()
        if not key:
            continue
        if family_key not in merged_templates:
            raise CliValidationError(
                f"Unknown family '{family_key}' in cvss.sast_inference.cwe_to_family"
            )
        normalized_cwe_map[key] = family_key
    sast_cfg["cwe_to_family"] = normalized_cwe_map

    owasp_map = sast_cfg.setdefault("owasp_to_family", {})
    if not isinstance(owasp_map, dict):
        raise CliValidationError("'cvss.sast_inference.owasp_to_family' must be a mapping")
    normalized_owasp_map: Dict[str, str] = {}
    for raw_key, family in owasp_map.items():
        key = normalize_lookup_key(raw_key)
        family_key = str(family).strip()
        if not key:
            continue
        if family_key not in merged_templates:
            raise CliValidationError(
                f"Unknown family '{family_key}' in cvss.sast_inference.owasp_to_family"
            )
        normalized_owasp_map[key] = family_key
    sast_cfg["owasp_to_family"] = normalized_owasp_map

    keyword_map = sast_cfg.setdefault("keyword_to_family", [])
    if not isinstance(keyword_map, list):
        raise CliValidationError("'cvss.sast_inference.keyword_to_family' must be a list")
    normalized_keyword_map: List[Dict[str, str]] = []
    for idx, entry in enumerate(keyword_map):
        if not isinstance(entry, dict):
            raise CliValidationError(
                f"'cvss.sast_inference.keyword_to_family[{idx}]' must be a mapping"
            )
        pattern = str(get_required(entry, "pattern", "cvss.sast_inference.keyword_to_family[]"))
        family_key = str(get_required(entry, "family", "cvss.sast_inference.keyword_to_family[]")).strip()
        if family_key not in merged_templates:
            raise CliValidationError(
                f"Unknown family '{family_key}' in cvss.sast_inference.keyword_to_family[{idx}]"
            )
        try:
            re.compile(pattern)
        except re.error as exc:
            raise CliValidationError(
                f"Invalid regex in cvss.sast_inference.keyword_to_family[{idx}]: {exc}"
            ) from exc
        normalized_keyword_map.append({"pattern": pattern, "family": family_key})
    sast_cfg["keyword_to_family"] = normalized_keyword_map

    epss_cfg.setdefault("fallback_to_first", True)
    epss_cfg.setdefault("first_api_url", "https://api.first.org/data/v1/epss")
    epss_cfg.setdefault("timeout_seconds", 5)
    epss_cfg["timeout_seconds"] = int(epss_cfg["timeout_seconds"])
    if epss_cfg["timeout_seconds"] <= 0:
        raise CliValidationError("'epss.timeout_seconds' must be > 0")

    default_profile = get_required(env_cfg, "default_profile", "environment")
    profiles = get_required(env_cfg, "profiles", "environment")
    if not isinstance(default_profile, str) or not default_profile:
        raise CliValidationError("'environment.default_profile' must be a non-empty string")
    if not isinstance(profiles, dict) or not profiles:
        raise CliValidationError("'environment.profiles' must be a non-empty mapping")
    if default_profile not in profiles:
        raise CliValidationError("Default environment profile not found in profiles map")

    for profile_name, profile in profiles.items():
        if not isinstance(profile, dict):
            raise CliValidationError(f"Profile '{profile_name}' must be a mapping")
        cvss_env = profile.setdefault("cvss_env", {})
        modified = profile.setdefault("modified_metrics", {})
        if not isinstance(cvss_env, dict) or not isinstance(modified, dict):
            raise CliValidationError(
                f"Profile '{profile_name}' requires mapping keys 'cvss_env' and 'modified_metrics'"
            )

    env_cfg.setdefault("repository_profile_map", [])
    if not isinstance(env_cfg["repository_profile_map"], list):
        raise CliValidationError("'environment.repository_profile_map' must be a list")
    for item in env_cfg["repository_profile_map"]:
        if not isinstance(item, dict):
            raise CliValidationError("Each repository_profile_map entry must be a mapping")
        pattern = get_required(item, "pattern", "environment.repository_profile_map[]")
        profile_name = get_required(item, "profile", "environment.repository_profile_map[]")
        if profile_name not in profiles:
            raise CliValidationError(f"repository_profile_map profile '{profile_name}' is undefined")
        try:
            re.compile(str(pattern))
        except re.error as exc:
            raise CliValidationError(f"Invalid repository regex '{pattern}': {exc}") from exc

    weights = get_required(priority, "weights", "priority")
    if not isinstance(weights, dict):
        raise CliValidationError("'priority.weights' must be a mapping")
    for k in ("cvss_base", "cvss_environmental", "epss"):
        if k not in weights:
            raise CliValidationError(f"'priority.weights.{k}' is required")
        weights[k] = float(weights[k])
        if weights[k] < 0:
            raise CliValidationError(f"'priority.weights.{k}' must be >= 0")
    total_weight = weights["cvss_base"] + weights["cvss_environmental"] + weights["epss"]
    if not math.isclose(total_weight, 1.0, rel_tol=1e-6, abs_tol=1e-6):
        raise CliValidationError("priority weights must sum exactly to 1.0")

    priority.setdefault("clamp_min", 0)
    priority.setdefault("clamp_max", 100)
    priority.setdefault("round_digits", 2)
    priority["clamp_min"] = float(priority["clamp_min"])
    priority["clamp_max"] = float(priority["clamp_max"])
    priority["round_digits"] = int(priority["round_digits"])
    if priority["clamp_min"] > priority["clamp_max"]:
        raise CliValidationError("'priority.clamp_min' cannot exceed 'priority.clamp_max'")
    if priority["round_digits"] < 0:
        raise CliValidationError("'priority.round_digits' must be >= 0")

    sast_post = priority.setdefault("sast_post_multipliers", {})
    if not isinstance(sast_post, dict):
        raise CliValidationError("'priority.sast_post_multipliers' must be a mapping")
    status_multiplier = sast_post.setdefault("status", {})
    if not isinstance(status_multiplier, dict):
        raise CliValidationError("'priority.sast_post_multipliers.status' must be a mapping")
    normalized_status_multiplier: Dict[str, float] = {}
    for status_key, default_value in DEFAULT_SAST_STATUS_MULTIPLIERS.items():
        normalized_status_multiplier[status_key] = as_float(
            status_multiplier.get(status_key, default_value),
            f"priority.sast_post_multipliers.status.{status_key}",
        )
        if normalized_status_multiplier[status_key] <= 0:
            raise CliValidationError(
                f"'priority.sast_post_multipliers.status.{status_key}' must be > 0"
            )
    for extra_key, value in status_multiplier.items():
        key = normalize_status(extra_key)
        if key in normalized_status_multiplier:
            continue
        numeric = as_float(value, f"priority.sast_post_multipliers.status.{extra_key}")
        if numeric <= 0:
            raise CliValidationError(
                f"'priority.sast_post_multipliers.status.{extra_key}' must be > 0"
            )
        normalized_status_multiplier[key] = numeric
    sast_post["status"] = normalized_status_multiplier

    return config


def parse_issue_types(raw_value: str) -> List[str]:
    values = [value.strip().lower() for value in raw_value.split(",") if value.strip()]
    if not values:
        raise CliValidationError("At least one issue type must be provided")
    invalid = [value for value in values if value not in VALID_ISSUE_TYPES]
    if invalid:
        raise CliValidationError(
            f"Unsupported issue type(s): {', '.join(invalid)}. Allowed: sast,sca"
        )
    return list(dict.fromkeys(values))


def normalize_cvss_vector(vector: str, version: str) -> str:
    vector = (vector or "").strip()
    if not vector:
        raise CliValidationError("Empty CVSS vector")
    if vector.startswith(f"CVSS:{version}/"):
        return vector
    if vector.startswith("CVSS:3.1/"):
        return vector
    if vector.startswith("AV:"):
        return f"CVSS:{version}/{vector}"
    if vector.startswith("CVSS:"):
        return vector
    raise CliValidationError(f"Unrecognized CVSS vector format: {vector}")


def validate_cvss_vector(vector: str) -> None:
    try:
        _CVSS3(vector)
    except Exception as exc:
        raise CliValidationError(f"Invalid CVSS vector '{vector}': {exc}") from exc


def parse_cvss_metrics(vector: str) -> Dict[str, str]:
    metrics: Dict[str, str] = {}
    for token in vector.split("/")[1:]:
        if ":" not in token:
            continue
        metric, value = token.split(":", 1)
        metrics[metric] = value
    return metrics


def build_cvss_vector(version: str, metrics: Dict[str, str], include_env: bool) -> str:
    missing = [metric for metric in BASE_METRIC_ORDER if metric not in metrics]
    if missing:
        raise CliValidationError(f"Missing mandatory CVSS base metrics: {missing}")
    parts = [f"{metric}:{metrics[metric]}" for metric in BASE_METRIC_ORDER]
    if include_env:
        for metric in ENV_METRIC_ORDER:
            if metric in metrics:
                parts.append(f"{metric}:{metrics[metric]}")
    return f"CVSS:{version}/" + "/".join(parts)


def cvss_scores(vector: str) -> Tuple[float, float, float]:
    parsed = _CVSS3(vector)
    scores = parsed.scores()
    if not isinstance(scores, tuple) or len(scores) < 3:
        raise ApiRuntimeError(f"Unexpected CVSS score tuple for vector: {vector}")
    base = float(scores[0]) if scores[0] is not None else 0.0
    temporal = float(scores[1]) if scores[1] is not None else 0.0
    environmental = float(scores[2]) if scores[2] is not None else 0.0
    return base, temporal, environmental


def json_get_path(payload: Any, path: str) -> Any:
    current = payload
    for chunk in path.split("."):
        if isinstance(current, dict):
            current = current.get(chunk)
            continue
        if isinstance(current, list):
            if chunk.isdigit():
                idx = int(chunk)
                if 0 <= idx < len(current):
                    current = current[idx]
                    continue
            return None
        return None
    return current


def parse_epoch(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not token:
        return None
    if re.fullmatch(r"\d+(\.\d+)?", token):
        return int(float(token))
    if token.endswith("Z"):
        token = token[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(token)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def normalize_status(value: Any) -> str:
    token = str(value or "unknown").strip()
    return token.lower() if token else "unknown"


def normalize_severity(value: Any) -> str:
    raw = str(value or "").strip().upper()
    if raw == "INFORMATIONAL":
        raw = "INFO"
    return raw if raw else "MEDIUM"


def coerce_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def bool_from_value(value: Any) -> bool:
    return parse_bool(value)


def extract_cve(finding: Dict[str, Any]) -> Optional[str]:
    pattern = re.compile(r"\bCVE-\d{4}-\d{4,}\b", flags=re.IGNORECASE)
    candidates: List[Any] = [
        finding.get("vulnerability_identifier"),
        finding.get("cve"),
        finding.get("cve_id"),
        json_get_path(finding, "vulnerability.id"),
    ]
    for candidate in candidates:
        if isinstance(candidate, str):
            match = pattern.search(candidate)
            if match:
                return match.group(0).upper()
        elif isinstance(candidate, list):
            for entry in candidate:
                if isinstance(entry, str):
                    match = pattern.search(entry)
                    if match:
                        return match.group(0).upper()
    return None


def extract_finding_timestamp(finding: Dict[str, Any]) -> Optional[int]:
    for key in TIMESTAMP_KEYS:
        value = finding.get(key)
        parsed = parse_epoch(value)
        if parsed is not None:
            return parsed
    return None


class HttpClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        timeout_seconds: int,
        retry_cfg: Dict[str, Any],
        logger: logging.Logger,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.retry_cfg = retry_cfg
        self.logger = logger
        self.session = _requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": "semgrep-cvss-cli/1.0",
            }
        )

    def _build_url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        return f"{self.base_url}/{path_or_url.lstrip('/')}"

    def _sleep_backoff(self, attempt: int) -> None:
        base_ms = int(self.retry_cfg["backoff_ms"])
        max_ms = int(self.retry_cfg["max_backoff_ms"])
        raw_ms = min(max_ms, base_ms * (2 ** (attempt - 1)))
        jittered_ms = max(1, int(raw_ms * random.uniform(0.7, 1.3)))
        time.sleep(jittered_ms / 1000.0)

    def get_json(
        self,
        path_or_url: str,
        params: Optional[Dict[str, Any]] = None,
        timeout_override: Optional[int] = None,
    ) -> Dict[str, Any]:
        url = self._build_url(path_or_url)
        max_attempts = int(self.retry_cfg["max_attempts"])
        retry_statuses = set(int(item) for item in self.retry_cfg["retry_statuses"])
        timeout = timeout_override if timeout_override is not None else self.timeout_seconds
        last_exc: Optional[Exception] = None

        for attempt in range(1, max_attempts + 1):
            try:
                response = self.session.get(url, params=params, timeout=timeout)
            except Exception as exc:
                last_exc = exc
                if attempt < max_attempts:
                    self.logger.debug(
                        "Request error (%s), retrying attempt %s/%s: %s",
                        type(exc).__name__,
                        attempt + 1,
                        max_attempts,
                        url,
                    )
                    self._sleep_backoff(attempt)
                    continue
                raise ApiRuntimeError(f"Request failed after {max_attempts} attempts: {url}") from exc

            if response.status_code in retry_statuses and attempt < max_attempts:
                self.logger.debug(
                    "Retryable HTTP %s on attempt %s/%s for %s",
                    response.status_code,
                    attempt,
                    max_attempts,
                    url,
                )
                self._sleep_backoff(attempt)
                continue

            if response.status_code in (401, 403):
                raise CliValidationError(
                    f"Authentication/authorization failed ({response.status_code}) for {url}"
                )
            if response.status_code >= 400:
                body = response.text.strip()
                snippet = body[:240] if body else "<empty response body>"
                raise ApiRuntimeError(f"HTTP {response.status_code} for {url}: {snippet}")

            try:
                parsed = response.json()
            except Exception as exc:
                raise ApiRuntimeError(f"Invalid JSON response from {url}: {exc}") from exc
            if not isinstance(parsed, dict):
                raise ApiRuntimeError(f"Expected JSON object from {url}, got {type(parsed).__name__}")
            return parsed

        if last_exc is not None:
            raise ApiRuntimeError(f"Request failed after retries: {url}") from last_exc
        raise ApiRuntimeError(f"Request failed after retries: {url}")


def resolve_deployment_slug(
    client: HttpClient, args_slug: Optional[str], config: Dict[str, Any], logger: logging.Logger
) -> str:
    if args_slug:
        return args_slug
    payload = client.get_json(config["semgrep"]["deployments_path"])
    deployments = payload.get("deployments")
    if not isinstance(deployments, list) or not deployments:
        raise ApiRuntimeError("No deployments found from Semgrep deployments endpoint")

    candidates: List[Dict[str, Any]] = []
    for deployment in deployments:
        if not isinstance(deployment, dict):
            continue
        slug = str(deployment.get("slug") or "").strip()
        if not slug:
            continue
        active = deployment.get("active", True)
        deployment["_active"] = bool_from_value(active)
        candidates.append(deployment)
    if not candidates:
        raise ApiRuntimeError("Deployments endpoint returned no usable deployment slugs")

    active = [item for item in candidates if item.get("_active")]
    source = active if active else candidates
    source.sort(key=lambda item: str(item.get("slug")).lower())
    selected_slug = str(source[0]["slug"])
    logger.info("Auto-selected deployment slug '%s' from /deployments", selected_slug)
    return selected_slug


def read_checkpoint(path: Path, logger: logging.Logger) -> Optional[int]:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        logger.warning("Checkpoint unreadable (%s), ignoring: %s", path, exc)
        return None
    if not isinstance(payload, dict):
        logger.warning("Checkpoint file is not an object, ignoring: %s", path)
        return None
    since = payload.get("since")
    if isinstance(since, (int, float)):
        return int(since)
    logger.warning("Checkpoint has no numeric 'since', ignoring: %s", path)
    return None


def write_checkpoint(path: Path, since_value: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "since": int(since_value),
        "updated_at": int(time.time()),
    }
    fd, temp_path = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))
            handle.write("\n")
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def fetch_findings(
    client: HttpClient,
    config: Dict[str, Any],
    deployment_slug: str,
    issue_types: Sequence[str],
    since: Optional[int],
    page_size: int,
    max_pages: Optional[int],
    logger: logging.Logger,
) -> List[Dict[str, Any]]:
    findings_template = str(config["semgrep"]["findings_path"])
    findings_path = resolve_findings_path(findings_template, deployment_slug)
    dedup = bool(config["semgrep"].get("dedup", True))
    merged: List[Dict[str, Any]] = []
    seen_keys: set[Tuple[str, str]] = set()

    for issue_type in issue_types:
        page = 0
        pages_processed = 0
        while True:
            if max_pages is not None and pages_processed >= max_pages:
                logger.warning(
                    "max-pages=%s reached for issue_type=%s, stopping pagination",
                    max_pages,
                    issue_type,
                )
                break

            params: Dict[str, Any] = {
                "issue_type": issue_type,
                "dedup": str(dedup).lower(),
                "page": page,
                "page_size": page_size,
            }
            if since is not None:
                params["since"] = int(since)

            payload = client.get_json(findings_path, params=params)
            batch = payload.get("findings", [])
            if not isinstance(batch, list):
                raise ApiRuntimeError("Findings response missing list field 'findings'")
            logger.debug(
                "Fetched %s findings for issue_type=%s page=%s",
                len(batch),
                issue_type,
                page,
            )
            if not batch:
                break

            for finding in batch:
                if not isinstance(finding, dict):
                    continue
                finding.setdefault("issue_type", issue_type)
                finding_id = str(finding.get("id") or finding.get("finding_id") or "").strip()
                key = (issue_type, finding_id)
                if finding_id and key in seen_keys:
                    continue
                if finding_id:
                    seen_keys.add(key)
                merged.append(finding)

            pages_processed += 1
            if len(batch) < page_size:
                break
            page += 1

    return merged


def resolve_findings_path(findings_path: str, deployment_slug: str) -> str:
    if "{deployment_slug}" in findings_path:
        if not deployment_slug:
            raise CliValidationError(
                "Deployment slug is required because semgrep.findings_path uses '{deployment_slug}'"
            )
        return findings_path.format(deployment_slug=deployment_slug)
    return findings_path


def extract_cvss_vector_from_nvd_payload(payload: Dict[str, Any], version: str) -> Optional[str]:
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return None
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        cve = vulnerability.get("cve")
        if not isinstance(cve, dict):
            continue
        metrics = cve.get("metrics")
        if not isinstance(metrics, dict):
            continue
        for metric_family in ("cvssMetricV31", "cvssMetricV30"):
            rows = metrics.get(metric_family)
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                vector = json_get_path(row, "cvssData.vectorString") or row.get("vectorString")
                if not vector:
                    continue
                try:
                    normalized = normalize_cvss_vector(str(vector), version)
                    validate_cvss_vector(normalized)
                    return normalized
                except Exception:
                    continue
    return None


class CvssExternalResolver:
    def __init__(self, cvss_cfg: Dict[str, Any], logger: logging.Logger, config_dir: Path) -> None:
        self.logger = logger
        external_cfg = cvss_cfg.get("external_lookup", {})
        self.enabled = bool(external_cfg.get("enabled", False))
        self.provider_order = list(external_cfg.get("provider_order", []))
        self.version = str(cvss_cfg.get("version", "3.1"))
        self.nvd_cfg = dict(external_cfg.get("nvd", {}))
        cache_file = str(external_cfg.get("cache_file", ".cvss_cache.json"))
        cache_path = Path(cache_file)
        if not cache_path.is_absolute():
            cache_path = (config_dir / cache_path).resolve()
        self.cache_path = cache_path
        self.cache_entries: Dict[str, Dict[str, Any]] = {}
        self.cache_dirty = False
        self._load_cache()

    def _load_cache(self) -> None:
        if not self.enabled or not self.cache_path.exists():
            return
        try:
            with self.cache_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception as exc:
            self.logger.warning("CVSS cache unreadable (%s), ignoring: %s", self.cache_path, exc)
            return
        if not isinstance(payload, dict):
            return
        entries = payload.get("entries")
        if isinstance(entries, dict):
            self.cache_entries = entries

    def persist_cache(self) -> None:
        if not self.enabled or not self.cache_dirty:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated_at": int(time.time()),
            "entries": self.cache_entries,
        }
        fd, temp_path = tempfile.mkstemp(
            prefix=f".{self.cache_path.name}.",
            suffix=".tmp",
            dir=str(self.cache_path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, separators=(",", ":"))
                handle.write("\n")
            os.replace(temp_path, self.cache_path)
            self.cache_dirty = False
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def resolve(self, cve: Optional[str]) -> Tuple[Optional[str], str]:
        if not self.enabled or not cve:
            return None, "none"
        normalized_cve = str(cve).upper().strip()
        if not normalized_cve:
            return None, "none"

        cached = self.cache_entries.get(normalized_cve)
        if isinstance(cached, dict):
            vector = cached.get("vector")
            source = str(cached.get("source") or "none")
            if isinstance(vector, str) and vector:
                return vector, source
            return None, "none"

        vector: Optional[str] = None
        source = "none"
        for provider in self.provider_order:
            if provider == "nvd":
                vector = self._lookup_nvd_vector(normalized_cve)
                source = "nvd" if vector else "none"
                break

        self.cache_entries[normalized_cve] = {
            "vector": vector,
            "source": source,
            "updated_at": int(time.time()),
        }
        self.cache_dirty = True
        return vector, source

    def _lookup_nvd_vector(self, cve: str) -> Optional[str]:
        url = str(self.nvd_cfg["api_url"])
        params = {"cveId": cve}
        headers = {
            "Accept": "application/json",
            "User-Agent": "semgrep-cvss-cli/1.0",
        }
        api_key_env = str(self.nvd_cfg.get("api_key_env") or "").strip()
        api_key = os.getenv(api_key_env, "").strip() if api_key_env else ""
        if api_key:
            headers["apiKey"] = api_key

        max_attempts = int(self.nvd_cfg["max_attempts"])
        retry_statuses = set(int(code) for code in self.nvd_cfg["retry_statuses"])
        timeout_seconds = int(self.nvd_cfg["timeout_seconds"])
        backoff_ms = int(self.nvd_cfg["backoff_ms"])
        max_backoff_ms = int(self.nvd_cfg["max_backoff_ms"])

        for attempt in range(1, max_attempts + 1):
            try:
                response = _requests.get(url, params=params, headers=headers, timeout=timeout_seconds)
            except Exception as exc:
                if attempt < max_attempts:
                    self._sleep_backoff(attempt, backoff_ms, max_backoff_ms)
                    continue
                self.logger.debug("NVD lookup failed for %s: %s", cve, exc)
                return None

            if response.status_code in retry_statuses and attempt < max_attempts:
                self._sleep_backoff(attempt, backoff_ms, max_backoff_ms)
                continue
            if response.status_code in (401, 403):
                self.logger.warning(
                    "NVD lookup unauthorized for %s (status=%s); check NVD API key if configured",
                    cve,
                    response.status_code,
                )
                return None
            if response.status_code >= 400:
                self.logger.debug("NVD lookup non-success for %s (status=%s)", cve, response.status_code)
                return None

            try:
                payload = response.json()
            except Exception:
                return None
            if not isinstance(payload, dict):
                return None
            return extract_cvss_vector_from_nvd_payload(payload, self.version)
        return None

    @staticmethod
    def _sleep_backoff(attempt: int, backoff_ms: int, max_backoff_ms: int) -> None:
        raw_ms = min(max_backoff_ms, backoff_ms * (2 ** (attempt - 1)))
        jittered_ms = max(1, int(raw_ms * random.uniform(0.7, 1.3)))
        time.sleep(jittered_ms / 1000.0)


def extract_official_cvss_vector(
    finding: Dict[str, Any], candidate_paths: Sequence[str], version: str
) -> Optional[str]:
    for path in candidate_paths:
        candidate = json_get_path(finding, path)
        if not candidate:
            continue
        try:
            vector = normalize_cvss_vector(str(candidate), version)
            validate_cvss_vector(vector)
            return vector
        except Exception:
            continue
    return None


def infer_base_vector(
    finding: Dict[str, Any], cvss_cfg: Dict[str, Any]
) -> Tuple[str, List[str], Optional[float]]:
    version = cvss_cfg["version"]
    severity_map = cvss_cfg["severity_to_base_vector"]
    overrides = cvss_cfg.get("inference_overrides", {})

    raw_severity = str(finding.get("severity") or "").strip()
    severity = normalize_severity(raw_severity)
    applied: List[str] = []
    if not raw_severity:
        severity = "MEDIUM"
        applied.append("severity_missing->MEDIUM")
    elif severity not in severity_map:
        severity = "MEDIUM"
        applied.append("severity_unknown->MEDIUM")

    vector = normalize_cvss_vector(str(severity_map[severity]), version)
    metrics = parse_cvss_metrics(vector)

    reachability = str(finding.get("reachability") or "").strip()
    transitivity = str(finding.get("transitivity") or "").strip()

    reachability_map = overrides.get("reachability", {})
    if reachability in reachability_map and isinstance(reachability_map[reachability], dict):
        for metric, value in reachability_map[reachability].items():
            metrics[str(metric)] = str(value)
            applied.append(f"reachability:{reachability}:{metric}->{value}")

    transitivity_map = overrides.get("transitivity", {})
    if transitivity in transitivity_map and isinstance(transitivity_map[transitivity], dict):
        for metric, value in transitivity_map[transitivity].items():
            metrics[str(metric)] = str(value)
            applied.append(f"transitivity:{transitivity}:{metric}->{value}")

    malicious = any(bool_from_value(finding.get(key)) for key in MALICIOUS_KEYS)
    if malicious:
        for metric, value in {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}.items():
            metrics[metric] = value
        applied.append("malicious:network_easy_noauth")

    confidence = str(finding.get("confidence") or finding.get("confidence_level") or "").upper()
    confidence_map = overrides.get("confidence_adjustment", {})
    confidence_multiplier: Optional[float] = None
    if confidence and confidence in confidence_map:
        confidence_multiplier = float(confidence_map[confidence])
        if not math.isclose(confidence_multiplier, 1.0, rel_tol=1e-9, abs_tol=1e-9):
            applied.append(f"confidence:{confidence}:x{confidence_multiplier:.2f}")

    final_vector = build_cvss_vector(version, metrics, include_env=False)
    validate_cvss_vector(final_vector)
    return final_vector, applied, confidence_multiplier


def infer_sast_base_vector(
    finding: Dict[str, Any], cvss_cfg: Dict[str, Any]
) -> Tuple[str, List[str], str]:
    version = cvss_cfg["version"]
    sast_cfg = cvss_cfg.get("sast_inference", {})
    family_templates = sast_cfg["family_templates"]
    precedence = sast_cfg["precedence"]

    rule = finding.get("rule")
    rule_obj = rule if isinstance(rule, dict) else {}
    selected_family: Optional[str] = None
    selected_source = "severity_default"
    selected_evidence = "none"

    vulnerability_class_to_family = sast_cfg.get("vulnerability_class_to_family", {})
    cwe_to_family = sast_cfg.get("cwe_to_family", {})
    owasp_to_family = sast_cfg.get("owasp_to_family", {})
    keyword_to_family = sast_cfg.get("keyword_to_family", [])
    severity_default_family = sast_cfg.get("severity_default_family", {})

    for source in precedence:
        if source == "vulnerability_classes":
            raw_classes = rule_obj.get("vulnerability_classes")
            if isinstance(raw_classes, list):
                for item in raw_classes:
                    normalized = normalize_lookup_key(item)
                    family = vulnerability_class_to_family.get(normalized)
                    if family:
                        selected_family = family
                        selected_source = source
                        selected_evidence = normalized
                        break
            if selected_family:
                break
        elif source == "cwe":
            raw_cwes = rule_obj.get("cwe_names")
            if isinstance(raw_cwes, list):
                for item in raw_cwes:
                    cwe = extract_cwe_id(item)
                    family = cwe_to_family.get(cwe or "")
                    if family and cwe:
                        selected_family = family
                        selected_source = source
                        selected_evidence = cwe
                        break
            if selected_family:
                break
        elif source == "owasp":
            raw_owasp = rule_obj.get("owasp_names")
            if isinstance(raw_owasp, list):
                for item in raw_owasp:
                    normalized = normalize_lookup_key(item)
                    family = owasp_to_family.get(normalized)
                    if family:
                        selected_family = family
                        selected_source = source
                        selected_evidence = normalized
                        break
            if selected_family:
                break
        elif source == "keyword":
            search_blob = " ".join(
                [
                    str(finding.get("rule_name") or ""),
                    str(rule_obj.get("name") or ""),
                    str(rule_obj.get("message") or ""),
                    " ".join(str(item) for item in (rule_obj.get("vulnerability_classes") or []) if item),
                    " ".join(str(item) for item in (rule_obj.get("cwe_names") or []) if item),
                    " ".join(str(item) for item in (rule_obj.get("owasp_names") or []) if item),
                ]
            )
            for mapping in keyword_to_family:
                pattern = str(mapping.get("pattern") or "")
                family = str(mapping.get("family") or "")
                if not pattern or not family:
                    continue
                if re.search(pattern, search_blob):
                    selected_family = family
                    selected_source = source
                    selected_evidence = f"pattern:{pattern}"
                    break
            if selected_family:
                break
        elif source == "severity_default":
            severity = normalize_severity(finding.get("severity"))
            selected_family = severity_default_family.get(
                severity, severity_default_family.get("MEDIUM", "improper_validation")
            )
            selected_source = source
            selected_evidence = f"severity:{severity}"
            break

    if not selected_family:
        selected_family = severity_default_family.get("MEDIUM", "improper_validation")
        selected_source = "severity_default"
        selected_evidence = "severity:MEDIUM"

    template_entry = family_templates.get(selected_family)
    if not isinstance(template_entry, dict) or not template_entry.get("vector"):
        raise CliValidationError(f"Missing vector for SAST family '{selected_family}'")
    vector = normalize_cvss_vector(str(template_entry["vector"]), version)
    validate_cvss_vector(vector)
    applied = [
        f"sast_family:{selected_family}",
        f"sast_source:{selected_source}",
        f"sast_evidence:{selected_evidence}",
    ]
    return vector, applied, selected_source


def find_sast_path_multiplier(file_path: str, mappings: Sequence[Dict[str, Any]]) -> Tuple[float, str]:
    for item in mappings:
        pattern = str(item.get("pattern") or "")
        multiplier = float(item.get("multiplier") or 1.0)
        if pattern and re.search(pattern, file_path):
            return multiplier, pattern
    return 1.0, "none"


def resolve_sast_priority_multiplier(
    finding: Dict[str, Any],
    config: Dict[str, Any],
    inference_source: str,
    scoring_method: str,
) -> Tuple[float, List[str]]:
    cvss_cfg = config["cvss"]
    priority_cfg = config["priority"]
    sast_cfg = cvss_cfg.get("sast_inference", {})
    if not bool(sast_cfg.get("enabled", False)):
        return 1.0, []

    notes: List[str] = []
    multiplier = 1.0

    source_multiplier = 1.0
    source_key = inference_source if scoring_method == "inferred_semgrep" else "official"
    if scoring_method == "inferred_semgrep":
        source_multiplier = float(
            sast_cfg.get("source_confidence_multiplier", {}).get(inference_source, 1.0)
        )
        notes.append(f"sast_source_conf:{source_key}:x{source_multiplier:.2f}")
    multiplier *= source_multiplier

    finding_conf = str(
        finding.get("confidence") or json_get_path(finding, "rule.confidence") or ""
    ).upper()
    confidence_multiplier = float(
        sast_cfg.get("confidence_multiplier", {}).get(finding_conf, 1.0)
    )
    multiplier *= confidence_multiplier
    notes.append(f"sast_conf:{finding_conf or 'NONE'}:x{confidence_multiplier:.2f}")

    verdict = str(json_get_path(finding, "assistant.autotriage.verdict") or "none").lower()
    autotriage_multiplier = float(
        sast_cfg.get("autotriage_multiplier", {}).get(verdict, sast_cfg.get("autotriage_multiplier", {}).get("none", 1.0))
    )
    multiplier *= autotriage_multiplier
    notes.append(f"sast_autotriage:{verdict}:x{autotriage_multiplier:.2f}")

    location = finding.get("location")
    location_obj = location if isinstance(location, dict) else {}
    file_path = str(
        location_obj.get("file_path") or finding.get("path") or json_get_path(finding, "location.path") or ""
    )
    path_multiplier, path_pattern = find_sast_path_multiplier(
        file_path,
        sast_cfg.get("path_exposure_multiplier", []),
    )
    multiplier *= path_multiplier
    notes.append(f"sast_path:{path_pattern}:x{path_multiplier:.2f}")

    status = normalize_status(finding.get("status"))
    status_map = priority_cfg.get("sast_post_multipliers", {}).get("status", {})
    status_multiplier = float(status_map.get(status, 1.0))
    multiplier *= status_multiplier
    notes.append(f"sast_status:{status}:x{status_multiplier:.2f}")

    return multiplier, notes


def select_environment_profile(
    repository: str, env_cfg: Dict[str, Any]
) -> Tuple[str, Dict[str, Any], Optional[str]]:
    profiles = env_cfg["profiles"]
    default_name = env_cfg["default_profile"]
    selected_name = default_name
    matched_pattern: Optional[str] = None
    for mapping in env_cfg.get("repository_profile_map", []):
        pattern = str(mapping.get("pattern", ""))
        profile = str(mapping.get("profile", ""))
        if not pattern or profile not in profiles:
            continue
        if repository and re.search(pattern, repository):
            selected_name = profile
            matched_pattern = pattern
            break
    return selected_name, profiles[selected_name], matched_pattern


def build_environmental_vector(
    base_vector: str, version: str, profile: Dict[str, Any]
) -> str:
    metrics = parse_cvss_metrics(base_vector)
    for metric, value in profile.get("cvss_env", {}).items():
        metrics[str(metric)] = str(value)
    for metric, value in profile.get("modified_metrics", {}).items():
        metrics[str(metric)] = str(value)
    env_vector = build_cvss_vector(version, metrics, include_env=True)
    validate_cvss_vector(env_vector)
    return env_vector


def resolve_epss(
    finding: Dict[str, Any],
    cve: Optional[str],
    epss_cfg: Dict[str, Any],
    client: HttpClient,
    logger: logging.Logger,
) -> Tuple[Optional[float], Optional[float], str]:
    semgrep_score = coerce_float(finding.get("epss_score"))
    semgrep_percentile = coerce_float(finding.get("epss_percentile"))
    if semgrep_score is not None:
        return clamp(semgrep_score, 0.0, 1.0), clamp_optional(semgrep_percentile, 0.0, 1.0), "semgrep"

    if not bool(epss_cfg.get("fallback_to_first", True)) or not cve:
        return None, None, "none"

    params = {"cve": cve}
    first_api_url = str(epss_cfg["first_api_url"])
    timeout_seconds = int(epss_cfg.get("timeout_seconds", 5))
    try:
        payload = client.get_json(first_api_url, params=params, timeout_override=timeout_seconds)
    except Exception as exc:
        logger.warning("FIRST EPSS lookup failed for %s: %s", cve, exc)
        return None, None, "none"
    rows = payload.get("data")
    if not isinstance(rows, list) or not rows:
        return None, None, "none"
    first_row = rows[0] if isinstance(rows[0], dict) else {}
    score = coerce_float(first_row.get("epss"))
    percentile = coerce_float(first_row.get("percentile"))
    if score is None:
        return None, None, "none"
    return clamp(score, 0.0, 1.0), clamp_optional(percentile, 0.0, 1.0), "first"


def clamp(value: float, min_value: float, max_value: float) -> float:
    return max(min_value, min(max_value, value))


def clamp_optional(value: Optional[float], min_value: float, max_value: float) -> Optional[float]:
    if value is None:
        return None
    return clamp(value, min_value, max_value)


def derive_confidence(
    scoring_method: str, epss_source: str, profile_name: str, overrides: Sequence[str]
) -> str:
    if scoring_method == "official_cvss" and epss_source != "none" and profile_name:
        return "high"
    if scoring_method == "inferred_semgrep":
        signals = 0
        if epss_source != "none":
            signals += 1
        if profile_name:
            signals += 1
        if overrides:
            signals += 1
        if signals >= 2:
            return "medium"
    return "low"


def build_rationale(
    scoring_method: str,
    cvss_source: str,
    overrides: Sequence[str],
    epss_source: str,
    profile_name: str,
    contributors: Sequence[Tuple[str, float]],
) -> str:
    top = ",".join(f"{name}:{value:.2f}" for name, value in contributors[:2])
    override_text = ",".join(overrides) if overrides else "none"
    method_text = "official" if scoring_method == "official_cvss" else "inferred"
    return (
        f"method={method_text}; cvss_source={cvss_source}; overrides={override_text}; epss={epss_source}; "
        f"profile={profile_name}; top={top}"
    )


def normalize_issue_type(value: Any) -> str:
    token = str(value or "").strip().lower()
    return token if token in VALID_ISSUE_TYPES else "sast"


def process_finding(
    finding: Dict[str, Any],
    config: Dict[str, Any],
    client: HttpClient,
    cvss_external_resolver: CvssExternalResolver,
    logger: logging.Logger,
) -> Dict[str, Any]:
    cvss_cfg = config["cvss"]
    priority_cfg = config["priority"]
    env_cfg = config["environment"]

    finding_id = str(finding.get("id") or finding.get("finding_id") or "").strip()
    if not finding_id:
        finding_id = f"generated-{abs(hash(json.dumps(finding, sort_keys=True, default=str)))}"

    issue_type = normalize_issue_type(finding.get("issue_type"))
    severity = normalize_severity(finding.get("severity"))
    status = normalize_status(finding.get("status"))
    repository = str(finding.get("repository") or finding.get("repo") or "").strip()
    cve = extract_cve(finding)

    official_vector = extract_official_cvss_vector(
        finding,
        cvss_cfg["official_cvss_candidate_paths"],
        cvss_cfg["version"],
    )
    cvss_source = "semgrep" if official_vector else "inferred"
    if not official_vector and cve:
        external_vector, external_source = cvss_external_resolver.resolve(cve)
        if external_vector:
            official_vector = external_vector
            cvss_source = external_source
    applied_overrides: List[str] = []
    confidence_multiplier: Optional[float] = None
    inference_source = "severity_default"

    if official_vector:
        scoring_method = "official_cvss"
        cvss_vector_base = official_vector
    else:
        scoring_method = "inferred_semgrep"
        if issue_type == "sast" and bool(cvss_cfg.get("sast_inference", {}).get("enabled", False)):
            cvss_vector_base, sast_notes, inference_source = infer_sast_base_vector(finding, cvss_cfg)
            applied_overrides.extend(sast_notes)
        else:
            cvss_vector_base, applied_overrides, confidence_multiplier = infer_base_vector(finding, cvss_cfg)
            inference_source = "legacy"

    base_score, _, _ = cvss_scores(cvss_vector_base)
    if scoring_method == "inferred_semgrep" and confidence_multiplier is not None:
        base_score = clamp(base_score * confidence_multiplier, 0.0, 10.0)

    profile_name, profile, _matched = select_environment_profile(repository, env_cfg)
    cvss_vector_environmental = build_environmental_vector(
        cvss_vector_base, cvss_cfg["version"], profile
    )
    _, _, env_score = cvss_scores(cvss_vector_environmental)
    if env_score == 0.0:
        env_score = base_score

    epss_score, epss_percentile, epss_source = resolve_epss(
        finding,
        cve,
        config["epss"],
        client,
        logger,
    )
    epss_effective = epss_score if epss_score is not None else 0.0

    weights = priority_cfg["weights"]
    base_component = 100.0 * weights["cvss_base"] * (base_score / 10.0)
    env_component = 100.0 * weights["cvss_environmental"] * (env_score / 10.0)
    epss_component = 100.0 * weights["epss"] * epss_effective
    raw_priority = base_component + env_component + epss_component
    if issue_type == "sast" and bool(cvss_cfg.get("sast_inference", {}).get("enabled", False)):
        sast_multiplier, sast_multiplier_notes = resolve_sast_priority_multiplier(
            finding=finding,
            config=config,
            inference_source=inference_source,
            scoring_method=scoring_method,
        )
        raw_priority *= sast_multiplier
        applied_overrides.extend(sast_multiplier_notes)
    final_priority = round(
        clamp(raw_priority, priority_cfg["clamp_min"], priority_cfg["clamp_max"]),
        priority_cfg["round_digits"],
    )

    contributors = sorted(
        (
            ("cvss_base", base_component),
            ("cvss_environmental", env_component),
            ("epss", epss_component),
        ),
        key=lambda item: item[1],
        reverse=True,
    )
    confidence = derive_confidence(scoring_method, epss_source, profile_name, applied_overrides)
    rationale = build_rationale(
        scoring_method,
        cvss_source,
        applied_overrides,
        epss_source,
        profile_name,
        contributors,
    )

    pool: List[Any] = []

    def _intern(val: Any) -> int:
        pool.append(val)
        return len(pool) - 1

    type_idx = _intern("primary")
    vec_idx = _intern(cvss_vector_base)
    score_idx = _intern(round(clamp(base_score, 0.0, 10.0), 2))
    src_idx = _intern({"type": type_idx, "vector": vec_idx, "score": score_idx})
    sources_idx = _intern([src_idx])

    vuln_obj = {
        "finding_id": finding_id,
        "issue_type": issue_type,
        "severity": severity,
        "status": status,
        "cvssSources": sources_idx,
        "epss_score": None if epss_score is None else round(epss_score, 5),
        "epss_percentile": None if epss_percentile is None else round(epss_percentile, 5),
        "final_priority_score": final_priority,
        "scoring_method": scoring_method,
        "rationale": rationale,
        "confidence": confidence,
    }
    return pool, vuln_obj


def effective_since(
    since_override: Optional[int], checkpoint_value: Optional[int]
) -> Optional[int]:
    if since_override is not None:
        return int(since_override)
    if checkpoint_value is not None:
        return int(checkpoint_value)
    return None


def compute_next_checkpoint(
    since_value: Optional[int], findings: Sequence[Dict[str, Any]], run_started_at: int
) -> int:
    timestamps = [extract_finding_timestamp(item) for item in findings]
    valid = [ts for ts in timestamps if ts is not None]
    if valid:
        candidate = max(valid)
        if since_value is not None:
            return max(candidate, int(since_value))
        return candidate
    if since_value is not None:
        return int(since_value)
    return int(run_started_at)


def emit_output(records: Sequence[Dict[str, Any]], out_path: Optional[Path]) -> None:
    payload = json.dumps(records, ensure_ascii=False, separators=(",", ":"))
    if out_path is None:
        sys.stdout.write(payload)
        sys.stdout.write("\n")
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.write("\n")


def run(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = setup_logging(args.log_level)

    try:
        ensure_dependencies()
        issue_types = parse_issue_types(args.issue_types)
        if args.since is not None and args.since < 0:
            raise CliValidationError("--since must be >= 0")
        if args.timeout_seconds <= 0:
            raise CliValidationError("--timeout-seconds must be > 0")
        if args.max_pages is not None and args.max_pages <= 0:
            raise CliValidationError("--max-pages must be > 0")
        if args.page_size is not None and (args.page_size <= 0 or args.page_size > 3000):
            raise CliValidationError("--page-size must be in range 1..3000")

        config_path = Path(args.config)
        config = validate_and_finalize_config(load_config(config_path))
        auth_env_var = str(config["semgrep"].get("auth_env_var", "SEMGREP_APP_TOKEN")).strip()
        token = os.getenv(auth_env_var, "").strip()
        if not token:
            raise CliValidationError(
                f"{auth_env_var} environment variable is required"
            )

        base_url = os.getenv("SEMGREP_BASE_URL", str(config["semgrep"]["base_url"])).strip()
        if not base_url:
            raise CliValidationError("SEMGREP_BASE_URL cannot be empty")

        page_size = int(args.page_size or config["semgrep"]["page_size"])
        if page_size > 3000:
            raise CliValidationError("Page size exceeds hard max of 3000")

        checkpoint_path = Path(args.checkpoint_file)
        checkpoint_value = read_checkpoint(checkpoint_path, logger)
        since_value = effective_since(args.since, checkpoint_value)

        client = HttpClient(
            base_url=base_url,
            token=token,
            timeout_seconds=args.timeout_seconds,
            retry_cfg=config["semgrep"]["retry"],
            logger=logger,
        )
        cvss_external_resolver = CvssExternalResolver(
            cvss_cfg=config["cvss"],
            logger=logger,
            config_dir=config_path.parent.resolve(),
        )

        findings_template = str(config["semgrep"]["findings_path"])
        if "{deployment_slug}" in findings_template:
            deployment_slug = resolve_deployment_slug(client, args.deployment_slug, config, logger)
        else:
            deployment_slug = ""
            if args.deployment_slug:
                logger.info(
                    "Ignoring --deployment-slug because semgrep.findings_path is fixed in config"
                )
        run_started_at = int(time.time())
        raw_findings = fetch_findings(
            client=client,
            config=config,
            deployment_slug=deployment_slug,
            issue_types=issue_types,
            since=since_value,
            page_size=page_size,
            max_pages=args.max_pages,
            logger=logger,
        )
        logger.info("Fetched %s normalized candidate findings", len(raw_findings))

        records: List[Any] = []
        for finding in raw_findings:
            pool, vuln_obj = process_finding(finding, config, client, cvss_external_resolver, logger)
            ordered_vuln = {field: vuln_obj.get(field) for field in OUTPUT_FIELDS}
            records.append([pool, ordered_vuln])

        emit_output(records, Path(args.out) if args.out else None)
        cvss_external_resolver.persist_cache()
        next_checkpoint = compute_next_checkpoint(since_value, raw_findings, run_started_at)
        write_checkpoint(checkpoint_path, next_checkpoint)
        logger.info("Checkpoint updated at %s with since=%s", checkpoint_path, next_checkpoint)
        return 0

    except CliValidationError as exc:
        logger.error("%s", exc)
        return 2
    except ApiRuntimeError as exc:
        logger.error("%s", exc)
        return 1
    except Exception as exc:
        logger.exception("Unhandled runtime failure: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(run())

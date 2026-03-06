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
    "cvss_vector_base",
    "cvss_score_base",
    "cvss_vector_environmental",
    "cvss_score_environmental",
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
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        token = value.strip().lower()
        return token in {"1", "true", "yes", "y"}
    return False


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
    overrides: Sequence[str],
    epss_source: str,
    profile_name: str,
    contributors: Sequence[Tuple[str, float]],
) -> str:
    top = ",".join(f"{name}:{value:.2f}" for name, value in contributors[:2])
    override_text = ",".join(overrides) if overrides else "none"
    method_text = "official" if scoring_method == "official_cvss" else "inferred"
    return (
        f"method={method_text}; overrides={override_text}; epss={epss_source}; "
        f"profile={profile_name}; top={top}"
    )


def normalize_issue_type(value: Any) -> str:
    token = str(value or "").strip().lower()
    return token if token in VALID_ISSUE_TYPES else "sast"


def process_finding(
    finding: Dict[str, Any],
    config: Dict[str, Any],
    client: HttpClient,
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
    applied_overrides: List[str] = []
    confidence_multiplier: Optional[float] = None

    if official_vector:
        scoring_method = "official_cvss"
        cvss_vector_base = official_vector
    else:
        scoring_method = "inferred_semgrep"
        cvss_vector_base, applied_overrides, confidence_multiplier = infer_base_vector(finding, cvss_cfg)

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
        applied_overrides,
        epss_source,
        profile_name,
        contributors,
    )

    return {
        "finding_id": finding_id,
        "issue_type": issue_type,
        "severity": severity,
        "status": status,
        "cvss_vector_base": cvss_vector_base,
        "cvss_score_base": round(clamp(base_score, 0.0, 10.0), 2),
        "cvss_vector_environmental": cvss_vector_environmental,
        "cvss_score_environmental": round(clamp(env_score, 0.0, 10.0), 2),
        "epss_score": None if epss_score is None else round(epss_score, 5),
        "epss_percentile": None if epss_percentile is None else round(epss_percentile, 5),
        "final_priority_score": final_priority,
        "scoring_method": scoring_method,
        "rationale": rationale,
        "confidence": confidence,
    }


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

        config = validate_and_finalize_config(load_config(Path(args.config)))
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

        records: List[Dict[str, Any]] = []
        for finding in raw_findings:
            scored = process_finding(finding, config, client, logger)
            ordered_record = {field: scored.get(field) for field in OUTPUT_FIELDS}
            records.append(ordered_record)

        emit_output(records, Path(args.out) if args.out else None)
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

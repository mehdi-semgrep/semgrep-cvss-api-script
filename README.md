# semgrep-cvss-api-script

A CLI tool that fetches Semgrep findings and enriches them with CVSS 3.1 and EPSS scores to produce a prioritized output.

## Overview

The script pulls findings from the Semgrep API, scores each finding using CVSS 3.1 base and environmental vectors, fetches EPSS probability scores from the FIRST.org API, and computes a weighted final priority score for each finding.

CVSS vectors are sourced in priority order:
1. **Official vector** embedded in the Semgrep finding
2. **NVD lookup** — fetches the official CVSS vector from the NVD API using the finding's CVE ID
3. **SAST family inference** — maps the finding to a vulnerability family (e.g. `sql_injection`, `xss`) via vulnerability classes, CWE, OWASP, or keyword matching, then applies a family-specific CVSS template
4. **Severity fallback** — infers a vector from the finding's severity level

## Requirements

- Python 3.8+
- `requests`
- `PyYAML`
- `cvss`

Install dependencies:

```bash
pip install requests PyYAML cvss
```

## Configuration

All behavior is controlled by a YAML config file. See `scoring-config.yaml` for a full example.

Key sections:

- **`semgrep`** — API base URL, deployment findings path, pagination, and retry settings
- **`cvss`** — CVSS version, severity-to-vector fallback map, NVD external lookup, and SAST family inference config
- **`epss`** — FIRST.org EPSS API settings and fallback behavior
- **`environment`** — Named environmental profiles (e.g. `prod_internet`, `internal_low`) with CVSS environmental metrics, and regex-based repository-to-profile mapping
- **`priority`** — Weights for `cvss_base`, `cvss_environmental`, and `epss` components (must sum to 1.0), plus SAST post-multipliers

## Authentication

Set your Semgrep API token via the environment variable specified in the config (default: `SEMGREP_APP_TOKEN`):

```bash
export SEMGREP_APP_TOKEN=<your_token>
```

Optionally set an NVD API key for higher rate limits (unauthenticated requests are also supported):

```bash
export NVD_API_KEY=<your_nvd_api_key>
```

## Usage

```bash
python semgrep_cvss_cli.py --config scoring-config.yaml [options]
```

### Options

| Flag | Description |
|------|-------------|
| `--config` | Path to scoring config YAML (required) |
| `--deployment-slug` | Override deployment slug (auto-detected if not set and path uses `{deployment_slug}`) |
| `--issue-types` | Comma-separated types: `sast`, `sca` (default: `sast,sca`) |
| `--since` | Epoch seconds lower bound for findings (overrides checkpoint) |
| `--checkpoint-file` | Path to checkpoint file for incremental runs (default: `.semgrep_checkpoint.json`) |
| `--out` | Output file path (default: stdout) |
| `--page-size` | Results per page, max 3000 (default: from config) |
| `--max-pages` | Safety cap on pages fetched per issue type |
| `--timeout-seconds` | HTTP timeout in seconds (default: 20) |
| `--log-level` | `INFO`, `DEBUG`, `WARN`, or `ERROR` (default: `INFO`) |

## Output

JSON array written to stdout (or `--out` file). Each record contains:

| Field | Description |
|-------|-------------|
| `finding_id` | Semgrep finding ID |
| `issue_type` | `sast` or `sca` |
| `severity` | Finding severity |
| `status` | Finding status |
| `cvss_vector_base` | CVSS 3.1 base vector |
| `cvss_score_base` | CVSS 3.1 base score (0–10) |
| `cvss_vector_environmental` | CVSS 3.1 environmental vector |
| `cvss_score_environmental` | CVSS 3.1 environmental score (0–10) |
| `epss_score` | EPSS probability (0–1), or null |
| `epss_percentile` | EPSS percentile (0–1), or null |
| `final_priority_score` | Weighted priority score (0–100) |
| `scoring_method` | `official_cvss` or `inferred_semgrep` |
| `rationale` | Human-readable scoring breakdown |
| `confidence` | `high`, `medium`, or `low` |

## NVD External CVSS Lookup

When a finding has a CVE ID but no embedded CVSS vector, the script queries the [NVD API](https://nvd.nist.gov/developers/vulnerabilities) to fetch the official CVSS 3.1 vector. Results are cached locally to avoid redundant API calls on subsequent runs.

Configure via `cvss.external_lookup` in the YAML:

```yaml
cvss:
  external_lookup:
    enabled: true
    provider_order: ["nvd"]
    cache_file: ".cvss_cache.json"
    nvd:
      api_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
      api_key_env: "NVD_API_KEY"
      timeout_seconds: 8
      max_attempts: 4
      backoff_ms: 500
      max_backoff_ms: 6000
      retry_statuses: [429, 500, 502, 503, 504]
```

## SAST Vulnerability Family Inference

For SAST findings without an official CVSS vector, the script can infer a more precise base vector by mapping the finding to a known vulnerability family (e.g. `sql_injection`, `xss`, `ssrf`) rather than relying purely on severity.

Enable via `cvss.sast_inference.enabled: true`.

### Family resolution precedence

Families are resolved in configurable order (default):

1. **`vulnerability_classes`** — matches Semgrep rule `vulnerability_classes` field against a configurable map
2. **`cwe`** — matches CWE IDs from the rule against a configurable map
3. **`owasp`** — matches OWASP category names against a configurable map
4. **`keyword`** — regex search across rule name, message, and metadata fields
5. **`severity_default`** — falls back to a severity-to-family mapping

### Supported vulnerability families

`sql_injection`, `command_injection`, `code_injection`, `insecure_deserialization`, `ssrf`, `path_traversal`, `improper_authorization`, `xss`, `csrf`, `open_redirect`, `sensitive_data_exposure`, `dos`, `improper_validation`, `insecure_hashing`

### Priority multipliers (SAST)

After computing the base CVSS score, additional multipliers are applied for SAST findings:

| Multiplier | Description |
|------------|-------------|
| `source_confidence_multiplier` | Discounts inferred scores based on how the family was determined (e.g. `vulnerability_classes: 1.0`, `keyword: 0.82`, `severity_default: 0.75`) |
| `confidence_multiplier` | Adjusts for Semgrep rule confidence level (`HIGH: 1.0`, `MEDIUM: 0.92`, `LOW: 0.85`) |
| `autotriage_multiplier` | Adjusts for Semgrep Assistant autotriage verdict (`true_positive: 1.05`, `false_positive: 0.65`) |
| `path_exposure_multiplier` | Boosts findings in exposed paths (e.g. `routes/`, `controllers/`) and discounts internal ones (e.g. `migrations/`, `tests/`) |
| `status` (post-multiplier) | Discounts findings by status (`open: 1.0`, `provisionally_ignored: 0.6`, `fixed: 0.25`) |

## Incremental Runs

The script writes a checkpoint file after each run. On subsequent runs without `--since`, it automatically fetches only findings newer than the last checkpoint.

## Example

```bash
export SEMGREP_APP_TOKEN=<your_token>
export NVD_API_KEY=<your_nvd_key>  # optional

python semgrep_cvss_cli.py \
  --config scoring-config.yaml \
  --issue-types sast,sca \
  --out results.json \
  --log-level DEBUG
```

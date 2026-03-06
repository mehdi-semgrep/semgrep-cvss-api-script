# semgrep-cvss-api-script

A CLI tool that fetches Semgrep findings and enriches them with CVSS 3.1 and EPSS scores to produce a prioritized output.

## Overview

The script pulls findings from the Semgrep API, scores each finding using CVSS 3.1 base and environmental vectors, fetches EPSS probability scores from the FIRST.org API, and computes a weighted final priority score for each finding.

Scoring uses official CVSS vectors from the finding data when available, and falls back to inferring vectors from the finding's severity, reachability, and transitivity metadata.

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
- **`cvss`** — CVSS version, severity-to-vector fallback map, and inference overrides for reachability/transitivity
- **`epss`** — FIRST.org EPSS API settings and fallback behavior
- **`environment`** — Named environmental profiles (e.g. `prod_internet`, `internal_low`) with CVSS environmental metrics, and regex-based repository-to-profile mapping
- **`priority`** — Weights for `cvss_base`, `cvss_environmental`, and `epss` components (must sum to 1.0)

## Authentication

Set your Semgrep API token via the environment variable specified in the config (default: `SEMGREP_APP_TOKEN`):

```bash
export SEMGREP_APP_TOKEN=<your_token>
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

## Incremental Runs

The script writes a checkpoint file after each run. On subsequent runs without `--since`, it automatically fetches only findings newer than the last checkpoint.

## Example

```bash
export SEMGREP_APP_TOKEN=<your_token>
python semgrep_cvss_cli.py \
  --config scoring-config.yaml \
  --issue-types sast,sca \
  --out results.json \
  --log-level DEBUG
```

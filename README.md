# CodeGuardian — Data Collection

LLM-powered code security review system. This module handles collecting and cleaning training/RAG data from public security sources.

---

## Quick Start

```bash
# 1. Clone and enter project
git clone <repo-url>
cd codeguardian

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate       # macOS/Linux
# .venv\Scripts\activate        # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure secrets
cp .env.example .env
# Edit .env and add your GITHUB_TOKEN

# 5. Collect data
python scripts/data_collection/collect_all.py

# 6. Validate collection
python scripts/data_collection/validate_data.py
```

---

## Project Structure

```
codeguardian/
├── scripts/
│   └── data_collection/
│       ├── collect_all.py           # Master script — run this
│       ├── collect_cves.py          # NVD CVE API
│       ├── collect_github_issues.py # GitHub security issues
│       ├── collect_owasp.py         # OWASP cheat sheets & docs
│       ├── collect_code_examples.py # OWASP Benchmark Java examples
│       ├── validate_data.py         # Post-collection quality check
│       └── diagnose_github.py       # Debug GitHub API access
│
├── data/
│   └── raw/
│       ├── v1/                      # Old timestamped files (gitignored)
│       └── v2/                      # Clean data — committed to git
│           ├── cves/
│           │   ├── cves.json
│           │   └── cve_metadata.json
│           ├── github_issues/
│           │   ├── issues.json
│           │   └── github_issues_metadata.json
│           ├── owasp/
│           │   ├── documentation.json
│           │   └── owasp_documentation_metadata.json
│           └── owasp_benchmark/
│               ├── owasp_benchmark.json
│               └── owasp_benchmark_metadata.json
│
├── logs/                            # Runtime logs (gitignored)
├── .env                             # Secrets — NEVER commit (gitignored)
├── .env.example                     # Template for teammates
├── requirements.txt
└── .gitignore
```

---

## Data Sources

| Source | Script | Output | What's cleaned |
|--------|--------|--------|----------------|
| [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) | `collect_cves.py` | `v2/cves/cves.json` | No cleaning needed (structured API) |
| GitHub Issues | `collect_github_issues.py` | `v2/github_issues/issues.json` | Code snippets extracted; spam flagged |
| [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org) | `collect_owasp.py` | `v2/owasp/documentation.json` | Navigation menus removed via HTML parsing |
| [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) | `collect_code_examples.py` | `v2/owasp_benchmark/owasp_benchmark.json` | License headers & package declarations removed |

All cleaning is applied **during collection** — data saved to disk is already RAG-ready.

---

## Setup: GitHub Token

A GitHub Personal Access Token is required for `collect_github_issues.py`.

1. Go to [GitHub → Settings → Developer settings → Personal access tokens](https://github.com/settings/tokens)
2. Generate a new token (classic) with **`public_repo`** scope
3. Add it to your `.env` file:

```
GITHUB_TOKEN=ghp_your_token_here
```

> **Important:** Never commit `.env`. It is listed in `.gitignore`.  
> If you accidentally expose a token, revoke it immediately at [github.com/settings/tokens](https://github.com/settings/tokens).

---

## What Gets Committed vs. Ignored

| Path | Committed? | Reason |
|------|-----------|--------|
| `scripts/` | Yes | Source code |
| `data/raw/v2/` | Yes | Clean data for team use |
| `data/raw/v1/` timestamped JSONs | No | Large, regeneratable |
| `logs/` | No | May contain API responses |
| `.env` | **No** | Contains secrets |
| `.env.example` | Yes | Template only, no real values |
| `.venv/` | No | Local environment |

---

## Running Individual Collectors

```bash
# CVEs only
python scripts/data_collection/collect_cves.py

# GitHub issues only
python scripts/data_collection/collect_github_issues.py

# OWASP docs only
python scripts/data_collection/collect_owasp.py

# Test OWASP cleaning on a single URL (no files written)
python scripts/data_collection/collect_owasp.py test

# Code examples only
python scripts/data_collection/collect_code_examples.py
```

---

## Validate After Collection

```bash
python scripts/data_collection/validate_data.py
```

Checks count, severity distribution, language breakdown, and warns if fewer than expected records were collected.

---

## Notes

- NVD API has a rate limit of 5 requests/30 seconds — the collector respects this automatically
- GitHub API is rate-limited to 60 requests/hour unauthenticated; with a token it's 5,000/hour
- OWASP collection takes ~30 seconds (1s sleep between pages to be polite)
- Total estimated collection time: **15–20 minutes**

# CodeGuardian Dataset Documentation

## Overview

This dataset powers **CodeGuardian**, an AI-powered security code review system that detects
vulnerabilities, provides explanations, suggests fixes, and cites authoritative security references.

**System Architecture:** Single-tier RAG for vulnerability detection with static citation mapping
for OWASP guidance and CVE references, and LLM-powered fix suggestions.

---

## Dataset Composition

### Training Dataset (450 items)

| Source | Count | Description |
|--------|------:|-------------|
| DVWA | 14 | PHP vulnerable web application files |
| WebGoat | 59 | Java security training lesson files |
| OWASP Benchmark | 20 | Java security test cases |
| Exploit-DB | 347 | Real-world exploit code examples |
| GitHub Issues | 10 | Security issue code snippets |

### Evaluation Set (65 items)

| Source | Count | Type |
|--------|------:|------|
| OWASP Benchmark | 30 | Vulnerable Java test cases |
| WebGoat | 10 | Java security lessons |
| DVWA | 5 | PHP vulnerable code |
| Exploit-DB | 20 | Exploit patterns |

### Reference Library

| Resource | Count | Purpose |
|----------|------:|---------|
| CVE Database | 673 | Vulnerability records for citation curation |
| OWASP Documentation | 26 | Security cheat sheets for guidance extraction |

---

## Vulnerability Coverage

| Vulnerability Type | Count | Coverage |
|--------------------|------:|---------|
| sql_injection             |      103 |      20% |
| xss                       |       86 |      16% |
| auth_bypass               |       66 |      12% |
| command_injection         |       52 |      10% |
| other_injection           |       47 |       9% |
| file_upload               |       40 |       7% |
| path_traversal            |       40 |       7% |
| rce                       |       40 |       7% |
| xxe                       |       22 |       4% |
| csrf                      |       11 |       2% |
| ssrf                      |        7 |       1% |
| deserialization           |        1 |       0% |

---

## Language Distribution

| Language | Count |
|----------|------:|
| other_web    |      200 |
| java         |      119 |
| python       |      112 |
| ruby         |       44 |
| php          |       22 |
| perl         |        9 |
| js           |        5 |
| unknown      |        3 |
| go           |        1 |

---

## File Descriptions

### `data/processed/training_dataset.json`
Unified training dataset with 450 items. Each item has:
- `item_id` — unique identifier (train_001, train_002, ...)
- `source` — original data source
- `language` — programming language
- `vulnerability_types` — list of vulnerability categories (multi-label)
- `severity` — critical / high / medium / low
- `code` — vulnerable code snippet
- `metadata` — source-specific fields (file path, lesson type, etc.)

### `data/processed/evaluation_set.json`
Held-out test cases with 65 items. Each has:
- `test_id` — unique identifier (eval_001, ...)
- `ground_truth` — vulnerability types, severity, explanation
- `expected_citations` — CWE ID and OWASP category for citation evaluation

### `data/processed/citation_map.json`
Static citation reference for 12 vulnerability types. Each entry contains:
- CWE mapping with ID, name, and URL
- OWASP category, guidance URL, key prevention points, and summary
- 2–3 representative CVE examples with severity scores

### `data/processed/few_shot_examples.json`
5 high-quality examples for LLM prompting covering:
SQL injection (PHP), XSS (PHP), Path traversal (Java), Command injection (PHP), Auth bypass (Java).

### `data/statistics/`
- `dataset_statistics.json` — counts by source, language, severity
- `vulnerability_distribution.json` — vuln type counts across train/eval
- `language_coverage.json` — language counts across train/eval

---

## Train/Eval Split Strategy

The dataset uses stratified sampling to maintain vulnerability type distribution:
- **OWASP Benchmark:** 30 eval / 20 train
- **WebGoat:** 10 eval / 59 train
- **Exploit-DB:** 20 eval / 347 train
- **DVWA:** 5 eval / 14 train
- **GitHub Issues:** 0 eval / 10 train (all code-bearing issues)

No item appears in both train and eval sets.

---

## Evaluation Metrics

| Metric | Description |
|--------|-------------|
| Precision | Fraction of flagged vulnerabilities that are true positives |
| Recall | Fraction of actual vulnerabilities correctly detected |
| F1-Score | Harmonic mean of precision and recall |
| False Positive Rate | Fraction of clean code incorrectly flagged |
| Latency | Time per code review (target < 5s) |
| Citation Accuracy | Fraction of correct CWE/OWASP citations |

---

## Usage

```python
import json

# Load training data
with open('data/processed/training_dataset.json') as f:
    train = json.load(f)

# Load evaluation set
with open('data/processed/evaluation_set.json') as f:
    eval_set = json.load(f)

# Load citation map
with open('data/processed/citation_map.json') as f:
    citations = json.load(f)

# Load few-shot examples
with open('data/processed/few_shot_examples.json') as f:
    few_shots = json.load(f)

# Access training items
for item in train['items']:
    code = item['code']
    vuln_types = item['vulnerability_types']
    # ... use for RAG indexing
```

---

## Regenerating the Dataset

```bash
cd codeguardian
python scripts/data_collection/build_processed_datasets.py
```

---

## Citation

If you use this dataset, please cite:

```
CodeGuardian: AI-Powered Security Code Review System
CMPE 258 Deep Learning Project
San Jose State University, 2026
```

## License

Source data licenses:
- **DVWA:** GNU GPLv3
- **WebGoat:** GPL-2.0
- **OWASP Benchmark:** Apache 2.0
- **Exploit-DB:** Public domain / open access
- **NVD CVE Data:** Public domain (U.S. Government)
- **OWASP Documentation:** CC BY-SA 4.0

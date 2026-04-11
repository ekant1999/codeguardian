"""
Build all processed datasets for CodeGuardian.

Generates:
  data/processed/training_dataset.json
  data/processed/evaluation_set.json
  data/processed/citation_map.json
  data/processed/few_shot_examples.json
  data/statistics/dataset_statistics.json
  data/statistics/vulnerability_distribution.json
  data/statistics/language_coverage.json
  docs/DATASET_README.md

Run from the codeguardian directory:
    python scripts/data_collection/build_processed_datasets.py
"""

import json
import re
import random
from collections import Counter, defaultdict
from datetime import date, datetime
from pathlib import Path

random.seed(42)  # reproducible splits

# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────

BASE        = Path(__file__).resolve().parent.parent.parent
RAW         = BASE / "data" / "raw" / "v2"
PROCESSED   = BASE / "data" / "processed"
STATS_DIR   = BASE / "data" / "statistics"
DOCS_DIR    = BASE / "docs"

PROCESSED.mkdir(parents=True, exist_ok=True)
STATS_DIR.mkdir(parents=True, exist_ok=True)
DOCS_DIR.mkdir(parents=True, exist_ok=True)

TODAY = date.today().isoformat()

# ──────────────────────────────────────────────
# Severity mapping
# ──────────────────────────────────────────────

SEVERITY_MAP = {
    "sql_injection":    "critical",
    "command_injection":"critical",
    "rce":              "critical",
    "deserialization":  "critical",
    "xxe":              "high",
    "ssrf":             "high",
    "path_traversal":   "high",
    "file_upload":      "high",
    "xss":              "high",
    "csrf":             "medium",
    "auth_bypass":      "high",
    "other_injection":  "medium",
}

# ──────────────────────────────────────────────
# OWASP Benchmark: infer category from @WebServlet annotation
# ──────────────────────────────────────────────

_BENCH_ROUTE_MAP = {
    "pathtraver": "path_traversal",
    "sqli":       "sql_injection",
    "xss":        "xss",
    "cmdi":       "command_injection",
    "crypto":     "other_injection",
    "trustbound": "auth_bypass",
    "weakrand":   "other_injection",
    "ldapi":      "other_injection",
    "securecookie":"auth_bypass",
    "xpathi":     "other_injection",
}

def bench_category(code: str) -> str:
    m = re.search(r'@WebServlet\(value\s*=\s*"/([\w-]+)/', code)
    if m:
        route = m.group(1).lower().rstrip("-0123456789")
        for key, cat in _BENCH_ROUTE_MAP.items():
            if key in route:
                return cat
    return "other_injection"

# ──────────────────────────────────────────────
# Load raw sources
# ──────────────────────────────────────────────

def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

print("Loading raw datasets...")

dvwa_raw    = load_json(RAW / "dvwa" / "dvwa_vulnerable_code_cleaned.json")
webgoat_raw = load_json(RAW / "webgoat" / "webgoat_vulnerable_code.json")
exploitdb_raw = load_json(RAW / "exploitdb" / "exploitdb_collection.json")
bench_raw   = load_json(RAW / "owasp_benchmark" / "owasp_benchmark.json")
cves_raw    = load_json(RAW / "cves" / "cves.json")
owasp_docs  = load_json(RAW / "owasp" / "documentation.json")
issues_raw  = load_json(RAW / "github_issues" / "issues.json")

dvwa_items    = dvwa_raw.get("snippets", [])
webgoat_items = webgoat_raw.get("snippets", [])
exploitdb_items = exploitdb_raw.get("exploits", [])
bench_items   = bench_raw if isinstance(bench_raw, list) else bench_raw.get("test_cases", [])
issues_with_code = [i for i in issues_raw if i.get("has_code") and not i.get("is_spam")]

print(f"  DVWA:            {len(dvwa_items)}")
print(f"  WebGoat:         {len(webgoat_items)}")
print(f"  Exploit-DB:      {len(exploitdb_items)}")
print(f"  OWASP Benchmark: {len(bench_items)}")
print(f"  GitHub Issues:   {len(issues_with_code)} (with code)")
print(f"  CVEs:            {len(cves_raw)}")
print(f"  OWASP Docs:      {len(owasp_docs)}")

# ──────────────────────────────────────────────
# Normalise each source into common schema
# ──────────────────────────────────────────────

def norm_dvwa(s):
    cat = s.get("category", "other_injection")
    return {
        "source":              "dvwa",
        "original_id":         s["snippet_id"],
        "language":            "php",
        "vulnerability_types": [cat],
        "severity":            SEVERITY_MAP.get(cat, "medium"),
        "code":                s.get("code", ""),
        "metadata": {
            "security_level": s.get("security_level"),
            "file_path":      s.get("file_path"),
            "file_size":      s.get("file_size"),
            "vuln_type":      s.get("vulnerability_type"),
        },
    }

def norm_webgoat(s):
    cat = s.get("category", "other_injection")
    return {
        "source":              "webgoat",
        "original_id":         s["snippet_id"],
        "language":            "java",
        "vulnerability_types": [cat],
        "severity":            SEVERITY_MAP.get(cat, "medium"),
        "code":                s.get("code", ""),
        "metadata": {
            "lesson_type":            s.get("lesson_type"),
            "file_path":              s.get("file_path"),
            "file_size":              s.get("file_size"),
            "quality_score":          s.get("quality_score"),
            "vulnerability_patterns": s.get("vulnerability_patterns", []),
        },
    }

def norm_exploitdb(e):
    cat = e.get("category", "other_injection")
    lang = e.get("language", "other_web")
    return {
        "source":              "exploitdb",
        "original_id":         f"edb_{e['exploit_id']}",
        "language":            lang,
        "vulnerability_types": [cat],
        "severity":            SEVERITY_MAP.get(cat, "medium"),
        "code":                e.get("code", ""),
        "metadata": {
            "title":          e.get("title"),
            "author":         e.get("author"),
            "date_published": e.get("date_published"),
            "platform":       e.get("platform"),
            "verified":       e.get("verified"),
            "cve_codes":      e.get("cve_codes"),
            "url":            e.get("url"),
            "file_path":      e.get("file_path"),
        },
    }

def norm_benchmark(b, idx):
    code = b.get("code", "")
    cat = bench_category(code)
    return {
        "source":              "owasp_benchmark",
        "original_id":         b.get("filename", f"bench_{idx}"),
        "language":            "java",
        "vulnerability_types": [cat],
        "severity":            SEVERITY_MAP.get(cat, "medium"),
        "code":                code,
        "metadata": {
            "filename": b.get("filename"),
            "url":      b.get("url"),
        },
    }

def norm_github(issue):
    # Pull first non-empty code snippet
    snippets = issue.get("code_snippets", [])
    code = ""
    lang = "unknown"
    for sn in snippets:
        if sn.get("code", "").strip():
            code = sn["code"]
            lang = sn.get("language", "unknown")
            break
    # Infer category from title/description keywords
    text = (issue.get("title", "") + " " + issue.get("description", "")).lower()
    cat = "other_injection"
    for kw, c in [
        ("sql injection", "sql_injection"), ("sqli", "sql_injection"),
        ("xss", "xss"), ("cross-site scripting", "xss"),
        ("csrf", "csrf"), ("command injection", "command_injection"),
        ("path traversal", "path_traversal"), ("directory traversal", "path_traversal"),
        ("deserialization", "deserialization"), ("ssrf", "ssrf"),
        ("auth", "auth_bypass"), ("bypass", "auth_bypass"),
        ("file upload", "file_upload"),
    ]:
        if kw in text:
            cat = c
            break
    return {
        "source":              "github_issues",
        "original_id":         f"gh_{issue['repository'].replace('/', '_')}_{issue['issue_number']}",
        "language":            lang,
        "vulnerability_types": [cat],
        "severity":            SEVERITY_MAP.get(cat, "medium"),
        "code":                code,
        "metadata": {
            "repository":   issue.get("repository"),
            "issue_number": issue.get("issue_number"),
            "title":        issue.get("title"),
            "url":          issue.get("url"),
            "labels":       issue.get("labels", []),
        },
    }

# Normalise all items
all_dvwa      = [norm_dvwa(s) for s in dvwa_items]
all_webgoat   = [norm_webgoat(s) for s in webgoat_items]
all_exploitdb = [norm_exploitdb(e) for e in exploitdb_items]
all_benchmark = [norm_benchmark(b, i) for i, b in enumerate(bench_items)]
all_github    = [norm_github(i) for i in issues_with_code]

print(f"\nNormalised counts:")
print(f"  DVWA:            {len(all_dvwa)}")
print(f"  WebGoat:         {len(all_webgoat)}")
print(f"  Exploit-DB:      {len(all_exploitdb)}")
print(f"  OWASP Benchmark: {len(all_benchmark)}")
print(f"  GitHub Issues:   {len(all_github)}")

# ──────────────────────────────────────────────
# Train / Eval split
# ──────────────────────────────────────────────
# Hold-out targets (from spec):
#   OWASP Benchmark: 30 eval, 20 train
#   WebGoat:         10 eval, 59 train
#   Exploit-DB:      20 eval, 348 train
#   DVWA:            5 eval,  14 train  (all 19 are available; hold 5 for eval)
#   GitHub Issues:   0 eval,  10 train  (use top 10 with code)

def stratified_holdout(items, n, key="vulnerability_types"):
    """Hold out n items with stratified sampling by vulnerability type."""
    by_cat = defaultdict(list)
    for item in items:
        cats = item.get(key, ["unknown"])
        by_cat[cats[0] if cats else "unknown"].append(item)

    holdout = []
    remaining = list(items)
    cats_sorted = sorted(by_cat.keys(), key=lambda c: -len(by_cat[c]))

    per_cat = max(1, n // len(cats_sorted))
    for cat in cats_sorted:
        pool = [x for x in by_cat[cat] if x in remaining]
        take = min(per_cat, len(pool), n - len(holdout))
        chosen = random.sample(pool, take)
        holdout.extend(chosen)
        for c in chosen:
            remaining.remove(c)
        if len(holdout) >= n:
            break

    # Top-up if we couldn't fill all categories
    while len(holdout) < n and remaining:
        holdout.append(remaining.pop(0))

    return holdout[:n], [x for x in items if x not in holdout[:n]]

random.shuffle(all_webgoat)
random.shuffle(all_exploitdb)
random.shuffle(all_benchmark)
random.shuffle(all_dvwa)

eval_webgoat, train_webgoat     = stratified_holdout(all_webgoat,   10)
eval_exploitdb, train_exploitdb = stratified_holdout(all_exploitdb, 20)
eval_benchmark, train_benchmark = stratified_holdout(all_benchmark, 30)
eval_dvwa, train_dvwa           = stratified_holdout(all_dvwa,       5)
train_github = all_github[:10]  # top 10 with code, none held for eval

train_items = train_dvwa + train_webgoat + train_benchmark + train_exploitdb + train_github
eval_items  = eval_dvwa  + eval_webgoat  + eval_benchmark  + eval_exploitdb

# Shuffle training set
random.shuffle(train_items)

print(f"\nSplit:")
print(f"  Train: {len(train_items)} | Eval: {len(eval_items)}")
print(f"    DVWA:      train={len(train_dvwa)}, eval={len(eval_dvwa)}")
print(f"    WebGoat:   train={len(train_webgoat)}, eval={len(eval_webgoat)}")
print(f"    Benchmark: train={len(train_benchmark)}, eval={len(eval_benchmark)}")
print(f"    ExploitDB: train={len(train_exploitdb)}, eval={len(eval_exploitdb)}")
print(f"    GitHub:    train={len(train_github)}, eval=0")

# ──────────────────────────────────────────────
# 1. Training Dataset
# ──────────────────────────────────────────────

print("\nBuilding training_dataset.json ...")

train_with_ids = []
for idx, item in enumerate(train_items, 1):
    entry = {"item_id": f"train_{idx:03d}"}
    entry.update(item)
    train_with_ids.append(entry)

train_lang_counts = dict(Counter(
    i["language"] for i in train_with_ids
))
train_vuln_counts = dict(Counter(
    v for i in train_with_ids for v in i["vulnerability_types"]
))
train_source_counts = dict(Counter(i["source"] for i in train_with_ids))

training_dataset = {
    "dataset_version": "1.0",
    "created_at":      TODAY,
    "description":     "Unified vulnerable code dataset for CodeGuardian RAG system",
    "total_items":     len(train_with_ids),
    "sources":         train_source_counts,
    "train_test_split": {
        "training":        len(train_with_ids),
        "evaluation":      len(eval_items),
        "split_strategy":  "stratified by vulnerability type",
    },
    "items":      train_with_ids,
    "statistics": {
        "by_language":      train_lang_counts,
        "by_vulnerability": train_vuln_counts,
        "by_severity":      dict(Counter(i["severity"] for i in train_with_ids)),
    },
}

with open(PROCESSED / "training_dataset.json", "w") as f:
    json.dump(training_dataset, f, indent=2, ensure_ascii=False)
print(f"  Saved: {len(train_with_ids)} training items")

# ──────────────────────────────────────────────
# 2. Evaluation Set
# ──────────────────────────────────────────────

print("Building evaluation_set.json ...")

# CWE static map for ground truth
CWE_MAP = {
    "sql_injection":    ("CWE-89",  "Improper Neutralization of Special Elements in SQL Command"),
    "xss":              ("CWE-79",  "Improper Neutralization of Input During Web Page Generation"),
    "csrf":             ("CWE-352", "Cross-Site Request Forgery"),
    "command_injection":("CWE-78",  "Improper Neutralization of Special Elements in OS Command"),
    "path_traversal":   ("CWE-22",  "Improper Limitation of a Pathname to a Restricted Directory"),
    "file_upload":      ("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
    "xxe":              ("CWE-611", "Improper Restriction of XML External Entity Reference"),
    "deserialization":  ("CWE-502", "Deserialization of Untrusted Data"),
    "ssrf":             ("CWE-918", "Server-Side Request Forgery"),
    "auth_bypass":      ("CWE-287", "Improper Authentication"),
    "other_injection":  ("CWE-74",  "Improper Neutralization of Special Elements in Output"),
    "rce":              ("CWE-94",  "Improper Control of Generation of Code"),
}

eval_cases = []
for idx, item in enumerate(eval_items, 1):
    cat = item["vulnerability_types"][0] if item["vulnerability_types"] else "other_injection"
    cwe_id, cwe_name = CWE_MAP.get(cat, ("CWE-74", "Injection"))
    source_type = "exploit_pattern" if item["source"] == "exploitdb" else "vulnerable_code"

    case = {
        "test_id":     f"eval_{idx:03d}",
        "source":      item["source"],
        "original_id": item["original_id"],
        "type":        source_type,
        "language":    item["language"],
        "code":        item["code"],
        "ground_truth": {
            "vulnerability_types": item["vulnerability_types"],
            "severity":            item["severity"],
            "vulnerable":          True,
            "explanation":         (
                f"{cat.replace('_', ' ').title()} vulnerability: "
                f"untrusted input flows into a sensitive operation without adequate sanitization."
            ),
        },
        "expected_citations": {
            "cwe":            cwe_id,
            "cwe_name":       cwe_name,
            "owasp_category": cat,
        },
    }

    # Attach extra metadata
    meta = item.get("metadata", {})
    if meta:
        case["source_metadata"] = meta

    eval_cases.append(case)

eval_source_counts = dict(Counter(c["source"] for c in eval_cases))
eval_type_counts   = dict(Counter(c["type"] for c in eval_cases))
eval_vuln_counts   = dict(Counter(
    v for c in eval_cases for v in c["ground_truth"]["vulnerability_types"]
))

evaluation_set = {
    "dataset_version": "1.0",
    "created_at":      TODAY,
    "description":     "Held-out test cases for evaluating CodeGuardian detection accuracy",
    "total_items":     len(eval_cases),
    "composition": {
        "vulnerable_code":   eval_type_counts.get("vulnerable_code", 0),
        "exploit_patterns":  eval_type_counts.get("exploit_pattern", 0),
    },
    "test_cases":  eval_cases,
    "statistics": {
        "by_source":          eval_source_counts,
        "by_type":            eval_type_counts,
        "by_vulnerability":   eval_vuln_counts,
        "by_severity":        dict(Counter(
            c["ground_truth"]["severity"] for c in eval_cases
        )),
    },
}

with open(PROCESSED / "evaluation_set.json", "w") as f:
    json.dump(evaluation_set, f, indent=2, ensure_ascii=False)
print(f"  Saved: {len(eval_cases)} evaluation cases")

# ──────────────────────────────────────────────
# 3. Citation Map
# ──────────────────────────────────────────────

print("Building citation_map.json ...")

# Map OWASP doc titles to vulnerability types
OWASP_DOC_MAP = {
    "sql_injection":    ["SQL Injection Prevention Cheat Sheet", "SQL Injection Bypassing WAF"],
    "xss":              ["Cross Site Scripting Prevention Cheat Sheet", "Content Security Policy Cheat Sheet"],
    "csrf":             ["Cross-Site Request Forgery Prevention Cheat Sheet"],
    "command_injection":["OS Command Injection Defense Cheat Sheet", "Command Injection"],
    "path_traversal":   ["Input Validation Cheat Sheet", "File Upload Cheat Sheet"],
    "file_upload":      ["File Upload Cheat Sheet"],
    "xxe":              ["XML External Entity Prevention Cheat Sheet"],
    "deserialization":  ["Deserialization Cheat Sheet", "Insecure Deserialization"],
    "ssrf":             ["REST Security Cheat Sheet"],
    "auth_bypass":      ["Authentication Cheat Sheet", "Session Management Cheat Sheet"],
    "other_injection":  ["Code Injection", "Input Validation Cheat Sheet"],
    "rce":              ["OS Command Injection Defense Cheat Sheet", "Code Injection"],
}

OWASP_URLS = {
    "sql_injection":    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    "xss":              "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "csrf":             "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    "command_injection":"https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
    "path_traversal":   "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
    "file_upload":      "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    "xxe":              "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    "deserialization":  "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
    "ssrf":             "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    "auth_bypass":      "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    "other_injection":  "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
    "rce":              "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
}

OWASP_TOP10 = {
    "sql_injection":    "A03:2021 – Injection",
    "xss":              "A03:2021 – Injection",
    "csrf":             "A01:2021 – Broken Access Control",
    "command_injection":"A03:2021 – Injection",
    "path_traversal":   "A01:2021 – Broken Access Control",
    "file_upload":      "A04:2021 – Insecure Design",
    "xxe":              "A05:2021 – Security Misconfiguration",
    "deserialization":  "A08:2021 – Software and Data Integrity Failures",
    "ssrf":             "A10:2021 – Server-Side Request Forgery",
    "auth_bypass":      "A07:2021 – Identification and Authentication Failures",
    "other_injection":  "A03:2021 – Injection",
    "rce":              "A03:2021 – Injection",
}

KEY_POINTS = {
    "sql_injection": [
        "Use prepared statements with parameterized queries",
        "Use stored procedures with proper parameterization",
        "Validate and escape all user-supplied input",
        "Apply principle of least privilege on database accounts",
        "Disable detailed database error messages in production",
    ],
    "xss": [
        "Escape all untrusted data before inserting into HTML output",
        "Use a Content Security Policy (CSP) header",
        "Validate and sanitize input server-side",
        "Use modern frameworks with built-in XSS protection",
        "Avoid innerHTML; use textContent or safe DOM APIs",
    ],
    "csrf": [
        "Use synchronizer token pattern (anti-CSRF tokens)",
        "Use SameSite cookie attribute (Strict or Lax)",
        "Verify Origin and Referer headers for state-changing requests",
        "Require re-authentication for sensitive operations",
    ],
    "command_injection": [
        "Avoid calling OS commands with user input entirely",
        "Use language-native APIs instead of shell commands",
        "If shell calls are unavoidable, use allowlist input validation",
        "Escape all special shell characters",
        "Run processes with least privilege",
    ],
    "path_traversal": [
        "Canonicalize paths and verify they start with the expected base directory",
        "Reject paths containing '../' or encoded equivalents",
        "Use an allowlist of permitted file extensions",
        "Run the application with minimal filesystem permissions",
    ],
    "file_upload": [
        "Validate file type by content (magic bytes), not just extension",
        "Rename uploaded files to random names on the server",
        "Store uploaded files outside the web root",
        "Limit file size and enforce quota limits",
        "Scan uploads with an antivirus/malware scanner",
    ],
    "xxe": [
        "Disable external entity processing in all XML parsers",
        "Use setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
        "Use less complex data formats such as JSON when possible",
        "Patch or upgrade XML processors and libraries regularly",
    ],
    "deserialization": [
        "Never deserialize data from untrusted sources",
        "Implement integrity checks such as digital signatures",
        "Use allowlists to restrict deserializable class types",
        "Run deserialization code in isolated low-privilege environments",
        "Monitor and log deserialization exceptions and failures",
    ],
    "ssrf": [
        "Use an allowlist of permitted domains/IPs",
        "Disable HTTP redirects for outbound requests",
        "Block requests to private IP ranges and loopback addresses",
        "Validate and sanitize all user-supplied URLs",
        "Segment network access so the server cannot reach internal services unnecessarily",
    ],
    "auth_bypass": [
        "Enforce authentication on every protected endpoint",
        "Use strong, well-reviewed authentication libraries",
        "Implement multi-factor authentication for sensitive actions",
        "Use short-lived, properly signed session tokens",
        "Validate authorization on the server — never trust client-side checks",
    ],
    "other_injection": [
        "Validate and sanitize all user-supplied input",
        "Use parameterized APIs instead of string concatenation",
        "Apply output encoding appropriate to the context",
        "Implement allowlists rather than denylists for input validation",
    ],
    "rce": [
        "Avoid executing user-supplied code or commands",
        "Sandbox code execution in isolated environments",
        "Apply strict input validation and allowlists",
        "Keep all interpreters and runtimes patched and up to date",
    ],
}

SUMMARIES = {
    "sql_injection":     "SQL injection occurs when untrusted user input is embedded directly into SQL queries without proper sanitization. Attackers can manipulate query logic to extract sensitive data, bypass authentication, or modify database content. It is consistently ranked in the OWASP Top 10 and can lead to complete database compromise.",
    "xss":               "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. The injected code executes in the victim's browser, enabling session hijacking, credential theft, and malware delivery. It is the most prevalent web application security flaw.",
    "csrf":              "Cross-Site Request Forgery tricks authenticated users into submitting unintended requests to a web application. Attackers exploit the browser's automatic inclusion of credentials (cookies) to perform actions on behalf of the victim. Effective mitigations include anti-CSRF tokens and SameSite cookies.",
    "command_injection": "Command injection allows attackers to execute arbitrary operating system commands on the host server by injecting malicious input into shell commands. Successful exploitation can lead to full server compromise, data exfiltration, and lateral movement within the network.",
    "path_traversal":    "Path traversal vulnerabilities allow attackers to access files and directories outside the intended root by manipulating file path inputs with sequences like '../'. This can expose sensitive configuration files, credentials, and source code.",
    "file_upload":       "Unrestricted file upload enables attackers to upload malicious files (e.g., web shells) to the server. If the uploaded file is accessible and executable, it can lead to remote code execution, server compromise, and data exfiltration.",
    "xxe":               "XML External Entity (XXE) injection exploits vulnerable XML parsers to read local files, perform SSRF, or execute denial-of-service attacks. Disabling DTD processing and external entity resolution in the XML parser is the primary defense.",
    "deserialization":   "Insecure deserialization occurs when applications deserialize data from untrusted sources without validation, allowing attackers to manipulate serialized objects to achieve remote code execution or privilege escalation.",
    "ssrf":              "Server-Side Request Forgery allows attackers to induce the server to make HTTP requests to unintended targets, including internal services behind firewalls. This can be used to access cloud metadata endpoints, internal APIs, and sensitive infrastructure.",
    "auth_bypass":       "Authentication bypass vulnerabilities allow attackers to access protected resources without valid credentials. Common causes include flawed logic, weak session management, insecure direct object references, and missing authorization checks.",
    "other_injection":   "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. Beyond SQL and OS command injection, this category includes LDAP, XPath, and template injection vulnerabilities.",
    "rce":               "Remote Code Execution allows attackers to run arbitrary code on the target server, often resulting from deserialization, template injection, or command injection vulnerabilities. RCE is the most severe class of web vulnerability.",
}

PREVALENCE = {
    "sql_injection":    "Found in 23% of web applications; ranked #3 in OWASP Top 10 2021",
    "xss":              "Found in 36% of web applications; most common web vulnerability",
    "csrf":             "Declining due to SameSite cookies; still common in legacy apps",
    "command_injection":"High severity; found in 8% of applications",
    "path_traversal":   "Found in 12% of web applications",
    "file_upload":      "Found in 15% of applications accepting file uploads",
    "xxe":              "Found in 18% of applications processing XML",
    "deserialization":  "Found in 10% of applications; declining due to framework mitigations",
    "ssrf":             "Newly ranked OWASP Top 10 2021 #10; increasing with cloud adoption",
    "auth_bypass":      "Found in 15% of web applications; #7 in OWASP Top 10 2021",
    "other_injection":  "Broad category; varies by injection subtype",
    "rce":              "Less common but highest severity; often chained from other vulns",
}

# Build OWASP doc index for content extraction
owasp_doc_index = {}
for doc in owasp_docs:
    owasp_doc_index[doc["title"]] = doc.get("content", "")

def extract_owasp_summary(vuln_type: str) -> str:
    """Extract first 400 chars of best-matching OWASP doc, falling back to curated summary."""
    for title in OWASP_DOC_MAP.get(vuln_type, []):
        content = owasp_doc_index.get(title, "")
        if content:
            # Take first non-blank paragraph
            paragraphs = [p.strip() for p in content.split("\n\n") if p.strip()]
            for para in paragraphs[1:4]:  # Skip the heading
                if len(para) > 80:
                    return para[:500].rstrip()
    return SUMMARIES.get(vuln_type, "")

# Build CVE index by keyword
def find_matching_cves(vuln_type: str, n: int = 3) -> list:
    keywords = {
        "sql_injection":    ["sql injection", "sql inject"],
        "xss":              ["cross-site scripting", "xss"],
        "csrf":             ["cross-site request forgery", "csrf"],
        "command_injection":["command injection", "os command", "shell injection"],
        "path_traversal":   ["path traversal", "directory traversal", "local file inclusion"],
        "file_upload":      ["file upload", "unrestricted upload", "arbitrary file"],
        "xxe":              ["xml external entity", "xxe"],
        "deserialization":  ["deserializ", "serializ"],
        "ssrf":             ["server-side request forgery", "ssrf"],
        "auth_bypass":      ["authentication bypass", "auth bypass", "privilege escalation"],
        "other_injection":  ["injection"],
        "rce":              ["remote code execution", "arbitrary code execution"],
    }
    kws = keywords.get(vuln_type, [])
    matched = []
    for cve in cves_raw:
        desc = cve.get("description", "").lower()
        if any(kw in desc for kw in kws):
            matched.append(cve)
        if len(matched) >= n * 5:
            break
    # Prefer CVEs with known severity
    matched.sort(key=lambda c: (c.get("cvss_score", 0) or 0), reverse=True)
    result = []
    for cve in matched[:n]:
        result.append({
            "id":          cve["id"],
            "description": cve["description"][:200],
            "severity":    cve.get("severity", "UNKNOWN"),
            "cvss_score":  cve.get("cvss_score", 0.0),
            "cwe_ids":     cve.get("cwe_ids", []),
        })
    return result

vuln_types_in_data = set(
    v for i in (train_with_ids + eval_cases)
    for v in (i.get("vulnerability_types") or i.get("ground_truth", {}).get("vulnerability_types", []))
)

citation_entries = {}
for vuln_type in sorted(vuln_types_in_data):
    cwe_id, cwe_name = CWE_MAP.get(vuln_type, ("CWE-74", "Injection"))
    owasp_url  = OWASP_URLS.get(vuln_type, "https://owasp.org/www-project-top-ten/")
    owasp_cat  = OWASP_TOP10.get(vuln_type, "A03:2021 – Injection")
    key_points = KEY_POINTS.get(vuln_type, ["Validate all user input", "Apply least privilege"])
    summary    = extract_owasp_summary(vuln_type) or SUMMARIES.get(vuln_type, "")
    example_cves = find_matching_cves(vuln_type)

    citation_entries[vuln_type] = {
        "cwe": {
            "id":   cwe_id,
            "name": cwe_name,
            "url":  f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
        },
        "severity": SEVERITY_MAP.get(vuln_type, "medium").upper(),
        "owasp": {
            "category":   owasp_cat,
            "url":        owasp_url,
            "key_points": key_points,
            "summary":    summary,
        },
        "example_cves": example_cves,
        "statistics": {
            "prevalence":      PREVALENCE.get(vuln_type, ""),
            "attack_vector":   "Network",
            "typical_impact":  "Data breach, unauthorized access, or server compromise",
        },
    }
    print(f"  Citation: {vuln_type} — {len(example_cves)} CVEs matched")

citation_map = {
    "version":             "1.0",
    "created_at":          TODAY,
    "description":         "Static citation mapping for vulnerability types — CWE, OWASP, and CVE references",
    "vulnerability_types": citation_entries,
}

with open(PROCESSED / "citation_map.json", "w") as f:
    json.dump(citation_map, f, indent=2, ensure_ascii=False)
print(f"  Saved: {len(citation_entries)} vulnerability type entries")

# ──────────────────────────────────────────────
# 4. Few-Shot Examples
# ──────────────────────────────────────────────

print("Building few_shot_examples.json ...")

FEW_SHOT_SPECS = [
    {
        "vuln_type": "sql_injection",
        "language":  "php",
        "source":    "dvwa",
        "input_code": (
            "<?php\n"
            "$id = $_GET['id'];\n"
            "$query = \"SELECT first_name, last_name FROM users WHERE user_id = '$id';\";\n"
            "$result = mysqli_query($GLOBALS['___mysqli_ston'], $query);\n"
            "while ($row = mysqli_fetch_assoc($result)) {\n"
            "    echo 'ID: ' . $row['user_id'] . '<br />';\n"
            "    echo 'First name: ' . $row['first_name'] . '<br />';\n"
            "}"
        ),
        "expected_output": {
            "vulnerability_detected": True,
            "vulnerability_types":    ["sql_injection"],
            "severity":               "CRITICAL",
            "cwe":                    "CWE-89",
            "location":               "line 2-3",
            "explanation":            "User input from $_GET['id'] is directly interpolated into the SQL query string without sanitization or parameterization, enabling classic SQL injection. An attacker can input `' OR '1'='1` to retrieve all rows or use UNION-based injection to exfiltrate other tables.",
            "fix_suggestion":         (
                "Use prepared statements:\n\n"
                "$stmt = $conn->prepare(\"SELECT first_name, last_name FROM users WHERE user_id = ?\");\n"
                "$stmt->bind_param('s', $id);\n"
                "$stmt->execute();\n"
                "$result = $stmt->get_result();"
            ),
            "references": {
                "owasp": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "cwe":   "https://cwe.mitre.org/data/definitions/89.html",
            },
        },
    },
    {
        "vuln_type": "xss",
        "language":  "php",
        "source":    "dvwa",
        "input_code": (
            "<?php\n"
            "if (array_key_exists('name', $_GET) && $_GET['name'] != NULL) {\n"
            "    $html .= '<pre>Hello ' . $_GET['name'] . '</pre>';\n"
            "}"
        ),
        "expected_output": {
            "vulnerability_detected": True,
            "vulnerability_types":    ["xss"],
            "severity":               "HIGH",
            "cwe":                    "CWE-79",
            "location":               "line 3",
            "explanation":            "The value of $_GET['name'] is directly concatenated into HTML output without escaping. An attacker can inject `<script>document.cookie</script>` to steal session cookies or perform phishing attacks.",
            "fix_suggestion":         (
                "HTML-encode the output:\n\n"
                "$html .= '<pre>Hello ' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '</pre>';"
            ),
            "references": {
                "owasp": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "cwe":   "https://cwe.mitre.org/data/definitions/79.html",
            },
        },
    },
    {
        "vuln_type": "path_traversal",
        "language":  "java",
        "source":    "webgoat",
        "input_code": (
            "public AttackResult uploadFileHandler(\n"
            "        @RequestParam(value = \"uploadedFile\") MultipartFile file,\n"
            "        @RequestParam(value = \"fullName\") String fullName) throws IOException {\n"
            "    File uploadDirectory = new File(\"webgoat/uploads\");\n"
            "    Path uploadedFile = Paths.get(uploadDirectory.getAbsolutePath(), \n"
            "                                  file.getOriginalFilename());\n"
            "    Files.copy(file.getInputStream(), uploadedFile);\n"
            "}"
        ),
        "expected_output": {
            "vulnerability_detected": True,
            "vulnerability_types":    ["path_traversal", "file_upload"],
            "severity":               "HIGH",
            "cwe":                    "CWE-22",
            "location":               "line 5-6",
            "explanation":            "file.getOriginalFilename() returns the client-supplied filename without validation. An attacker can supply '../../etc/passwd' or '../webapps/shell.jsp' to write files outside the upload directory, enabling path traversal and potential RCE.",
            "fix_suggestion":         (
                "Normalize and validate the path:\n\n"
                "String safeName = Paths.get(file.getOriginalFilename()).getFileName().toString();\n"
                "Path resolved = uploadDirectory.toPath().resolve(safeName).normalize();\n"
                "if (!resolved.startsWith(uploadDirectory.toPath())) {\n"
                "    throw new SecurityException(\"Path traversal detected\");\n"
                "}\n"
                "Files.copy(file.getInputStream(), resolved);"
            ),
            "references": {
                "owasp": "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                "cwe":   "https://cwe.mitre.org/data/definitions/22.html",
            },
        },
    },
    {
        "vuln_type": "command_injection",
        "language":  "php",
        "source":    "dvwa",
        "input_code": (
            "<?php\n"
            "if (isset($_POST['Submit'])) {\n"
            "    $target = $_POST['ip'];\n"
            "    if (stristr(php_uname('s'), 'Windows NT')) {\n"
            "        $cmd = shell_exec('ping  ' . $target);\n"
            "    } else {\n"
            "        $cmd = shell_exec('ping  -c 4 ' . $target);\n"
            "    }\n"
            "    echo '<pre>' . $cmd . '</pre>';\n"
            "}"
        ),
        "expected_output": {
            "vulnerability_detected": True,
            "vulnerability_types":    ["command_injection"],
            "severity":               "CRITICAL",
            "cwe":                    "CWE-78",
            "location":               "lines 4-7",
            "explanation":            "The $_POST['ip'] value is passed directly to shell_exec() without validation. An attacker can inject additional commands using shell metacharacters: `127.0.0.1; cat /etc/passwd` or `127.0.0.1 && rm -rf /`.",
            "fix_suggestion":         (
                "Validate input against an allowlist:\n\n"
                "$ip = $_POST['ip'];\n"
                "if (!filter_var($ip, FILTER_VALIDATE_IP)) {\n"
                "    die('Invalid IP address');\n"
                "}\n"
                "$cmd = shell_exec('ping -c 4 ' . escapeshellarg($ip));"
            ),
            "references": {
                "owasp": "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                "cwe":   "https://cwe.mitre.org/data/definitions/78.html",
            },
        },
    },
    {
        "vuln_type": "auth_bypass",
        "language":  "java",
        "source":    "webgoat",
        "input_code": (
            "@GetMapping(\"/\")  \n"
            "@ResponseBody\n"
            "public AttackResult completed(\n"
            "        @RequestParam Integer accountNo,\n"
            "        @RequestParam String accountName) {\n"
            "    return injectableQuery(accountNo);\n"
            "}\n\n"
            "private AttackResult injectableQuery(Integer accountNo) {\n"
            "    String query = \"SELECT * FROM user_data WHERE userid = \" + accountNo;\n"
            "    // Execute query and return account data\n"
            "}"
        ),
        "expected_output": {
            "vulnerability_detected": True,
            "vulnerability_types":    ["auth_bypass", "sql_injection"],
            "severity":               "CRITICAL",
            "cwe":                    "CWE-287",
            "location":               "line 10",
            "explanation":            "The accountNo parameter is used directly in a SQL query without authorization checks. Any authenticated user can supply another user's account number to access their data (IDOR), and the SQL concatenation enables SQL injection attacks.",
            "fix_suggestion":         (
                "Add authorization check and use parameterized query:\n\n"
                "// Verify the accountNo belongs to the authenticated user\n"
                "if (!currentUser.getAccountNo().equals(accountNo)) {\n"
                "    throw new AccessDeniedException(\"Not authorized\");\n"
                "}\n"
                "PreparedStatement stmt = conn.prepareStatement(\n"
                "    \"SELECT * FROM user_data WHERE userid = ?\");\n"
                "stmt.setInt(1, accountNo);"
            ),
            "references": {
                "owasp": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                "cwe":   "https://cwe.mitre.org/data/definitions/287.html",
            },
        },
    },
]

few_shot_list = []
for idx, spec in enumerate(FEW_SHOT_SPECS, 1):
    few_shot_list.append({
        "example_id":       f"fewshot_{idx:03d}",
        "vulnerability_type": spec["vuln_type"],
        "language":         spec["language"],
        "source":           spec["source"],
        "input_code":       spec["input_code"],
        "expected_output":  spec["expected_output"],
    })

few_shot = {
    "version":       "1.0",
    "created_at":    TODAY,
    "description":   "High-quality few-shot examples for prompting the CodeGuardian LLM",
    "total_examples": len(few_shot_list),
    "usage":         "Prepend these examples to the LLM prompt to guide vulnerability detection format and quality.",
    "examples":      few_shot_list,
}

with open(PROCESSED / "few_shot_examples.json", "w") as f:
    json.dump(few_shot, f, indent=2, ensure_ascii=False)
print(f"  Saved: {len(few_shot_list)} few-shot examples")

# ──────────────────────────────────────────────
# 5. Statistics files
# ──────────────────────────────────────────────

print("Building statistics files ...")

all_items = train_with_ids + eval_cases

# Normalise eval_cases to same schema for stats
def eval_vuln_types(case):
    return case.get("ground_truth", {}).get("vulnerability_types", case.get("vulnerability_types", []))

full_vuln_counts = Counter()
for item in train_with_ids:
    for v in item.get("vulnerability_types", []):
        full_vuln_counts[v] += 1
for case in eval_cases:
    for v in eval_vuln_types(case):
        full_vuln_counts[v] += 1

full_lang_counts = Counter(
    item.get("language", "unknown") for item in train_with_ids
) + Counter(
    case.get("language", "unknown") for case in eval_cases
)

full_source_counts = Counter(
    item.get("source", "unknown") for item in train_with_ids
) + Counter(
    case.get("source", "unknown") for case in eval_cases
)

dataset_statistics = {
    "created_at":      TODAY,
    "total_items":     len(train_with_ids) + len(eval_cases),
    "training_items":  len(train_with_ids),
    "evaluation_items":len(eval_cases),
    "by_source": {
        "training":   dict(Counter(i["source"] for i in train_with_ids)),
        "evaluation": dict(Counter(c["source"] for c in eval_cases)),
        "total":      dict(full_source_counts),
    },
    "by_language": {
        "training":   dict(Counter(i["language"] for i in train_with_ids)),
        "evaluation": dict(Counter(c["language"] for c in eval_cases)),
        "total":      dict(full_lang_counts),
    },
    "by_severity": {
        "training":   dict(Counter(i["severity"] for i in train_with_ids)),
        "evaluation": dict(Counter(
            c.get("ground_truth", {}).get("severity", "unknown") for c in eval_cases
        )),
    },
    "raw_source_counts": {
        "dvwa_original":   len(dvwa_items),
        "webgoat_original":len(webgoat_items),
        "exploitdb_original": len(exploitdb_items),
        "owasp_benchmark_original": len(bench_items),
        "github_issues_original": len(issues_raw),
        "github_issues_with_code": len(issues_with_code),
        "cves_available":  len(cves_raw),
        "owasp_docs":      len(owasp_docs),
    },
}

with open(STATS_DIR / "dataset_statistics.json", "w") as f:
    json.dump(dataset_statistics, f, indent=2)

vuln_dist = {
    "created_at": TODAY,
    "vulnerability_distribution": dict(full_vuln_counts),
    "training_distribution":  dict(Counter(
        v for i in train_with_ids for v in i.get("vulnerability_types", [])
    )),
    "evaluation_distribution": dict(Counter(
        v for c in eval_cases for v in eval_vuln_types(c)
    )),
}
with open(STATS_DIR / "vulnerability_distribution.json", "w") as f:
    json.dump(vuln_dist, f, indent=2)

lang_cov = {
    "created_at": TODAY,
    "language_coverage": dict(full_lang_counts),
    "training":   dict(Counter(i["language"] for i in train_with_ids)),
    "evaluation": dict(Counter(c["language"] for c in eval_cases)),
}
with open(STATS_DIR / "language_coverage.json", "w") as f:
    json.dump(lang_cov, f, indent=2)

print("  Saved: dataset_statistics.json, vulnerability_distribution.json, language_coverage.json")

# ──────────────────────────────────────────────
# 6. DATASET_README.md
# ──────────────────────────────────────────────

print("Building docs/DATASET_README.md ...")

vuln_dist_table = "\n".join(
    f"| {v:<25} | {full_vuln_counts[v]:>8} | {int(full_vuln_counts[v]/(len(train_with_ids)+len(eval_cases))*100):>7}% |"
    for v in sorted(full_vuln_counts, key=lambda x: -full_vuln_counts[x])
)

lang_dist_table = "\n".join(
    f"| {lang:<12} | {cnt:>8} |"
    for lang, cnt in sorted(full_lang_counts.items(), key=lambda x: -x[1])
)

readme = f"""# CodeGuardian Dataset Documentation

## Overview

This dataset powers **CodeGuardian**, an AI-powered security code review system that detects
vulnerabilities, provides explanations, suggests fixes, and cites authoritative security references.

**System Architecture:** Single-tier RAG for vulnerability detection with static citation mapping
for OWASP guidance and CVE references, and LLM-powered fix suggestions.

---

## Dataset Composition

### Training Dataset ({len(train_with_ids)} items)

| Source | Count | Description |
|--------|------:|-------------|
| DVWA | {len(train_dvwa)} | PHP vulnerable web application files |
| WebGoat | {len(train_webgoat)} | Java security training lesson files |
| OWASP Benchmark | {len(train_benchmark)} | Java security test cases |
| Exploit-DB | {len(train_exploitdb)} | Real-world exploit code examples |
| GitHub Issues | {len(train_github)} | Security issue code snippets |

### Evaluation Set ({len(eval_cases)} items)

| Source | Count | Type |
|--------|------:|------|
| OWASP Benchmark | {len(eval_benchmark)} | Vulnerable Java test cases |
| WebGoat | {len(eval_webgoat)} | Java security lessons |
| DVWA | {len(eval_dvwa)} | PHP vulnerable code |
| Exploit-DB | {len(eval_exploitdb)} | Exploit patterns |

### Reference Library

| Resource | Count | Purpose |
|----------|------:|---------|
| CVE Database | {len(cves_raw)} | Vulnerability records for citation curation |
| OWASP Documentation | {len(owasp_docs)} | Security cheat sheets for guidance extraction |

---

## Vulnerability Coverage

| Vulnerability Type | Count | Coverage |
|--------------------|------:|---------|
{vuln_dist_table}

---

## Language Distribution

| Language | Count |
|----------|------:|
{lang_dist_table}

---

## File Descriptions

### `data/processed/training_dataset.json`
Unified training dataset with {len(train_with_ids)} items. Each item has:
- `item_id` — unique identifier (train_001, train_002, ...)
- `source` — original data source
- `language` — programming language
- `vulnerability_types` — list of vulnerability categories (multi-label)
- `severity` — critical / high / medium / low
- `code` — vulnerable code snippet
- `metadata` — source-specific fields (file path, lesson type, etc.)

### `data/processed/evaluation_set.json`
Held-out test cases with {len(eval_cases)} items. Each has:
- `test_id` — unique identifier (eval_001, ...)
- `ground_truth` — vulnerability types, severity, explanation
- `expected_citations` — CWE ID and OWASP category for citation evaluation

### `data/processed/citation_map.json`
Static citation reference for {len(citation_entries)} vulnerability types. Each entry contains:
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
- **WebGoat:** 10 eval / {len(train_webgoat)} train
- **Exploit-DB:** 20 eval / {len(train_exploitdb)} train
- **DVWA:** 5 eval / {len(train_dvwa)} train
- **GitHub Issues:** 0 eval / {len(train_github)} train (all code-bearing issues)

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
"""

with open(DOCS_DIR / "DATASET_README.md", "w") as f:
    f.write(readme)
print("  Saved: docs/DATASET_README.md")

# ──────────────────────────────────────────────
# Final summary
# ──────────────────────────────────────────────

print("\n" + "=" * 60)
print("Build Complete")
print("=" * 60)
print(f"\nFiles written to data/processed/:")
print(f"  training_dataset.json   — {len(train_with_ids)} items")
print(f"  evaluation_set.json     — {len(eval_cases)} items")
print(f"  citation_map.json       — {len(citation_entries)} vulnerability types")
print(f"  few_shot_examples.json  — {len(few_shot_list)} examples")
print(f"\nFiles written to data/statistics/:")
print(f"  dataset_statistics.json")
print(f"  vulnerability_distribution.json")
print(f"  language_coverage.json")
print(f"\nFiles written to docs/:")
print(f"  DATASET_README.md")

print(f"\nVulnerability distribution (train+eval):")
for v, cnt in sorted(full_vuln_counts.items(), key=lambda x: -x[1]):
    print(f"  {v:<25}: {cnt}")

print(f"\nLanguage distribution (train+eval):")
for lang, cnt in sorted(full_lang_counts.items(), key=lambda x: -x[1]):
    print(f"  {lang:<12}: {cnt}")

print(f"\nCitation map coverage: {list(citation_entries.keys())}")
print("=" * 60)

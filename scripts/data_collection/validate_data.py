"""
Validate collected data quality
"""

import json
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)

class DataValidator:
    """Validate collected data meets quality standards"""
    
    def __init__(self):
        self.data_dir = Path('data/raw')
    
    def validate_all(self):
        """Run all validation checks"""
        
        print("\n" + "="*60)
        print("DATA VALIDATION REPORT")
        print("="*60 + "\n")
        
        self.validate_cves()
        self.validate_github_issues()
        self.validate_owasp()
        self.validate_code_examples()
        
        print("\n" + "="*60)
        print("VALIDATION COMPLETE")
        print("="*60 + "\n")
    
    def validate_cves(self):
        """Validate CVE data"""
        cve_files = list((self.data_dir / 'cves').glob('cves_*.json'))
        
        if not cve_files:
            print("❌ No CVE data found")
            return
        
        # Load most recent file
        latest = max(cve_files, key=lambda p: p.stat().st_mtime)
        
        with open(latest) as f:
            cves = json.load(f)
        
        # Validate
        print(f"✅ CVEs: {len(cves)} collected")
        
        # Check severity distribution
        severities = {}
        for cve in cves:
            sev = cve.get('severity', 'UNKNOWN')
            severities[sev] = severities.get(sev, 0) + 1
        
        print(f"   Severity: {severities}")
        
        # Check for descriptions
        with_desc = sum(1 for c in cves if c.get('description'))
        print(f"   With descriptions: {with_desc}/{len(cves)}")
        
        if len(cves) < 100:
            print("   ⚠️ Warning: Less than 100 CVEs. Recommend collecting more.")
    
    def validate_github_issues(self):
        """Validate GitHub issues"""
        issue_files = list((self.data_dir / 'github_issues').glob('github_issues_*.json'))
        
        if not issue_files:
            print("❌ No GitHub issues found")
            return
        
        latest = max(issue_files, key=lambda p: p.stat().st_mtime)
        
        with open(latest) as f:
            issues = json.load(f)
        
        print(f"✅ GitHub Issues: {len(issues)} collected")
        
        # Language breakdown
        languages = {}
        for issue in issues:
            lang = issue.get('language', 'Unknown')
            languages[lang] = languages.get(lang, 0) + 1
        
        print(f"   Languages: {languages}")
        
        if len(issues) < 50:
            print("   ⚠️ Warning: Less than 50 issues. Recommend collecting more.")
    
    def validate_owasp(self):
        """Validate OWASP docs"""
        owasp_files = list((self.data_dir / 'owasp').glob('owasp_docs_*.json'))
        
        if not owasp_files:
            print("❌ No OWASP documentation found")
            return
        
        latest = max(owasp_files, key=lambda p: p.stat().st_mtime)
        
        with open(latest) as f:
            docs = json.load(f)
        
        print(f"✅ OWASP Docs: {len(docs)} collected")
        
        # Type breakdown
        types = {}
        for doc in docs:
            dtype = doc.get('type', 'unknown')
            types[dtype] = types.get(dtype, 0) + 1
        
        print(f"   Types: {types}")
    
    def validate_code_examples(self):
        """Validate code examples"""
        example_files = list((self.data_dir / 'code_examples').glob('code_examples_*.json'))
        
        if not example_files:
            print("⚠️ No code examples found (optional)")
            return
        
        latest = max(example_files, key=lambda p: p.stat().st_mtime)
        
        with open(latest) as f:
            examples = json.load(f)
        
        print(f"✅ Code Examples: {len(examples)} collected")


if __name__ == "__main__":
    validator = DataValidator()
    validator.validate_all()
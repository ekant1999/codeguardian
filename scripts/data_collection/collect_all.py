"""
Master script to run all data collection (v2 - clean output)
"""

import os
import sys
from pathlib import Path
import logging

# Add scripts directory to path
sys.path.append(str(Path(__file__).parent))

from collect_cves import main as collect_cves
from collect_github_issues import main as collect_github_issues
from collect_owasp import main as collect_owasp
from collect_code_examples import main as collect_code_examples

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

V2_DIRS = [
    'data/raw/v2/cves',
    'data/raw/v2/github_issues',
    'data/raw/v2/owasp',
    'data/raw/v2/code_examples',
]

def main():
    """Run all collection scripts, saving clean data to data/raw/v2/"""

    print("\n" + "="*70)
    print("  CodeGuardian Data Collection Suite (v2 - Clean Output)")
    print("="*70 + "\n")

    print("This will collect and clean:")
    print("  1. CVE vulnerability data from NVD            → data/raw/v2/cves/cves.json")
    print("  2. Security issues from GitHub repositories   → data/raw/v2/github_issues/issues.json")
    print("  3. OWASP security documentation               → data/raw/v2/owasp/documentation.json")
    print("  4. Code examples from OWASP Benchmark         → data/raw/v2/code_examples/examples.json")
    print("\nCleaning applied during collection:")
    print("  - CVEs:          no cleaning needed (already structured)")
    print("  - GitHub issues: code snippets extracted, spam flagged")
    print("  - OWASP docs:    navigation menus and ToC removed")
    print("  - Code examples: license headers and package declarations removed")
    print("\nEstimated time: 15-20 minutes")
    print("Internet connection required\n")

    response = input("Continue? (y/n): ")

    if response.lower() != 'y':
        print("Collection cancelled.")
        return

    # Ensure all v2 output directories exist
    for d in V2_DIRS:
        os.makedirs(d, exist_ok=True)

    # Run each collector
    try:
        print("\n" + "="*70)
        print("STEP 1/4: Collecting CVE Data")
        print("="*70)
        collect_cves()

        print("\n" + "="*70)
        print("STEP 2/4: Collecting GitHub Issues")
        print("="*70)
        collect_github_issues()

        print("\n" + "="*70)
        print("STEP 3/4: Collecting OWASP Documentation")
        print("="*70)
        collect_owasp()

        print("\n" + "="*70)
        print("STEP 4/4: Collecting Code Examples")
        print("="*70)
        collect_code_examples()

        print("\n" + "="*70)
        print("  ✅ DATA COLLECTION COMPLETE!")
        print("="*70)
        print("\nClean data saved in: data/raw/v2/")
        print("  ├── cves/           cves.json + metadata.json")
        print("  ├── github_issues/  issues.json + metadata.json")
        print("  ├── owasp/          documentation.json + metadata.json")
        print("  └── code_examples/  examples.json + metadata.json")
        print("\nLogs saved in: logs/")
        print("\nNext steps:")
        print("  1. Run validate_data.py to check collection quality")
        print("  2. Load data/raw/v2/ directly into your RAG pipeline")

    except Exception as e:
        logging.error(f"Collection failed: {e}")
        print(f"\n❌ Error: {e}")
        print("Check logs/ directory for details")


if __name__ == "__main__":
    main()
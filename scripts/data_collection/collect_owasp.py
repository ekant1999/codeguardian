"""
Collect OWASP (Open Web Application Security Project) documentation
UPDATED: Uses HTML-based cleaning to eliminate navigation pollution for RAG.
"""

import re
import requests
from bs4 import BeautifulSoup
import json
from pathlib import Path
import logging
from datetime import datetime
import time


def clean_owasp_html(html: str) -> str:
    """
    Extract clean content from OWASP cheat sheet HTML using DOM parsing.

    The OWASP cheat sheet site (Material MkDocs) has this structure:
      - <nav class="md-nav md-nav--primary">  → left sidebar nav  (REMOVE)
      - <nav class="md-nav md-nav--secondary"> → right TOC sidebar (REMOVE)
      - <article class="md-content__inner md-typeset"> → actual content (KEEP)

    For owasp.org community pages the structure differs; falls back to
    <article>, then <main>, then <div class="content">.

    Also removes the "Related Articles" section at the end of cheat sheets.
    """
    soup = BeautifulSoup(html, 'html.parser')

    # Primary target: MkDocs article container used by cheatsheetseries.owasp.org
    article = soup.find('article', class_='md-content__inner')

    # Fallbacks for owasp.org community pages
    if not article:
        article = soup.find('article')
    if not article:
        article = soup.find('main')
    if not article:
        article = soup.find('div', class_='content')

    if not article:
        logging.error("No content container found in HTML")
        return ""

    # Remove "Related Articles" h2 and everything that follows it
    for heading in article.find_all(['h2', 'h1']):
        if 'related articles' in heading.get_text().lower():
            for sibling in list(heading.find_next_siblings()):
                sibling.decompose()
            heading.decompose()
            break

    # Extract text, preserving paragraph structure
    content = article.get_text(separator='\n', strip=True)

    # Collapse runs of 3+ blank lines down to 2
    content = re.sub(r'\n{3,}', '\n\n', content)
    # Collapse multiple spaces
    content = re.sub(r' {2,}', ' ', content)

    return content.strip()


def validate_cleaning(html: str, cleaned_text: str) -> dict:
    """
    Validate that HTML-based cleaning removed navigation pollution.
    Returns a stats dict that is stored alongside each collected document.
    """
    nav_indicators = [
        'Index Alphabetical',
        'Index ASVS',
        'Index MASVS',
        'Index Proactive Controls',
        'Index Top 10',
    ]
    pollution_count = sum(1 for ind in nav_indicators if ind in cleaned_text)
    related_removed = 'Related Articles' not in cleaned_text
    original_len = len(html)
    cleaned_len = len(cleaned_text)
    reduction_pct = (1 - cleaned_len / original_len) * 100 if original_len else 0

    return {
        'original_length': original_len,
        'cleaned_length': cleaned_len,
        'reduction_pct': round(reduction_pct, 1),
        'nav_pollution_items_found': pollution_count,
        'related_articles_removed': related_removed,
        'cleaning_successful': pollution_count == 0 and related_removed,
    }


class OWASPCollector:
    """
    Collect OWASP security guidelines and documentation.
    Uses HTML-based cleaning so navigation menus never reach the saved file.
    """

    def __init__(self, output_dir='data/raw/v2/owasp'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def collect_all(self):
        """Collect all OWASP documentation"""

        all_docs = []

        logging.info("Collecting OWASP Cheat Sheets...")
        cheat_sheets = self._collect_cheat_sheets()
        all_docs.extend(cheat_sheets)
        logging.info(f"  Collected {len(cheat_sheets)} cheat sheets")

        logging.info("Collecting OWASP vulnerability pages...")
        vuln_docs = self._collect_working_vulnerability_pages()
        all_docs.extend(vuln_docs)
        logging.info(f"  Collected {len(vuln_docs)} vulnerability pages")

        logging.info("Collecting OWASP attack pages...")
        attack_docs = self._collect_working_attack_pages()
        all_docs.extend(attack_docs)
        logging.info(f"  Collected {len(attack_docs)} attack pages")

        self._save_docs(all_docs)

        return all_docs

    def _collect_cheat_sheets(self):
        cheat_sheet_urls = [
            # Core security topics
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',

            # Authentication & Session
            'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',

            # Input/Output
            'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html',

            # Cryptography
            'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html',

            # Security Headers & Config
            'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',

            # Error Handling & Logging
            'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',

            # XML & APIs
            'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html',

            # File handling
            'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',

            # Deserialization
            'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
        ]

        docs = []
        for url in cheat_sheet_urls:
            try:
                page_name = url.split('/')[-1].replace('.html', '')
                doc = self._fetch_and_parse(url, 'cheat_sheet', page_name)
                if doc:
                    docs.append(doc)
                time.sleep(1)
            except Exception as e:
                logging.error(f"  ✗ Error with {url}: {e}")
                continue

        return docs

    def _collect_working_vulnerability_pages(self):
        working_vuln_urls = [
            'https://owasp.org/www-community/vulnerabilities/Buffer_Overflow',
            'https://owasp.org/www-community/vulnerabilities/Insecure_Randomness',
            'https://owasp.org/www-community/vulnerabilities/Insecure_Deserialization',
        ]

        docs = []
        for url in working_vuln_urls:
            try:
                page_name = url.split('/')[-1]
                doc = self._fetch_and_parse(url, 'vulnerability', page_name)
                if doc:
                    docs.append(doc)
                time.sleep(1)
            except Exception as e:
                logging.debug(f"  Error with {url}: {e}")
                continue

        return docs

    def _collect_working_attack_pages(self):
        working_attack_urls = [
            'https://owasp.org/www-community/attacks/Code_Injection',
            'https://owasp.org/www-community/attacks/Command_Injection',
            'https://owasp.org/www-community/attacks/LDAP_Injection',
            'https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF',
        ]

        docs = []
        for url in working_attack_urls:
            try:
                page_name = url.split('/')[-1]
                doc = self._fetch_and_parse(url, 'attack', page_name)
                if doc:
                    docs.append(doc)
                time.sleep(1)
            except Exception as e:
                logging.debug(f"  Error with {url}: {e}")
                continue

        return docs

    def _fetch_and_parse(self, url, doc_type, page_name):
        """Fetch a page and clean it using HTML-based extraction."""

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            # Pass raw HTML to the HTML-aware cleaner (not pre-parsed text)
            clean_text = clean_owasp_html(response.text)

            # Validate cleaning quality
            validation = validate_cleaning(response.text, clean_text)

            if not validation['cleaning_successful']:
                logging.warning(
                    f"  ⚠ Cleaning issues for {page_name}: "
                    f"{validation['nav_pollution_items_found']} nav items remain, "
                    f"related_articles_removed={validation['related_articles_removed']}"
                )
            else:
                logging.info(
                    f"  ✓ {page_name} "
                    f"(reduced {validation['reduction_pct']:.1f}%, "
                    f"{validation['cleaned_length']:,} chars)"
                )

            if len(clean_text) < 100:
                logging.warning(f"  Content too short for {url} ({len(clean_text)} chars)")
                return None

            return {
                'type': doc_type,
                'title': page_name.replace('_', ' '),
                'url': url,
                'content': clean_text,
                'collected_at': datetime.now().isoformat(),
                'cleaning_stats': validation,
            }

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logging.debug(f"Page not found (404): {url}")
            else:
                logging.error(f"HTTP error fetching {url}: {e}")
            return None
        except Exception as e:
            logging.error(f"Error fetching {url}: {e}")
            return None

    def _save_docs(self, docs):
        """Save documentation and metadata to v2 output directory."""
        filename = self.output_dir / 'documentation.json'

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(docs, f, indent=2, ensure_ascii=False)

        logging.info(f"✓ Saved {len(docs)} OWASP documents to {filename}")

        successful_cleans = sum(
            1 for d in docs
            if d.get('cleaning_stats', {}).get('cleaning_successful', False)
        )
        avg_reduction = (
            sum(d.get('cleaning_stats', {}).get('reduction_pct', 0) for d in docs) / len(docs)
            if docs else 0
        )

        metadata = {
            'collection_date': datetime.now().isoformat(),
            'total_documents': len(docs),
            'type_breakdown': self._get_type_breakdown(docs),
            'successful_collections': len(docs),
            'cleaning_applied': {
                'method': 'html_parsing',
                'navigation_menus_removed': True,
                'table_of_contents_removed': True,
                'related_articles_removed': True,
                'successful_cleans': successful_cleans,
                'success_rate': f"{(successful_cleans / len(docs) * 100):.1f}%" if docs else "0%",
                'avg_size_reduction': f"{avg_reduction:.1f}%",
            }
        }

        meta_file = self.output_dir / 'owasp_documentation_metadata.json'
        with open(meta_file, 'w') as f:
            json.dump(metadata, f, indent=2)

    def _get_type_breakdown(self, docs):
        from collections import Counter
        return dict(Counter(d['type'] for d in docs))


def test_single_url():
    """
    Smoke-test the HTML cleaner on a single cheat sheet.
    Run directly: python collect_owasp.py
    """
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

    url = "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
    print(f"Fetching: {url}\n")

    response = requests.get(url, timeout=15)
    cleaned = clean_owasp_html(response.text)
    stats = validate_cleaning(response.text, cleaned)

    print("=" * 60)
    print("CLEANING TEST RESULTS")
    print("=" * 60)
    print(f"Original HTML size : {stats['original_length']:,} bytes")
    print(f"Cleaned text size  : {stats['cleaned_length']:,} bytes")
    print(f"Reduction          : {stats['reduction_pct']:.1f}%")
    print(f"Nav pollution found: {stats['nav_pollution_items_found']} items")
    print(f"Related arts removed: {stats['related_articles_removed']}")
    print(f"Cleaning successful: {stats['cleaning_successful']}")
    print("\nFirst 500 characters of cleaned content:")
    print("-" * 60)
    print(cleaned[:500])
    print("=" * 60)


def main():
    """Main execution"""

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/owasp_collection.log'),
            logging.StreamHandler()
        ],
        force=True
    )

    collector = OWASPCollector()

    logging.info("=" * 60)
    logging.info("Starting OWASP Documentation Collection (v2 - data/raw/v2/owasp/)")
    logging.info("Cleaning method: HTML-based (BeautifulSoup article extraction)")
    logging.info("=" * 60)

    docs = collector.collect_all()

    logging.info("=" * 60)
    logging.info(f"✓ Collection complete! Total documents: {len(docs)}")
    logging.info("=" * 60)

    if len(docs) < 10:
        logging.warning("⚠️ Fewer than expected documents collected")
        logging.warning("Some OWASP URLs may have changed")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        test_single_url()
    else:
        main()

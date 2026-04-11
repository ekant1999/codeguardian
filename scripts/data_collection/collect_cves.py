"""
Collect CVE (Common Vulnerabilities and Exposures) data
Source: National Vulnerability Database (NVD)
"""

import requests
import json
import time
from datetime import datetime
from pathlib import Path
import logging


class CVECollector:
    """
    Collects CVE data from National Vulnerability Database
    Focus: Security vulnerabilities relevant to code review
    """
    
    def __init__(self, output_dir='data/raw/v2/cves'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
    def collect_by_keywords(self, keywords, results_per_keyword=100):
        """
        Collect CVEs by security-related keywords
        
        Args:
            keywords: List of security terms to search
            results_per_keyword: Max CVEs to collect per keyword
        """
        all_cves = []
        
        for keyword in keywords:
            logging.info(f"Collecting CVEs for keyword: {keyword}")
            
            try:
                cves = self._fetch_cves_for_keyword(keyword, results_per_keyword)
                all_cves.extend(cves)
                logging.info(f"  Collected {len(cves)} CVEs for '{keyword}'")
                
                # Respect API rate limits
                time.sleep(6)  # NVD allows 5 requests per 30 seconds
                
            except Exception as e:
                logging.error(f"Error collecting CVEs for '{keyword}': {e}")
                continue
        
        # Remove duplicates (same CVE might match multiple keywords)
        unique_cves = self._deduplicate(all_cves)
        logging.info(f"Total unique CVEs collected: {len(unique_cves)}")
        
        # Save to file
        self._save_cves(unique_cves)
        
        return unique_cves
    
    def _fetch_cves_for_keyword(self, keyword, max_results):
        """Fetch CVEs from NVD API"""
        
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': min(max_results, 2000)  # API limit
        }
        
        response = requests.get(self.base_url, params=params)
        response.raise_for_status()
        
        data = response.json()
        
        cves = []
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            
            # Extract relevant information
            cve_data = {
                'id': cve.get('id'),
                'published': cve.get('published'),
                'last_modified': cve.get('lastModified'),
                'description': self._get_description(cve),
                'severity': self._get_severity(cve),
                'cvss_score': self._get_cvss_score(cve),
                'cwe_ids': self._get_cwe_ids(cve),
                'references': self._get_references(cve),
                'keyword_matched': keyword
            }
            
            cves.append(cve_data)
        
        return cves
    
    def _get_description(self, cve):
        """Extract English description"""
        descriptions = cve.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        return ''
    
    def _get_severity(self, cve):
        """Extract severity rating"""
        metrics = cve.get('metrics', {})
        
        # Try CVSS v3.1 first
        cvss_v31 = metrics.get('cvssMetricV31', [])
        if cvss_v31:
            return cvss_v31[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
        
        # Fallback to CVSS v3.0
        cvss_v30 = metrics.get('cvssMetricV30', [])
        if cvss_v30:
            return cvss_v30[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
        
        return 'UNKNOWN'
    
    def _get_cvss_score(self, cve):
        """Extract CVSS base score"""
        metrics = cve.get('metrics', {})
        
        cvss_v31 = metrics.get('cvssMetricV31', [])
        if cvss_v31:
            return cvss_v31[0].get('cvssData', {}).get('baseScore', 0.0)
        
        cvss_v30 = metrics.get('cvssMetricV30', [])
        if cvss_v30:
            return cvss_v30[0].get('cvssData', {}).get('baseScore', 0.0)
        
        return 0.0
    
    def _get_cwe_ids(self, cve):
        """Extract CWE (Common Weakness Enumeration) IDs"""
        weaknesses = cve.get('weaknesses', [])
        cwe_ids = []
        
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                cwe_id = desc.get('value', '')
                if cwe_id.startswith('CWE-'):
                    cwe_ids.append(cwe_id)
        
        return cwe_ids
    
    def _get_references(self, cve):
        """Extract reference URLs"""
        references = cve.get('references', [])
        return [ref.get('url') for ref in references[:3]]  # Keep top 3
    
    def _deduplicate(self, cves):
        """Remove duplicate CVEs"""
        seen = set()
        unique = []
        
        for cve in cves:
            if cve['id'] not in seen:
                seen.add(cve['id'])
                unique.append(cve)
        
        return unique
    
    def _save_cves(self, cves):
        """Save CVEs to JSON file"""
        filename = self.output_dir / 'cves.json'

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(cves, f, indent=2, ensure_ascii=False)

        logging.info(f"Saved {len(cves)} CVEs to {filename}")

        metadata = {
            'collection_date': datetime.now().isoformat(),
            'total_cves': len(cves),
            'severity_breakdown': self._get_severity_breakdown(cves),
            'cwe_breakdown': self._get_cwe_breakdown(cves),
            'cleaning_applied': False
        }

        meta_file = self.output_dir / 'cve_metadata.json'
        with open(meta_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def _get_severity_breakdown(self, cves):
        """Count CVEs by severity"""
        from collections import Counter
        severities = [cve['severity'] for cve in cves]
        return dict(Counter(severities))
    
    def _get_cwe_breakdown(self, cves):
        """Count top CWE types"""
        from collections import Counter
        all_cwes = []
        for cve in cves:
            all_cwes.extend(cve.get('cwe_ids', []))
        return dict(Counter(all_cwes).most_common(10))


def main():
    """Main execution"""

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/cve_collection.log'),
            logging.StreamHandler()
        ],
        force=True
    )

    # Keywords relevant to code security
    keywords = [
        'SQL injection',
        'cross-site scripting',
        'XSS',
        'buffer overflow',
        'authentication bypass',
        'code injection',
        'command injection',
        'path traversal',
        'insecure deserialization',
        'XML external entity',
        'security misconfiguration',
        'broken access control',
        'cryptographic failure',
        'server-side request forgery',
        'CSRF'
    ]
    
    collector = CVECollector()

    logging.info("="*60)
    logging.info("Starting CVE Collection (v2 - data/raw/v2/cves/)")
    logging.info("="*60)
    
    cves = collector.collect_by_keywords(keywords, results_per_keyword=50)
    
    logging.info("="*60)
    logging.info("CVE Collection Complete!")
    logging.info(f"Total CVEs collected: {len(cves)}")
    logging.info("="*60)


if __name__ == "__main__":
    main()
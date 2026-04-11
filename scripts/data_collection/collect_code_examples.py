"""
Collect real vulnerable code examples from public datasets
Sources: Defects4J-style datasets, vulnerability databases
"""

import re
import requests
import json
from pathlib import Path
import logging
from datetime import datetime
#import zipfile
#import io


def clean_java_code(code: str) -> str:
    """
    Remove license headers and package declarations from Java code.
    Called during collection, before saving to disk.
    """
    # Remove /** ... */ block comments (license headers)
    code = re.sub(r'/\*\*.*?\*/', '', code, flags=re.DOTALL)

    # Remove /* ... */ block comments (alternate license style)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)

    # Remove package declarations
    code = re.sub(r'^\s*package\s+[\w.]+\s*;\s*\n?', '', code, flags=re.MULTILINE)

    return code.strip()


class CodeExampleCollector:
    """
    Collect vulnerable code examples from public datasets
    """
    
    def __init__(self, output_dir='data/raw/v2/owasp_benchmark'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def collect_from_sources(self):
        """Collect from multiple sources"""
        
        all_examples = []
        
        # Source 1: OWASP Benchmark (has test cases with known results)
        logging.info("Collecting OWASP Benchmark examples...")
        benchmark_examples = self._collect_owasp_benchmark()
        all_examples.extend(benchmark_examples)
        
        # Source 2: Juliet Test Suite examples (NIST)
        logging.info("Note: Juliet Test Suite is large (~1.5GB)")
        logging.info("Visit: https://samate.nist.gov/SARD/test-suites/112 to download manually if needed")
        
        # Save collected examples
        self._save_examples(all_examples)
        
        return all_examples
    
    def _collect_owasp_benchmark(self):
        """
        Collect examples from OWASP Benchmark
        This is a free, open test suite for security tools
        """
        
        # OWASP Benchmark is on GitHub
        api_url = "https://api.github.com/repos/OWASP-Benchmark/BenchmarkJava/contents/src/main/java/org/owasp/benchmark/testcode"
        
        try:
            response = requests.get(api_url)
            response.raise_for_status()
            
            files = response.json()
            
            examples = []
            
            # Get first 50 example files
            for file_info in files[:50]:
                if file_info['name'].endswith('.java'):
                    
                    # Fetch file content
                    file_response = requests.get(file_info['download_url'])
                    
                    if file_response.status_code == 200:
                        raw_code = file_response.text

                        # Clean license headers and package declarations during collection
                        cleaned_code = clean_java_code(raw_code)
                        logging.info(f"  Collected and cleaned: {file_info['name']}")

                        examples.append({
                            'filename': file_info['name'],
                            'language': 'Java',
                            'code': cleaned_code,
                            'source': 'OWASP Benchmark',
                            'url': file_info['html_url']
                        })
            
            return examples
            
        except Exception as e:
            logging.error(f"Error collecting OWASP Benchmark: {e}")
            return []
    
    def _save_examples(self, examples):
        """Save code examples"""
        filename = self.output_dir / 'owasp_benchmark.json'

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(examples, f, indent=2, ensure_ascii=False)

        logging.info(f"Saved {len(examples)} code examples to {filename}")

        from collections import Counter
        languages = [ex.get('language', 'Unknown') for ex in examples]
        sources = [ex.get('source', 'Unknown') for ex in examples]
        metadata = {
            'collection_date': datetime.now().isoformat(),
            'total_examples': len(examples),
            'language_breakdown': dict(Counter(languages)),
            'source_breakdown': dict(Counter(sources)),
            'cleaning_applied': {
                'license_headers_removed': True,
                'package_declarations_removed': True
            }
        }

        meta_file = self.output_dir / 'owasp_benchmark_metadata.json'
        with open(meta_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        logging.info(f"Saved metadata to {meta_file}")


def main():
    """Main execution"""

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/code_examples_collection.log'),
            logging.StreamHandler()
        ],
        force=True
    )

    collector = CodeExampleCollector()
    
    logging.info("="*60)
    logging.info("Starting Code Examples Collection (v2 - data/raw/v2/code_examples/)")
    logging.info("="*60)
    
    examples = collector.collect_from_sources()
    
    logging.info("="*60)
    logging.info(f"Collection complete! Total examples: {len(examples)}")
    logging.info("="*60)


if __name__ == "__main__":
    main()
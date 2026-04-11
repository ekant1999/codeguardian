"""
Collect security issues from GitHub - SIMPLIFIED VERSION
Strategy: Just get recent closed issues and filter by keywords
"""

import os
import re
import json
import time
from pathlib import Path
from github import Github, Auth
from dotenv import load_dotenv
import logging
from datetime import datetime

load_dotenv()


def extract_code_snippets(description: str) -> list:
    """
    Extract fenced code blocks from a markdown issue description.
    Called during collection, before saving to disk.
    """
    code_blocks = re.findall(r'```(\w+)?\n(.*?)```', description, re.DOTALL)
    snippets = []
    for lang, code in code_blocks:
        code = code.strip()
        if code:
            snippets.append({
                'code': code,
                'language': lang.lower() if lang else 'unknown'
            })
    return snippets


def is_spam_issue(title: str, description: str) -> bool:
    """
    Detect automated vulnerability scanner spam.
    Called during collection to flag low-quality issues.
    """
    title_l = title.lower()
    desc_l = description.lower()
    return any([
        ('we found' in title_l and 'vulnerabilit' in title_l),
        '| cve |' in desc_l,
        ('routine' in desc_l and 'scan' in desc_l),
    ])


class SimpleGitHubCollector:
    """
    Simple, direct approach: Get recent issues and filter by keywords
    """
    
    def __init__(self, output_dir='data/raw/v2/github_issues'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        github_token = os.getenv('GITHUB_TOKEN')
        if not github_token:
            raise ValueError("GITHUB_TOKEN not found in .env file")
        
        auth = Auth.Token(github_token)
        self.github = Github(auth=auth)
        
        # Security keywords to search for
        self.security_keywords = [
            'security', 'vulnerability', 'cve', 'exploit',
            'injection', 'xss', 'csrf', 'sql', 'authentication',
            'bypass', 'malicious', 'attack', 'unsafe', 'sanitize'
        ]
    
    def collect_from_repositories(self, repo_list, max_per_repo=20):
        """Collect security-related issues"""
        
        all_issues = []
        
        for repo_name in repo_list:
            logging.info(f"Collecting from {repo_name}...")
            
            try:
                repo_issues = self._collect_from_repo(repo_name, max_per_repo)
                
                if repo_issues:
                    all_issues.extend(repo_issues)
                    logging.info(f"  ✓ Found {len(repo_issues)} security issues")
                else:
                    logging.warning("  ⚠ No security issues found")
                
                time.sleep(2)
                
            except Exception as e:
                logging.error(f"  ✗ Error: {e}")
                continue
        
        if all_issues:
            self._save_issues(all_issues)
        else:
            logging.warning("⚠️ No issues collected from any repository!")
        
        return all_issues
    
    def _collect_from_repo(self, repo_name, max_issues):
        """Collect from a single repository"""
        
        try:
            repo = self.github.get_repo(repo_name)
        except Exception as e:
            logging.error(f"Could not access repository: {e}")
            return []
        
        logging.info("  Fetching recent closed issues...")
        
        try:
            # Get recent closed issues (last 100)
            issues = repo.get_issues(
                state='closed',
                sort='updated',
                direction='desc'
            )
            
            collected = []
            checked = 0
            
            for issue in issues:
                # Stop if we have enough
                if len(collected) >= max_issues:
                    break
                
                # Don't check more than 100 issues per repo
                if checked >= 100:
                    break
                
                checked += 1
                
                # Skip pull requests
                if issue.pull_request:
                    continue
                
                # Must have a body
                if not issue.body or len(issue.body) < 50:
                    continue
                
                # Check if it's security-related
                title_lower = issue.title.lower()
                body_lower = issue.body.lower()
                
                is_security = any(
                    keyword in title_lower or keyword in body_lower
                    for keyword in self.security_keywords
                )
                
                if is_security:
                    issue_data = self._extract_issue_data(issue, repo)
                    if issue_data:
                        collected.append(issue_data)
                        logging.info(f"    #{issue.number}: {issue.title[:60]}...")
            
            logging.info(f"  Checked {checked} issues, found {len(collected)} security-related")
            return collected
            
        except Exception as e:
            logging.error(f"Error collecting issues: {e}")
            return []
    
    def _extract_issue_data(self, issue, repo):
        """Extract relevant data from issue, with code extraction and spam detection."""

        try:
            description = issue.body[:3000]
            title = issue.title

            # Extract code snippets during collection
            snippets = extract_code_snippets(description)
            spam = is_spam_issue(title, description)

            if spam:
                logging.info(f"    ⚠ Flagged as spam: #{issue.number}: {title[:60]}")

            if snippets:
                logging.info(f"    Extracted {len(snippets)} code snippet(s) from #{issue.number}")

            return {
                'repository': repo.full_name,
                'issue_number': issue.number,
                'title': title,
                'description': description,
                'labels': [label.name for label in issue.labels],
                'state': issue.state,
                'created_at': issue.created_at.isoformat() if issue.created_at else None,
                'closed_at': issue.closed_at.isoformat() if issue.closed_at else None,
                'url': issue.html_url,
                'language': repo.language if repo.language else 'Unknown',
                'author': issue.user.login if issue.user else 'Unknown',
                'comments_count': issue.comments,
                'code_snippets': snippets,
                'has_code': len(snippets) > 0,
                'is_spam': spam
            }
        except Exception as e:
            logging.debug(f"Error extracting issue: {e}")
            return None
    
    def _save_issues(self, issues):
        """Save to JSON file"""
        filename = self.output_dir / 'issues.json'

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(issues, f, indent=2, ensure_ascii=False)

        logging.info(f"\n✓ Saved {len(issues)} issues to {filename}")

        spam_count = sum(1 for i in issues if i.get('is_spam'))
        with_code_count = sum(1 for i in issues if i.get('has_code'))

        metadata = {
            'collection_date': datetime.now().isoformat(),
            'total_issues': len(issues),
            'repositories': list(set(i['repository'] for i in issues)),
            'language_breakdown': self._get_language_breakdown(issues),
            'cleaning_applied': {
                'code_extracted': True,
                'spam_filtered': spam_count,
                'issues_with_code': with_code_count
            }
        }

        meta_file = self.output_dir / 'github_issues_metadata.json'
        with open(meta_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        logging.info("\n" + "="*60)
        logging.info("COLLECTION SUMMARY")
        logging.info("="*60)
        logging.info(f"Total issues: {len(issues)}")
        logging.info(f"Repositories: {len(metadata['repositories'])}")
        logging.info(f"Languages: {metadata['language_breakdown']}")
        logging.info(f"Issues with code snippets: {with_code_count}")
        logging.info(f"Spam issues flagged: {spam_count}")
        logging.info("="*60)
    
    def _get_language_breakdown(self, issues):
        """Count by language"""
        from collections import Counter
        languages = [i['language'] for i in issues]
        return dict(Counter(languages))


def main():
    """Main execution"""

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/github_collection.log'),
            logging.StreamHandler()
        ],
        force=True
    )

    # Repositories with known security issues
    repositories = [
        # Based on diagnostic - these have security issues!
        'pallets/flask',
        'OWASP/CheatSheetSeries',
        'django/django',
        
        # Other popular repos
        'expressjs/express',
        'axios/axios',
        'lodash/lodash',
        'nodejs/node',
        'psf/requests',
        'encode/django-rest-framework',
        
        # Security tools (lots of examples)
        'sqlmapproject/sqlmap',
        'zaproxy/zaproxy',
    ]
    
    collector = SimpleGitHubCollector()
    
    logging.info("="*60)
    logging.info("GitHub Security Issues Collection (v2 - data/raw/v2/github_issues/)")
    logging.info("="*60)
    
    issues = collector.collect_from_repositories(repositories, max_per_repo=15)
    
    if len(issues) == 0:
        logging.error("\n❌ No issues collected!")
        logging.error("This is unusual. Please check:")
        logging.error("  1. GitHub token has 'public_repo' scope")
        logging.error("  2. Internet connection is working")
        logging.error("  3. GitHub API is accessible")
    else:
        logging.info(f"\n✅ SUCCESS! Collected {len(issues)} total issues")


if __name__ == "__main__":
    main()
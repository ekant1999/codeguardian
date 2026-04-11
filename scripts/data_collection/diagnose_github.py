"""
Diagnose why we're getting 0 issues
"""

import os
from github import Github, Auth
from dotenv import load_dotenv

load_dotenv()

def diagnose_repository(repo_name):
    """Check what's available in a repository"""
    
    github_token = os.getenv('GITHUB_TOKEN')
    auth = Auth.Token(github_token)
    github = Github(auth=auth)
    
    print(f"\n{'='*60}")
    print(f"Diagnosing: {repo_name}")
    print('='*60)
    
    try:
        repo = github.get_repo(repo_name)
        
        # Check labels
        print("\n1. Available Labels:")
        labels = list(repo.get_labels())
        label_names = [label.name for label in labels[:20]]
        print(f"   Found {len(labels)} labels total")
        print(f"   First 20: {label_names}")
        
        # Check for security-related labels
        security_labels = [l for l in label_names if any(
            keyword in l.lower() for keyword in 
            ['security', 'vulnerability', 'cve', 'bug', 'critical']
        )]
        print(f"   Security-related: {security_labels}")
        
        # Check total issues
        print("\n2. Issue Statistics:")
        all_issues = repo.get_issues(state='all')
        print(f"   Total issues (open + closed): {all_issues.totalCount}")
        
        closed_issues = repo.get_issues(state='closed')
        print(f"   Closed issues: {closed_issues.totalCount}")
        
        open_issues = repo.get_issues(state='open')
        print(f"   Open issues: {open_issues.totalCount}")
        
        # Sample a few closed issues
        print("\n3. Sample of Closed Issues:")
        for i, issue in enumerate(list(closed_issues)[:5]):
            if issue.pull_request:
                continue
            print(f"\n   Issue #{issue.number}:")
            print(f"   Title: {issue.title[:60]}...")
            print(f"   Labels: {[l.name for l in issue.labels]}")
            print(f"   Body length: {len(issue.body) if issue.body else 0} chars")
            
    except Exception as e:
        print(f"Error: {e}")

# Test a few repositories
repos_to_test = [
    'django/django',
    'pallets/flask',
    'OWASP/CheatSheetSeries'
]

for repo in repos_to_test:
    diagnose_repository(repo)
    print("\n" + "="*60 + "\n")
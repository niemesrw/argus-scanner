#!/usr/bin/env python3
"""
Update README badges with latest CI/CD status and coverage information.
"""

import json
import re
import sys
from pathlib import Path


def update_readme_badges(readme_path: Path, coverage_percent: float = None):
    """Update badges in README file."""
    
    with open(readme_path, 'r') as f:
        content = f.read()
    
    # Badge URLs
    repo = "niemesrw/argus-scanner"  # Update with actual repo
    
    badges = {
        'ci': f'[![CI Status](https://github.com/{repo}/workflows/CI%20-%20Enhanced%20Test%20and%20Build/badge.svg)](https://github.com/{repo}/actions/workflows/ci-enhanced.yml)',
        'coverage': f'[![Coverage](https://codecov.io/gh/{repo}/branch/main/graph/badge.svg)](https://codecov.io/gh/{repo})',
        'docker': f'[![Docker](https://img.shields.io/docker/v/{repo}?sort=semver)](https://ghcr.io/{repo})',
        'license': f'[![License](https://img.shields.io/github/license/{repo})](LICENSE)',
        'python': '[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)',
        'security': f'[![Security](https://github.com/{repo}/workflows/Security%20Scan/badge.svg)](https://github.com/{repo}/security)',
        'code_quality': '[![Code Quality](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)',
    }
    
    # Custom coverage badge if percentage provided
    if coverage_percent:
        color = 'red' if coverage_percent < 50 else 'yellow' if coverage_percent < 80 else 'green'
        badges['coverage'] = f'[![Coverage](https://img.shields.io/badge/coverage-{coverage_percent:.1f}%25-{color})](https://codecov.io/gh/{repo})'
    
    # Create badge section
    badge_section = """## 🛡️ Status

<div align="center">

{ci}
{coverage}
{security}
{code_quality}

{docker}
{python}
{license}

</div>
""".format(**badges)
    
    # Replace existing badge section or add after title
    badge_pattern = r'## 🛡️ Status.*?(?=##|\Z)'
    if re.search(badge_pattern, content, re.DOTALL):
        content = re.sub(badge_pattern, badge_section.strip() + '\n\n', content, flags=re.DOTALL)
    else:
        # Insert after the main title and description
        lines = content.split('\n')
        insert_index = 0
        
        # Find the first non-title, non-empty line after initial content
        for i, line in enumerate(lines):
            if i > 0 and line.strip() and not line.startswith('#'):
                insert_index = i + 1
                break
        
        lines.insert(insert_index, '\n' + badge_section)
        content = '\n'.join(lines)
    
    with open(readme_path, 'w') as f:
        f.write(content)
    
    print(f"✅ Updated badges in {readme_path}")


def get_coverage_from_json(coverage_file: Path) -> float:
    """Extract coverage percentage from coverage.json file."""
    try:
        with open(coverage_file, 'r') as f:
            data = json.load(f)
            return data.get('totals', {}).get('percent_covered', 0)
    except Exception as e:
        print(f"Warning: Could not read coverage data: {e}")
        return None


if __name__ == '__main__':
    # Find repository root
    repo_root = Path(__file__).parent.parent.parent
    readme_path = repo_root / 'README.md'
    coverage_file = repo_root / 'coverage.json'
    
    # Get coverage if available
    coverage = None
    if len(sys.argv) > 1:
        coverage = float(sys.argv[1])
    elif coverage_file.exists():
        coverage = get_coverage_from_json(coverage_file)
    
    # Update README
    update_readme_badges(readme_path, coverage)
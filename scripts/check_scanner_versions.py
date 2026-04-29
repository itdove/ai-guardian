#!/usr/bin/env python3
"""
Check if pinned scanner versions exist and are downloadable.

This script verifies that all pinned scanner versions in pyproject.toml
still exist on GitHub releases and are downloadable. It prevents CI failures
when versions are yanked or repositories are archived.

Exit codes:
    0: All pinned scanner versions exist and are downloadable
    1: One or more pinned scanner versions do not exist
"""

import sys
import requests
import tomllib
from pathlib import Path


def check_scanner_exists(repo: str, version: str, scanner_name: str, platform: str = "linux_x64") -> dict:
    """
    Check if a scanner version exists on GitHub releases.

    Args:
        repo: GitHub repo (e.g., "gitleaks/gitleaks")
        version: Version to check (e.g., "8.30.1")
        scanner_name: Name of scanner (gitleaks, betterleaks, leaktk)
        platform: Platform string (e.g., "linux_x64")

    Returns:
        dict with exists, download_url, error
    """
    # Try release API first
    api_url = f"https://api.github.com/repos/{repo}/releases/tags/v{version}"

    try:
        response = requests.get(api_url, timeout=10)

        if response.status_code == 404:
            return {
                'exists': False,
                'error': f'Release v{version} not found in {repo}'
            }

        response.raise_for_status()
        release_data = response.json()

        # Build expected asset name based on scanner naming conventions
        # gitleaks/betterleaks: scanner_version_platform.tar.gz (e.g., gitleaks_8.30.1_linux_x64.tar.gz)
        # leaktk: scanner-version-system-arch.tar.xz with x86_64 instead of x64 (e.g., leaktk-0.2.10-linux-x86_64.tar.xz)
        if scanner_name == "leaktk":
            # leaktk uses hyphens, separate system and arch, and x86_64 instead of x64
            system, arch = platform.split('_', 1)
            leaktk_arch = "x86_64" if arch == "x64" else arch
            asset_name = f"{scanner_name}-{version}-{system}-{leaktk_arch}.tar.xz"
        else:
            # gitleaks and betterleaks use underscores
            asset_name = f"{scanner_name}_{version}_{platform}.tar.gz"

        assets = release_data.get('assets', [])
        matching_asset = next(
            (a for a in assets if a['name'] == asset_name),
            None
        )

        if not matching_asset:
            return {
                'exists': False,
                'error': f'Asset {asset_name} not found in release v{version}'
            }

        # Asset exists in release - no need for HEAD request since GitHub API is authoritative
        return {
            'exists': True,
            'download_url': matching_asset['browser_download_url'],
            'size_mb': round(matching_asset['size'] / 1024 / 1024, 2)
        }

    except requests.RequestException as e:
        return {
            'exists': False,
            'error': f'Network error checking {repo} v{version}: {e}'
        }


def main():
    # Load pyproject.toml
    pyproject_path = Path('pyproject.toml')
    if not pyproject_path.exists():
        print("❌ pyproject.toml not found")
        sys.exit(1)

    with open(pyproject_path, 'rb') as f:
        config = tomllib.load(f)

    scanners_config = config.get('tool', {}).get('ai-guardian', {}).get('scanners', {})
    repos_config = scanners_config.get('repos', {})

    if not scanners_config:
        print("❌ No scanner versions found in pyproject.toml")
        sys.exit(1)

    print("Checking pinned scanner versions...\n")

    all_exist = True

    for scanner, version in scanners_config.items():
        if scanner == 'repos':
            continue  # Skip repos section

        repo = repos_config.get(scanner)
        if not repo:
            print(f"⚠️  {scanner}: No repository configured, skipping")
            continue

        print(f"Checking {scanner} v{version} ({repo})...")

        result = check_scanner_exists(repo, version, scanner)

        if result['exists']:
            print(f"  ✅ EXISTS - {result['download_url']}")
            print(f"     Size: {result['size_mb']} MB")
        else:
            print(f"  ❌ NOT FOUND - {result['error']}")
            all_exist = False

        print()

    if not all_exist:
        print("\n🚨 CRITICAL: One or more pinned scanner versions do not exist!")
        print("Action required: Update pyproject.toml with valid versions")
        sys.exit(1)

    print("✅ All pinned scanner versions exist and are downloadable")
    sys.exit(0)


if __name__ == '__main__':
    main()

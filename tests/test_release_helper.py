#!/usr/bin/env python3
"""
Tests for release helper module.

This test suite verifies the release helper functionality for:
- Version reading and updating
- CHANGELOG.md management
- Version calculation
- Prerequisites validation
"""

import sys
import tempfile
from pathlib import Path
from datetime import datetime

# Add the skills directory to the path to import release_helper
sys.path.insert(0, str(Path.home() / ".claude" / "skills" / "release"))

from release_helper import ReleaseHelper


def create_test_repo(tmp_path):
    """Create a minimal test repository structure."""
    # Create directory structure
    src_dir = tmp_path / "src" / "ai_guardian"
    src_dir.mkdir(parents=True)

    # Create pyproject.toml
    pyproject_content = """[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "ai-guardian"
version = "1.1.0-dev"
description = "Test"
"""
    (tmp_path / "pyproject.toml").write_text(pyproject_content)

    # Create __init__.py
    init_content = '''"""AI Guardian package."""

__version__ = "1.1.0-dev"
'''
    (src_dir / "__init__.py").write_text(init_content)

    # Create CHANGELOG.md
    changelog_content = """# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- New feature X
- New feature Y

### Fixed
- Bug fix Z

## [1.0.0] - 2026-01-01

### Added
- Initial release

[Unreleased]: https://github.com/itdove/ai-guardian/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.0
"""
    (tmp_path / "CHANGELOG.md").write_text(changelog_content)

    return tmp_path


def test_get_current_version():
    """Test getting current version from both files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        create_test_repo(tmp_path)

        helper = ReleaseHelper(tmp_path)
        pyproject_ver, init_ver, match = helper.get_current_version()

        assert pyproject_ver == "1.1.0-dev"
        assert init_ver == "1.1.0-dev"
        assert match is True


def test_version_mismatch_detection():
    """Test detection of version mismatch between files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        create_test_repo(tmp_path)

        # Manually update only one file to create mismatch
        init_path = tmp_path / "src" / "ai_guardian" / "__init__.py"
        content = init_path.read_text()
        content = content.replace('__version__ = "1.1.0-dev"', '__version__ = "1.2.0-dev"')
        init_path.write_text(content)

        helper = ReleaseHelper(tmp_path)
        pyproject_ver, init_ver, match = helper.get_current_version()

        assert pyproject_ver == "1.1.0-dev"
        assert init_ver == "1.2.0-dev"
        assert match is False


def test_update_version():
    """Test updating version in both files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        create_test_repo(tmp_path)

        helper = ReleaseHelper(tmp_path)
        success = helper.update_version("1.2.0")

        assert success is True

        # Verify both files updated
        pyproject_ver, init_ver, match = helper.get_current_version()
        assert pyproject_ver == "1.2.0"
        assert init_ver == "1.2.0"
        assert match is True


def test_calculate_next_version_minor():
    """Test calculating next minor version."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        helper = ReleaseHelper(tmp_path)

        next_ver = helper.calculate_next_version("1.1.0-dev", "minor")
        assert next_ver == "1.2.0"


def test_calculate_next_version_major():
    """Test calculating next major version."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        helper = ReleaseHelper(tmp_path)

        next_ver = helper.calculate_next_version("1.1.0-dev", "major")
        assert next_ver == "2.0.0"


def test_calculate_next_version_patch():
    """Test calculating next patch version."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        helper = ReleaseHelper(tmp_path)

        next_ver = helper.calculate_next_version("1.1.0", "patch")
        assert next_ver == "1.1.1"


def test_calculate_next_version_test():
    """Test calculating test version."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        helper = ReleaseHelper(tmp_path)

        next_ver = helper.calculate_next_version("1.2.0-dev", "test")
        assert next_ver == "1.2.0-test1"


def test_update_changelog():
    """Test updating CHANGELOG.md."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        create_test_repo(tmp_path)

        helper = ReleaseHelper(tmp_path)
        success = helper.update_changelog("1.1.0", "2026-04-08")

        assert success is True

        # Verify CHANGELOG updated
        changelog = (tmp_path / "CHANGELOG.md").read_text()
        assert "## [1.1.0] - 2026-04-08" in changelog
        assert "### Added" in changelog
        assert "- New feature X" in changelog
        assert "[1.1.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.1.0" in changelog
        assert "[Unreleased]: https://github.com/itdove/ai-guardian/compare/v1.1.0...HEAD" in changelog


def test_update_changelog_empty_unreleased():
    """Test updating CHANGELOG with empty Unreleased section fails."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        create_test_repo(tmp_path)

        # Create CHANGELOG with empty Unreleased
        changelog_content = """# Changelog

## [Unreleased]

## [1.0.0] - 2026-01-01

### Added
- Initial release

[Unreleased]: https://github.com/itdove/ai-guardian/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.0
"""
        (tmp_path / "CHANGELOG.md").write_text(changelog_content)

        helper = ReleaseHelper(tmp_path)
        success = helper.update_changelog("1.1.0", "2026-04-08")

        assert success is False


def test_validate_prerequisites_success():
    """Test successful prerequisites validation."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        create_test_repo(tmp_path)

        helper = ReleaseHelper(tmp_path)
        valid, errors = helper.validate_prerequisites("regular")

        assert valid is True
        assert len(errors) == 0


def test_validate_prerequisites_version_mismatch():
    """Test prerequisites validation detects version mismatch."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        create_test_repo(tmp_path)

        # Create version mismatch
        init_path = tmp_path / "src" / "ai_guardian" / "__init__.py"
        content = init_path.read_text()
        content = content.replace('__version__ = "1.1.0-dev"', '__version__ = "1.2.0-dev"')
        init_path.write_text(content)

        helper = ReleaseHelper(tmp_path)
        valid, errors = helper.validate_prerequisites("regular")

        assert valid is False
        assert len(errors) > 0
        assert any("mismatch" in err.lower() for err in errors)


def test_validate_prerequisites_missing_unreleased():
    """Test prerequisites validation detects missing Unreleased section."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        create_test_repo(tmp_path)

        # Remove Unreleased section
        changelog_content = """# Changelog

## [1.0.0] - 2026-01-01

### Added
- Initial release
"""
        (tmp_path / "CHANGELOG.md").write_text(changelog_content)

        helper = ReleaseHelper(tmp_path)
        valid, errors = helper.validate_prerequisites("regular")

        assert valid is False
        assert len(errors) > 0
        assert any("unreleased" in err.lower() for err in errors)


def test_validate_prerequisites_empty_unreleased():
    """Test prerequisites validation detects empty Unreleased section."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        create_test_repo(tmp_path)

        # Empty Unreleased section
        changelog_content = """# Changelog

## [Unreleased]

## [1.0.0] - 2026-01-01

### Added
- Initial release
"""
        (tmp_path / "CHANGELOG.md").write_text(changelog_content)

        helper = ReleaseHelper(tmp_path)
        valid, errors = helper.validate_prerequisites("regular")

        assert valid is False
        assert len(errors) > 0
        assert any("empty" in err.lower() for err in errors)


def run_tests():
    """Run all tests and report results."""
    tests = [
        test_get_current_version,
        test_version_mismatch_detection,
        test_update_version,
        test_calculate_next_version_minor,
        test_calculate_next_version_major,
        test_calculate_next_version_patch,
        test_calculate_next_version_test,
        test_update_changelog,
        test_update_changelog_empty_unreleased,
        test_validate_prerequisites_success,
        test_validate_prerequisites_version_mismatch,
        test_validate_prerequisites_missing_unreleased,
        test_validate_prerequisites_empty_unreleased,
    ]

    passed = 0
    failed = 0
    errors = []

    for test in tests:
        try:
            test()
            passed += 1
            print(f"✓ {test.__name__}")
        except AssertionError as e:
            failed += 1
            errors.append((test.__name__, str(e)))
            print(f"✗ {test.__name__}: {e}")
        except Exception as e:
            failed += 1
            errors.append((test.__name__, str(e)))
            print(f"✗ {test.__name__}: {e}")

    print(f"\n{'='*70}")
    print(f"Results: {passed} passed, {failed} failed")
    print(f"{'='*70}")

    if errors:
        print("\nFailed tests:")
        for name, error in errors:
            print(f"  {name}: {error}")

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)

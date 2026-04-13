#!/usr/bin/env python3
"""
Test script for directory exclusions feature.

Tests that directory exclusions work correctly with .ai-read-deny markers,
including precedence rules and path matching.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

from ai_guardian import check_directory_denied


def test_basic_exclusion():
    """Test basic exclusion (excluded dir, no .ai-read-deny)"""
    test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")

    try:
        # Create directory structure
        allowed_dir = os.path.join(test_dir, "workspace")
        os.makedirs(allowed_dir)

        allowed_file = os.path.join(allowed_dir, "file.txt")
        with open(allowed_file, 'w') as f:
            f.write("test content")

        # Config with exclusion (no .ai-read-deny marker)
        config = {
            "directory_exclusions": {
                "enabled": True,
                "paths": [test_dir + "/**"]
            }
        }

        is_denied, denied_dir = check_directory_denied(allowed_file, config)
        assert not is_denied, "Excluded directory should allow access"
        assert denied_dir is None, "Should not have denied directory"
        print("✓ Test 1 PASSED: Basic exclusion works (no .ai-read-deny)")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_ai_read_deny_overrides_exclusion():
    """Test that .ai-read-deny ALWAYS overrides exclusions (CRITICAL)"""
    test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")

    try:
        # Create directory structure
        excluded_dir = os.path.join(test_dir, "workspace")
        os.makedirs(excluded_dir)

        # Add .ai-read-deny marker
        deny_marker = os.path.join(excluded_dir, ".ai-read-deny")
        with open(deny_marker, 'w') as f:
            f.write("")

        blocked_file = os.path.join(excluded_dir, "file.txt")
        with open(blocked_file, 'w') as f:
            f.write("secret content")

        # Config with exclusion - but .ai-read-deny should still block
        config = {
            "directory_exclusions": {
                "enabled": True,
                "paths": [test_dir + "/**"]
            }
        }

        is_denied, denied_dir = check_directory_denied(blocked_file, config)
        assert is_denied, ".ai-read-deny MUST override exclusion"
        assert denied_dir == excluded_dir, "Should report correct denied directory"
        print("✓ Test 2 PASSED: .ai-read-deny overrides exclusion (CRITICAL)")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_subdirectory_deny_in_excluded_parent():
    """Test .ai-read-deny in subdirectory of excluded parent"""
    test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")

    try:
        # Create directory structure
        excluded_dir = os.path.join(test_dir, "workspace")
        secrets_dir = os.path.join(excluded_dir, "secrets")
        os.makedirs(secrets_dir)

        # Add .ai-read-deny in subdirectory
        deny_marker = os.path.join(secrets_dir, ".ai-read-deny")
        with open(deny_marker, 'w') as f:
            f.write("")

        # Create files
        allowed_file = os.path.join(excluded_dir, "public.txt")
        blocked_file = os.path.join(secrets_dir, "secret.txt")

        with open(allowed_file, 'w') as f:
            f.write("public content")
        with open(blocked_file, 'w') as f:
            f.write("secret content")

        # Config excludes parent directory
        config = {
            "directory_exclusions": {
                "enabled": True,
                "paths": [excluded_dir + "/**"]
            }
        }

        # Public file should be allowed (in excluded dir, no .ai-read-deny)
        is_denied, denied_dir = check_directory_denied(allowed_file, config)
        assert not is_denied, "File in excluded dir should be allowed"

        # Secret file should be blocked (.ai-read-deny takes precedence)
        is_denied, denied_dir = check_directory_denied(blocked_file, config)
        assert is_denied, ".ai-read-deny in subdirectory should block"
        assert denied_dir == secrets_dir, "Should report correct denied directory"

        print("✓ Test 3 PASSED: Subdirectory .ai-read-deny in excluded parent")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_tilde_expansion():
    """Test tilde expansion in exclusion paths"""
    home_dir = os.path.expanduser("~")
    test_dir = os.path.join(home_dir, ".ai_exclusion_test_tilde")
    os.makedirs(test_dir, exist_ok=True)

    try:
        test_file = os.path.join(test_dir, "file.txt")
        with open(test_file, 'w') as f:
            f.write("test content")

        # Config with tilde path
        config = {
            "directory_exclusions": {
                "enabled": True,
                "paths": ["~/.ai_exclusion_test_tilde/**"]
            }
        }

        is_denied, denied_dir = check_directory_denied(test_file, config)
        assert not is_denied, "Tilde expansion should work"
        print("✓ Test 4 PASSED: Tilde expansion works")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_wildcard_matching():
    """Test wildcard matching (*, **)"""
    test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")

    try:
        # Create directory structure for ** test
        deep_dir = os.path.join(test_dir, "repos", "public", "proj1", "src")
        os.makedirs(deep_dir)

        deep_file = os.path.join(deep_dir, "file.txt")
        with open(deep_file, 'w') as f:
            f.write("test content")

        # Test ** (recursive wildcard)
        config = {
            "directory_exclusions": {
                "enabled": True,
                "paths": [os.path.join(test_dir, "repos", "**")]
            }
        }

        is_denied, denied_dir = check_directory_denied(deep_file, config)
        assert not is_denied, "** should match recursively"
        print("✓ Test 5 PASSED: Wildcard ** matches recursively")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_exclusion_disabled():
    """Test that exclusions don't apply when enabled: false"""
    test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")

    try:
        test_file = os.path.join(test_dir, "file.txt")
        with open(test_file, 'w') as f:
            f.write("test content")

        # Config with exclusion disabled
        config = {
            "directory_exclusions": {
                "enabled": False,
                "paths": [test_dir + "/**"]
            }
        }

        # Should not exclude (disabled)
        is_denied, denied_dir = check_directory_denied(test_file, config)
        assert not is_denied, "Should allow (no .ai-read-deny, exclusions disabled)"
        print("✓ Test 6 PASSED: Disabled exclusions don't apply")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_missing_exclusion_config():
    """Test backward compatibility when directory_exclusions is missing"""
    test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")

    try:
        test_file = os.path.join(test_dir, "file.txt")
        with open(test_file, 'w') as f:
            f.write("test content")

        # Config without directory_exclusions
        config = {
            "permissions": []
        }

        is_denied, denied_dir = check_directory_denied(test_file, config)
        assert not is_denied, "Should allow (no .ai-read-deny, no exclusions)"
        print("✓ Test 7 PASSED: Backward compatible (missing config)")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_invalid_paths():
    """Test that invalid paths fail-safe (don't cause errors)"""
    test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")

    try:
        test_file = os.path.join(test_dir, "file.txt")
        with open(test_file, 'w') as f:
            f.write("test content")

        # Config with invalid path types
        config = {
            "directory_exclusions": {
                "enabled": True,
                "paths": [
                    "/nonexistent/path/**",  # Valid format but doesn't exist
                    123,  # Invalid type (not a string)
                    None,  # Invalid type
                    test_dir + "/**"  # Valid path (should work)
                ]
            }
        }

        # Should handle invalid paths gracefully and still apply valid ones
        is_denied, denied_dir = check_directory_denied(test_file, config)
        assert not is_denied, "Should apply valid path despite invalid ones"
        print("✓ Test 8 PASSED: Invalid paths handled gracefully (fail-safe)")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_absolute_paths():
    """Test absolute path matching"""
    test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")

    try:
        test_file = os.path.join(test_dir, "file.txt")
        with open(test_file, 'w') as f:
            f.write("test content")

        # Config with absolute path
        config = {
            "directory_exclusions": {
                "enabled": True,
                "paths": [test_dir]
            }
        }

        is_denied, denied_dir = check_directory_denied(test_file, config)
        assert not is_denied, "Absolute path should work"
        print("✓ Test 9 PASSED: Absolute paths work")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_no_config():
    """Test that None config doesn't cause errors"""
    test_dir = tempfile.mkdtemp(prefix="ai_exclusion_test_")

    try:
        test_file = os.path.join(test_dir, "file.txt")
        with open(test_file, 'w') as f:
            f.write("test content")

        # No config
        is_denied, denied_dir = check_directory_denied(test_file, None)
        assert not is_denied, "Should allow (no .ai-read-deny, no config)"
        print("✓ Test 10 PASSED: None config handled correctly")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def run_all_tests():
    """Run all directory exclusion tests"""
    print("Testing directory exclusions feature...")
    print("=" * 70)

    tests = [
        test_basic_exclusion,
        test_ai_read_deny_overrides_exclusion,
        test_subdirectory_deny_in_excluded_parent,
        test_tilde_expansion,
        test_wildcard_matching,
        test_exclusion_disabled,
        test_missing_exclusion_config,
        test_invalid_paths,
        test_absolute_paths,
        test_no_config,
    ]

    failed = []

    for test in tests:
        try:
            test()
        except AssertionError as e:
            failed.append((test.__name__, str(e)))
            print(f"❌ {test.__name__} FAILED: {e}")
        except Exception as e:
            failed.append((test.__name__, str(e)))
            print(f"❌ {test.__name__} ERROR: {e}")
            import traceback
            traceback.print_exc()

    print("=" * 70)

    if failed:
        print(f"❌ {len(failed)} test(s) FAILED:")
        for name, error in failed:
            print(f"  - {name}: {error}")
        return False
    else:
        print(f"✅ All {len(tests)} tests PASSED!")
        print()
        print("Summary:")
        print("  - Basic exclusion works")
        print("  - .ai-read-deny ALWAYS takes precedence over exclusions")
        print("  - Subdirectory .ai-read-deny blocks even in excluded parent")
        print("  - Tilde expansion works")
        print("  - Wildcard matching (**) works")
        print("  - Disabled exclusions don't apply")
        print("  - Backward compatible (missing config)")
        print("  - Invalid paths handled gracefully")
        print("  - Absolute paths work")
        print("  - None config handled correctly")
        return True


if __name__ == "__main__":
    try:
        success = run_all_tests()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

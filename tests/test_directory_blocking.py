#!/usr/bin/env python3
"""
Test script for directory blocking feature with .ai-read-deny marker
"""

import os
import sys
import tempfile
import shutil

from ai_guardian import check_directory_denied


def test_directory_blocking():
    """Test that .ai-read-deny marker blocks access to directory and subdirectories"""

    # Create temporary directory structure
    test_dir = tempfile.mkdtemp(prefix="ai_deny_test_")

    try:
        # Create directory structure:
        # test_dir/
        #   allowed_dir/
        #     allowed_file.txt
        #   denied_dir/
        #     .ai-read-deny
        #     blocked_file.txt
        #     subdir/
        #       deeply_blocked_file.txt

        allowed_dir = os.path.join(test_dir, "allowed_dir")
        denied_dir = os.path.join(test_dir, "denied_dir")
        denied_subdir = os.path.join(denied_dir, "subdir")

        os.makedirs(allowed_dir)
        os.makedirs(denied_subdir)

        # Create files
        allowed_file = os.path.join(allowed_dir, "allowed_file.txt")
        blocked_file = os.path.join(denied_dir, "blocked_file.txt")
        deeply_blocked_file = os.path.join(denied_subdir, "deeply_blocked_file.txt")

        with open(allowed_file, 'w') as f:
            f.write("This file should be accessible")

        with open(blocked_file, 'w') as f:
            f.write("This file should be blocked")

        with open(deeply_blocked_file, 'w') as f:
            f.write("This nested file should also be blocked")

        # Create .ai-read-deny marker in denied_dir
        deny_marker = os.path.join(denied_dir, ".ai-read-deny")
        with open(deny_marker, 'w') as f:
            f.write("")

        # Run tests
        print("Testing directory blocking feature...")
        print("=" * 70)

        # Use explicit config with block mode (not log mode)
        test_config = {
            "directory_rules": {
                "action": "block",
                "rules": []
            }
        }

        # Test 1: Allowed file should not be blocked
        is_denied, denied_path, _, _ = check_directory_denied(allowed_file, test_config)
        assert not is_denied, f"FAIL: Allowed file was blocked"
        assert denied_path is None, f"FAIL: Allowed file has denied path"
        print(f"✓ Test 1 PASSED: Allowed file is accessible")
        print(f"  File: {allowed_file}")
        print(f"  Blocked: {is_denied}")

        # Test 2: File in denied directory should be blocked
        is_denied, denied_path, _, _ = check_directory_denied(blocked_file, test_config)
        assert is_denied, f"FAIL: Denied file was not blocked"
        assert denied_path == denied_dir, f"FAIL: Wrong denied directory reported"
        print(f"✓ Test 2 PASSED: File in denied directory is blocked")
        print(f"  File: {blocked_file}")
        print(f"  Blocked: {is_denied}")
        print(f"  Denied dir: {denied_path}")

        # Test 3: File in subdirectory of denied directory should be blocked
        is_denied, denied_path, _, _ = check_directory_denied(deeply_blocked_file, test_config)
        assert is_denied, f"FAIL: Nested file in denied directory was not blocked"
        assert denied_path == denied_dir, f"FAIL: Wrong denied directory reported for nested file"
        print(f"✓ Test 3 PASSED: Nested file in denied directory is blocked")
        print(f"  File: {deeply_blocked_file}")
        print(f"  Blocked: {is_denied}")
        print(f"  Denied dir: {denied_path}")

        print("=" * 70)
        print("✅ All tests PASSED!")
        print()
        print("Summary:")
        print(f"  - Files in allowed directories: accessible ✓")
        print(f"  - Files in denied directories: blocked ✓")
        print(f"  - Files in subdirectories of denied directories: blocked ✓")

        return True

    finally:
        # Cleanup
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        success = test_directory_blocking()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

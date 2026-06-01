"""Tests for pattern validation functions."""

import pytest

from ai_guardian.patterns.validators import (
    env_not_file_path,
    get_validator,
    _is_file_path,
    _is_placeholder,
)


class TestEnvNotFilePath:
    """Tests for the env_not_file_path validator."""

    def test_unix_absolute_path_skipped(self):
        assert env_not_file_path("PKGMGR=/usr/bin/microdnf") is False

    def test_unix_deep_path_skipped(self):
        assert env_not_file_path("APP_DIR=/opt/app-root/src/config") is False

    def test_unix_local_path_skipped(self):
        assert env_not_file_path("PYTHON=/usr/local/bin/python3") is False

    def test_windows_forward_slash_path_skipped(self):
        assert env_not_file_path("APP_DIR=C:/Users/cesar/project") is False

    def test_windows_backslash_path_skipped(self):
        assert env_not_file_path("APP_DIR=C:\\Users\\cesar\\project") is False

    def test_relative_dot_path_skipped(self):
        assert env_not_file_path("OUT_DIR=./out/build/artifact") is False

    def test_relative_dotdot_path_skipped(self):
        assert env_not_file_path("CFG=../config/settings/app") is False

    def test_quoted_path_skipped(self):
        assert env_not_file_path('PKGMGR="/usr/bin/microdnf"') is False

    def test_single_quoted_path_skipped(self):
        assert env_not_file_path("PKGMGR='/usr/bin/microdnf'") is False

    def test_real_secret_detected(self):
        assert env_not_file_path(
            "AWS_SECRET_KEY=wJalrXUtnFEMIK7MDENGEXAMPLEKEY"
        ) is True

    def test_aws_key_with_slash_detected(self):
        assert env_not_file_path(
            "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ) is True

    def test_base64_token_detected(self):
        assert env_not_file_path(
            "TOKEN=dGhpcyBpcyBhIHRlc3QgdG9rZW4="
        ) is True

    def test_no_equals_sign_passes(self):
        assert env_not_file_path("NOEQUALSSIGN") is True

    def test_empty_value_passes(self):
        assert env_not_file_path("KEY=") is True

    def test_short_single_segment_path_passes(self):
        assert env_not_file_path("KEY=/verylongsinglesegment") is True

    def test_underscore_value_skipped(self):
        """Issue #912: Python identifier starting with _ should not be flagged."""
        assert env_not_file_path("CONFIG=_internal_function_name_here") is False

    def test_double_underscore_value_skipped(self):
        assert env_not_file_path("HANDLER=__private_method_name_x") is False

    def test_placeholder_your_skipped(self):
        """Issue #912: placeholder 'your-...' should not be flagged."""
        assert env_not_file_path('JIRA_API_TOKEN="your-personal-access-token"') is False

    def test_placeholder_example_skipped(self):
        assert env_not_file_path("API_KEY=example-token-value-here") is False

    def test_placeholder_replace_skipped(self):
        assert env_not_file_path("SECRET=replace-with-your-key") is False

    def test_placeholder_test_skipped(self):
        assert env_not_file_path("TOKEN=test-api-key-value12345") is False

    def test_placeholder_here_suffix_skipped(self):
        assert env_not_file_path("KEY=put-your-secret-here") is False

    def test_registry_lookup(self):
        validator = get_validator("env_not_file_path")
        assert validator is env_not_file_path


class TestIsPlaceholder:
    """Tests for the _is_placeholder helper."""

    def test_your_prefix(self):
        assert _is_placeholder("your-personal-access-token") is True

    def test_example_prefix(self):
        assert _is_placeholder("example-token-value") is True

    def test_here_suffix(self):
        assert _is_placeholder("put-your-secret-here") is True

    def test_changeme_prefix(self):
        assert _is_placeholder("changeme-this-value") is True

    def test_dummy_prefix(self):
        assert _is_placeholder("dummy_token_12345678") is True

    def test_real_key_not_placeholder(self):
        assert _is_placeholder("wJalrXUtnFEMIK7MDENGEXAMPLEKEY") is False

    def test_base64_not_placeholder(self):
        assert _is_placeholder("dGhpcyBpcyBhIHRlc3QgdG9rZW4=") is False

    def test_random_alphanumeric_not_placeholder(self):
        assert _is_placeholder("a1b2c3d4e5f6g7h8") is False


class TestIsFilePath:
    """Direct tests for _is_file_path helper."""

    def test_unix_absolute(self):
        assert _is_file_path("/usr/bin/microdnf") is True

    def test_unix_absolute_deep(self):
        assert _is_file_path("/opt/app-root/src") is True

    def test_single_segment_not_path(self):
        assert _is_file_path("/onlyonesegment") is False

    def test_windows_forward(self):
        assert _is_file_path("C:/Users/cesar/project") is True

    def test_windows_backslash(self):
        assert _is_file_path("C:\\Users\\cesar\\project") is True

    def test_relative_dot(self):
        assert _is_file_path("./out/build/artifact") is True

    def test_relative_dotdot(self):
        assert _is_file_path("../config/settings/app") is True

    def test_bare_value_not_path(self):
        assert _is_file_path("wJalrXUtnFEMIK7MDENG") is False

    def test_slash_in_secret_not_path(self):
        assert _is_file_path("wJalrXUtnFEMI/K7MDENG/bPxRfi") is False

    def test_path_with_dots_in_filename(self):
        assert _is_file_path("/usr/local/bin/python3.11") is True

    def test_path_with_hyphens(self):
        assert _is_file_path("/opt/app-root/src") is True

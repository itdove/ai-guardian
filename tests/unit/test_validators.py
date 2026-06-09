"""Tests for pattern validation functions."""

import pytest

from ai_guardian.patterns.validators import (
    connection_not_placeholder,
    env_not_file_path,
    get_validator,
    token_not_placeholder,
    _is_connection_placeholder,
    _is_container_image,
    _is_file_path,
    _is_placeholder,
    _is_token_placeholder,
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

    def test_container_image_localhost_skipped(self):
        """Issue #1019: container image references should not be flagged."""
        assert env_not_file_path("CARBONITE_IMAGE=localhost/carbonite-dev") is False

    def test_container_image_ghcr_skipped(self):
        assert env_not_file_path("IMAGE=ghcr.io/org/my-image") is False

    def test_container_image_registry_skipped(self):
        assert env_not_file_path("IMG=registry.example.com/project/image") is False

    def test_container_image_with_tag_skipped(self):
        assert env_not_file_path("IMG=quay.io/namespace/app:latest") is False

    def test_container_image_quoted_skipped(self):
        assert env_not_file_path('IMAGE="localhost/carbonite-dev"') is False

    def test_container_image_nested_path_skipped(self):
        assert env_not_file_path("IMG=registry.redhat.io/rhel9/python-312") is False

    def test_container_image_dot_local_skipped(self):
        assert env_not_file_path("IMG=myregistry.local/team/service") is False

    def test_registry_lookup(self):
        validator = get_validator("env_not_file_path")
        assert validator is env_not_file_path


class TestIsContainerImage:
    """Tests for _is_container_image helper (Issue #1019)."""

    def test_localhost_image(self):
        assert _is_container_image("localhost/carbonite-dev") is True

    def test_ghcr_io(self):
        assert _is_container_image("ghcr.io/org/image") is True

    def test_quay_io_with_tag(self):
        assert _is_container_image("quay.io/namespace/app:latest") is True

    def test_registry_com(self):
        assert _is_container_image("registry.example.com/project/image") is True

    def test_registry_dot_local(self):
        assert _is_container_image("myregistry.local/team/service") is True

    def test_docker_io(self):
        assert _is_container_image("docker.io/library/nginx") is True

    def test_gcr_io(self):
        assert _is_container_image("gcr.io/project/image:v1.2.3") is True

    def test_registry_dev(self):
        assert _is_container_image("registry.dev/my-org/my-app") is True

    def test_bare_value_not_image(self):
        assert _is_container_image("wJalrXUtnFEMIK7MDENG") is False

    def test_no_slash_not_image(self):
        assert _is_container_image("localhost") is False

    def test_random_host_no_tld_not_image(self):
        assert _is_container_image("myhost/something") is False


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


class TestIsConnectionPlaceholder:
    """Tests for _is_connection_placeholder helper (Issue #919)."""

    def test_bracket_hidden(self):
        assert _is_connection_placeholder("[HIDDEN]") is True

    def test_bracket_redacted(self):
        assert _is_connection_placeholder("[REDACTED]") is True

    def test_bracket_password(self):
        assert _is_connection_placeholder("[PASSWORD]") is True

    def test_bracket_masked(self):
        assert _is_connection_placeholder("[MASKED]") is True

    def test_bracket_case_insensitive(self):
        assert _is_connection_placeholder("[hidden]") is True

    def test_angle_bracket_password(self):
        assert _is_connection_placeholder("<password>") is True

    def test_angle_bracket_your_password(self):
        assert _is_connection_placeholder("<your-password>") is True

    def test_angle_bracket_secret(self):
        assert _is_connection_placeholder("<secret>") is True

    def test_repeated_x(self):
        assert _is_connection_placeholder("xxxxxxxx") is True

    def test_repeated_star(self):
        assert _is_connection_placeholder("********") is True

    def test_repeated_zero(self):
        assert _is_connection_placeholder("000000") is True

    def test_generic_placeholder_your(self):
        assert _is_connection_placeholder("your-password-here") is True

    def test_generic_placeholder_example(self):
        assert _is_connection_placeholder("example-password") is True

    def test_real_password(self):
        assert _is_connection_placeholder("MySecretPass123") is False

    def test_real_password_special(self):
        assert _is_connection_placeholder("p@ssw0rd!") is False

    def test_base64_password(self):
        assert _is_connection_placeholder("dGhpcyBpcw==") is False

    def test_short_repeated_not_placeholder(self):
        assert _is_connection_placeholder("xxxxx") is False


class TestConnectionNotPlaceholder:
    """Tests for connection_not_placeholder validator (Issue #919)."""

    def test_real_password_detected(self):
        assert connection_not_placeholder(
            "mongodb://user:MySecretPass123@db.example.com:27017/mydb"
        ) is True

    def test_hidden_placeholder_skipped(self):
        assert connection_not_placeholder(
            "mongodb://user:[HIDDEN]@db.example.com:27017/mydb"
        ) is False

    def test_redacted_placeholder_skipped(self):
        assert connection_not_placeholder(
            "postgres://admin:[REDACTED]@db.host:5432/app"
        ) is False

    def test_angle_bracket_skipped(self):
        assert connection_not_placeholder(
            "mysql://root:<password>@localhost:3306/test"
        ) is False

    def test_repeated_chars_skipped(self):
        assert connection_not_placeholder(
            "redis://:xxxxxxxx@cache.example.com:6379/0"
        ) is False

    def test_no_connection_string_passes(self):
        assert connection_not_placeholder("not a connection string") is True

    def test_registry_lookup(self):
        validator = get_validator("connection_not_placeholder")
        assert validator is connection_not_placeholder


class TestIsTokenPlaceholder:
    """Tests for _is_token_placeholder helper (Issue #931)."""

    def test_repeated_x_lowercase(self):
        assert _is_token_placeholder("xxxxxxxxxxxxxxxxxxxx") is True

    def test_repeated_x_uppercase(self):
        assert _is_token_placeholder("XXXXXXXXXXXXXXXXXXXX") is True

    def test_repeated_zero(self):
        assert _is_token_placeholder("00000000000000000000") is True

    def test_repeated_a(self):
        assert _is_token_placeholder("aaaaaaaaaaaaaaaaaa") is True

    def test_short_repeated_not_placeholder(self):
        assert _is_token_placeholder("xxxxxxx") is False

    def test_placeholder_your_prefix(self):
        assert _is_token_placeholder("your-api-key-here") is True

    def test_placeholder_example_prefix(self):
        assert _is_token_placeholder("example-token-value") is True

    def test_placeholder_test_prefix(self):
        assert _is_token_placeholder("test-api-key-value12345") is True

    def test_placeholder_fake_prefix(self):
        assert _is_token_placeholder("fake-token-abcdef1234") is True

    def test_placeholder_here_suffix(self):
        assert _is_token_placeholder("put-your-secret-here") is True

    def test_all_caps_underscores(self):
        assert _is_token_placeholder("YOUR_TOKEN_HERE") is True

    def test_all_caps_underscores_replace(self):
        assert _is_token_placeholder("REPLACE_ME") is True

    def test_all_caps_underscores_api_key(self):
        assert _is_token_placeholder("API_KEY_VALUE_HERE") is True

    def test_template_angle_brackets(self):
        assert _is_token_placeholder("<your-token-here>") is True

    def test_template_dollar_brace(self):
        assert _is_token_placeholder("${TOKEN}") is True

    def test_template_double_brace(self):
        assert _is_token_placeholder("{{token}}") is True

    def test_real_mixed_case_token(self):
        assert _is_token_placeholder("AbCdEfGhIjKlMnOpQrStUv") is False

    def test_real_alphanumeric_token(self):
        assert _is_token_placeholder("a1B2c3D4e5F6g7H8i9J0k1L2") is False

    def test_real_hex_token(self):
        assert _is_token_placeholder("4f3c2a1b9e8d7c6f5a4b3c2d") is False

    def test_empty_string(self):
        assert _is_token_placeholder("") is False

    def test_single_uppercase_word_not_placeholder(self):
        assert _is_token_placeholder("ABCDEFGHIJKLMNOP") is False


class TestTokenNotPlaceholder:
    """Tests for token_not_placeholder validator (Issue #931)."""

    def test_glpat_all_x_skipped(self):
        assert token_not_placeholder(
            "glpat-xxxxxxxxxxxxxxxxxxxx"
        ) is False

    def test_ghp_all_x_skipped(self):
        assert token_not_placeholder(
            "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        ) is False

    def test_sk_your_key_skipped(self):
        assert token_not_placeholder(
            "sk-your-api-key-here-abcdef"
        ) is False

    def test_xoxb_placeholder_skipped(self):
        assert token_not_placeholder(
            "xoxb-PLACEHOLDER-TOKEN-VALUE"
        ) is False

    def test_glpat_template_angle_skipped(self):
        assert token_not_placeholder(
            "glpat-<your-token-here-value>"
        ) is False

    def test_sk_template_dollar_skipped(self):
        assert token_not_placeholder(
            "sk-${TOKEN_VALUE_PLACEHOLDER}"
        ) is False

    def test_gho_all_caps_underscores_skipped(self):
        assert token_not_placeholder(
            "gho_YOUR_TOKEN_VALUE_HERE_REPLACE_ME_NOW_123456"
        ) is False

    def test_sk_ant_placeholder_skipped(self):
        assert token_not_placeholder(
            "sk-ant-example-key-value-abcdefghijklmnop"
        ) is False

    def test_sk_proj_placeholder_skipped(self):
        assert token_not_placeholder(
            "sk-proj-dummy_token_value_here_abcdef"
        ) is False

    def test_real_glpat_detected(self):
        assert token_not_placeholder(
            "glpat-AbCdEfGhIjKlMnOpQrSt"  # notsecret
        ) is True

    def test_real_ghp_detected(self):
        assert token_not_placeholder(
            "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"  # notsecret
        ) is True

    def test_real_sk_detected(self):
        assert token_not_placeholder(
            "sk-a1B2c3D4e5F6g7H8i9J0k1L2"
        ) is True

    def test_real_xoxb_detected(self):
        assert token_not_placeholder(
            "xoxb-not-a-real-slack-token-aBcDeFgHiJ"  # notsecret
        ) is True

    def test_no_prefix_passes(self):
        assert token_not_placeholder("not-a-token-at-all") is True

    def test_registry_lookup(self):
        validator = get_validator("token_not_placeholder")
        assert validator is token_not_placeholder

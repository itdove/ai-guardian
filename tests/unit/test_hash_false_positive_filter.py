"""Tests for SHA hash false positive filter (Issue #1378)."""

from ai_guardian.patterns.validators import (
    is_hash_value,
    filter_findings_by_hash,
    filter_findings_dicts_by_hash,
)
from ai_guardian.scanners.strategies import SecretMatch

# Real hash values for testing
SHA256_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA1_HASH = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
MD5_HASH = "d41d8cd98f00b204e9800998ecf8427e"
SHA512_HASH = (
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)
SHA384_HASH = (
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
    "274edebfe76f65fbd51ad2f14898b95b"
)


def _make_secret_match(secret, line_number=1, category="secrets"):
    return SecretMatch(
        rule_id="hex-secret-with-context",
        description="test",
        file="test.py",
        line_number=line_number,
        secret=secret,
        category=category,
    )


class TestIsHashValue:
    def test_sha256_with_sha256_keyword(self):
        assert is_hash_value(SHA256_HASH, f"sha256: {SHA256_HASH}")

    def test_sha1_with_hash_keyword(self):
        assert is_hash_value(SHA1_HASH, f"file hash: {SHA1_HASH}")

    def test_md5_with_checksum_keyword(self):
        assert is_hash_value(MD5_HASH, f"checksum={MD5_HASH}")

    def test_sha512_with_digest_keyword(self):
        assert is_hash_value(SHA512_HASH, f"digest: {SHA512_HASH}")

    def test_sha384_with_sha384_keyword(self):
        assert is_hash_value(SHA384_HASH, f"sha384: {SHA384_HASH}")

    def test_sha256_with_fingerprint_keyword(self):
        assert is_hash_value(SHA256_HASH, f"fingerprint: {SHA256_HASH}")

    def test_sha256_with_integrity_keyword(self):
        assert is_hash_value(SHA256_HASH, f"integrity sha256-{SHA256_HASH}")

    def test_sha256_with_sha256sum_keyword(self):
        assert is_hash_value(SHA256_HASH, f"sha256sum: {SHA256_HASH}")

    def test_sha256_with_md5sum_keyword(self):
        assert is_hash_value(MD5_HASH, f"md5sum: {MD5_HASH}")

    def test_sha_hyphenated_keyword(self):
        assert is_hash_value(SHA256_HASH, f"sha-256: {SHA256_HASH}")

    def test_no_hash_keyword_real_secret(self):
        assert not is_hash_value(SHA256_HASH, f"secret_key = {SHA256_HASH}")

    def test_no_line_text(self):
        assert not is_hash_value(SHA256_HASH, None)

    def test_empty_line_text(self):
        assert not is_hash_value(SHA256_HASH, "")

    def test_non_hex_chars(self):
        bad = "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert not is_hash_value(bad, f"sha256: {bad}")

    def test_wrong_length_63(self):
        short = SHA256_HASH[:63]
        assert not is_hash_value(short, f"sha256: {short}")

    def test_wrong_length_65(self):
        long = SHA256_HASH + "a"
        assert not is_hash_value(long, f"sha256: {long}")

    def test_mixed_case_hex(self):
        upper = SHA256_HASH.upper()
        assert is_hash_value(upper, f"SHA256: {upper}")

    def test_empty_matched_text(self):
        assert not is_hash_value("", "sha256: abc")

    def test_none_matched_text(self):
        assert not is_hash_value(None, "sha256: abc")

    def test_quoted_hash_value(self):
        assert is_hash_value(f'"{SHA256_HASH}"', f'sha256: "{SHA256_HASH}"')

    def test_sri_keyword(self):
        assert is_hash_value(SHA384_HASH, f"sri: {SHA384_HASH}")

    def test_subresource_keyword(self):
        assert is_hash_value(SHA256_HASH, f"subresource integrity: {SHA256_HASH}")

    def test_env_variable_key_equals_hash(self):
        env_match = f"GCLOUD_SHA256_X86_64={SHA256_HASH}"
        assert is_hash_value(env_match, f"export {env_match}")

    def test_env_variable_checksum_keyword(self):
        env_match = f"CHECKSUM={MD5_HASH}"
        assert is_hash_value(env_match, f"export {env_match}")

    def test_env_variable_no_hash_keyword(self):
        env_match = f"API_TOKEN={SHA256_HASH}"
        assert not is_hash_value(env_match, f"export {env_match}")

    def test_env_variable_digest_keyword(self):
        env_match = f"DIGEST_VALUE={SHA256_HASH}"
        assert is_hash_value(env_match, f"{env_match}")

    def test_equals_in_value_no_key(self):
        assert is_hash_value(SHA256_HASH, f"sha256: {SHA256_HASH}")


class TestFilterFindingsByHash:
    def test_hash_finding_suppressed(self):
        content = f"sha256: {SHA256_HASH}\n"
        secrets = [_make_secret_match(SHA256_HASH, line_number=1)]
        filtered, count = filter_findings_by_hash(secrets, content)
        assert len(filtered) == 0
        assert count == 1

    def test_real_secret_preserved(self):
        content = f"api_key = {SHA256_HASH}\n"
        secrets = [_make_secret_match(SHA256_HASH, line_number=1)]
        filtered, count = filter_findings_by_hash(secrets, content)
        assert len(filtered) == 1
        assert count == 0

    def test_mixed_list(self):
        content = f"sha256: {SHA256_HASH}\napi_key = {SHA1_HASH}\n"
        secrets = [
            _make_secret_match(SHA256_HASH, line_number=1),
            _make_secret_match(SHA1_HASH, line_number=2),
        ]
        filtered, count = filter_findings_by_hash(secrets, content)
        assert len(filtered) == 1
        assert filtered[0].secret == SHA1_HASH
        assert count == 1

    def test_none_content_no_filtering(self):
        secrets = [_make_secret_match(SHA256_HASH)]
        filtered, count = filter_findings_by_hash(secrets, None)
        assert len(filtered) == 1
        assert count == 0

    def test_empty_content_no_filtering(self):
        secrets = [_make_secret_match(SHA256_HASH)]
        filtered, count = filter_findings_by_hash(secrets, "")
        assert len(filtered) == 1
        assert count == 0

    def test_line_number_out_of_range(self):
        content = "one line only\n"
        secrets = [_make_secret_match(SHA256_HASH, line_number=99)]
        filtered, count = filter_findings_by_hash(secrets, content)
        assert len(filtered) == 1
        assert count == 0

    def test_pii_category_not_filtered(self):
        content = f"sha256: {SHA256_HASH}\n"
        secrets = [_make_secret_match(SHA256_HASH, line_number=1, category="pii")]
        filtered, count = filter_findings_by_hash(secrets, content)
        assert len(filtered) == 1
        assert count == 0

    def test_line_number_zero_not_filtered(self):
        content = f"sha256: {SHA256_HASH}\n"
        secrets = [_make_secret_match(SHA256_HASH, line_number=0)]
        filtered, count = filter_findings_by_hash(secrets, content)
        assert len(filtered) == 1
        assert count == 0


class TestFilterFindingsDictsByHash:
    def test_hash_dict_suppressed(self):
        content = f"checksum: {MD5_HASH}\n"
        findings = [{"matched_text": MD5_HASH, "line_number": 1}]
        filtered, count = filter_findings_dicts_by_hash(findings, content)
        assert len(filtered) == 0
        assert count == 1

    def test_no_keyword_preserved(self):
        content = f"token = {MD5_HASH}\n"
        findings = [{"matched_text": MD5_HASH, "line_number": 1}]
        filtered, count = filter_findings_dicts_by_hash(findings, content)
        assert len(filtered) == 1
        assert count == 0

    def test_missing_line_number_preserved(self):
        content = f"sha256: {SHA256_HASH}\n"
        findings = [{"matched_text": SHA256_HASH}]
        filtered, count = filter_findings_dicts_by_hash(findings, content)
        assert len(filtered) == 1
        assert count == 0

    def test_none_content_no_filtering(self):
        findings = [{"matched_text": SHA256_HASH, "line_number": 1}]
        filtered, count = filter_findings_dicts_by_hash(findings, None)
        assert len(filtered) == 1
        assert count == 0

    def test_none_line_number_preserved(self):
        content = f"sha256: {SHA256_HASH}\n"
        findings = [{"matched_text": SHA256_HASH, "line_number": None}]
        filtered, count = filter_findings_dicts_by_hash(findings, content)
        assert len(filtered) == 1
        assert count == 0

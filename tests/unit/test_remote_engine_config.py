"""Tests for remote engine configuration."""

import unittest
from unittest.mock import patch, MagicMock

from ai_guardian.scanners.remote_config import (
    fetch_remote_engine_config,
    merge_engine_configs,
)


class TestFetchRemoteEngineConfig(unittest.TestCase):

    def test_returns_none_when_no_url(self):
        result = fetch_remote_engine_config({})
        self.assertIsNone(result)

    def test_returns_none_when_url_empty(self):
        result = fetch_remote_engine_config({"url": ""})
        self.assertIsNone(result)

    @patch("ai_guardian.scanners.remote_config.RemoteFetcher")
    def test_fetch_uses_remote_fetcher(self, mock_cls):
        mock_fetcher = MagicMock()
        mock_fetcher.fetch_config.return_value = {"engines": ["gitleaks"]}
        mock_cls.return_value = mock_fetcher

        result = fetch_remote_engine_config({
            "url": "https://example.com/config.json",
            "refresh_interval_hours": 6,
        })
        self.assertEqual(result, {"engines": ["gitleaks"]})
        mock_fetcher.fetch_config.assert_called_once()

    @patch("ai_guardian.scanners.remote_config.RemoteFetcher")
    def test_auth_token_env_passed_as_header(self, mock_cls):
        mock_fetcher = MagicMock()
        mock_fetcher.fetch_config.return_value = {}
        mock_cls.return_value = mock_fetcher

        with patch.dict("os.environ", {"MY_TOKEN": "secret123"}):
            fetch_remote_engine_config({
                "url": "https://example.com/config.json",
                "auth_token_env": "MY_TOKEN",
            })

        call_kwargs = mock_fetcher.fetch_config.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        self.assertEqual(headers["Authorization"], "Bearer secret123")


class TestMergeEngineConfigs(unittest.TestCase):

    def test_immutable_replaces_local(self):
        local = ["gitleaks", "trufflehog"]
        remote = ["detect-secrets"]
        result = merge_engine_configs(local, remote, immutable=True)
        self.assertEqual(result, ["detect-secrets"])

    def test_non_immutable_prepends_remote(self):
        local = ["gitleaks", "trufflehog"]
        remote = ["detect-secrets"]
        result = merge_engine_configs(local, remote, immutable=False)
        self.assertEqual(result, ["detect-secrets", "gitleaks", "trufflehog"])

    def test_deduplicates_engine_types(self):
        local = ["gitleaks", "trufflehog"]
        remote = ["gitleaks", "secretlint"]
        result = merge_engine_configs(local, remote, immutable=False)
        self.assertEqual(result, ["gitleaks", "secretlint", "trufflehog"])

    def test_dict_engine_specs(self):
        local = [{"type": "gitleaks"}]
        remote = [{"type": "gitleaks", "extra_flags": ["--verbose"]}]
        result = merge_engine_configs(local, remote, immutable=False)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["extra_flags"], ["--verbose"])

    def test_empty_remote(self):
        local = ["gitleaks"]
        result = merge_engine_configs(local, [], immutable=False)
        self.assertEqual(result, ["gitleaks"])


if __name__ == "__main__":
    unittest.main()

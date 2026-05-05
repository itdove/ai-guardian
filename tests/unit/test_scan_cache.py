"""Tests for scan result caching."""

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ai_guardian.scanners.cache import ScanResultCache, FileStateTracker
from ai_guardian.scanners.strategies import ScanResult, SecretMatch


class TestScanResultCache(unittest.TestCase):

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.cache_dir = Path(self.tmp.name) / "cache"
        self.cache = ScanResultCache(cache_dir=self.cache_dir, ttl_hours=24.0)

    def tearDown(self):
        self.tmp.cleanup()

    def _sample_result(self, has_secrets=True):
        secrets = []
        if has_secrets:
            secrets.append(SecretMatch(
                rule_id="aws-access-key",
                description="AWS Access Key detected",
                file="test.py",
                line_number=5,
                engine="gitleaks",
                confidence=1.0,
                verified=False,
            ))
        return ScanResult(
            has_secrets=has_secrets,
            secrets=secrets,
            engine="gitleaks",
            scan_time_ms=120.5,
        )

    def test_cache_miss_returns_none(self):
        result = self.cache.get("abc123", "gitleaks", "cfg123")
        self.assertIsNone(result)

    def test_cache_hit_returns_result(self):
        original = self._sample_result()
        self.cache.put("abc123", "gitleaks", "cfg123", original)

        cached = self.cache.get("abc123", "gitleaks", "cfg123")
        self.assertIsNotNone(cached)
        self.assertTrue(cached.has_secrets)
        self.assertEqual(len(cached.secrets), 1)
        self.assertEqual(cached.secrets[0].rule_id, "aws-access-key")
        self.assertEqual(cached.scan_time_ms, 0.0)

    def test_cache_expired_returns_none(self):
        cache = ScanResultCache(cache_dir=self.cache_dir, ttl_hours=0.0001)
        cache.put("abc123", "gitleaks", "cfg123", self._sample_result())
        time.sleep(0.5)
        result = cache.get("abc123", "gitleaks", "cfg123")
        self.assertIsNone(result)

    def test_cache_key_varies_by_content(self):
        k1 = self.cache.cache_key("hash_a", "gitleaks", "cfg")
        k2 = self.cache.cache_key("hash_b", "gitleaks", "cfg")
        self.assertNotEqual(k1, k2)

    def test_cache_key_varies_by_engine(self):
        k1 = self.cache.cache_key("hash", "gitleaks", "cfg")
        k2 = self.cache.cache_key("hash", "trufflehog", "cfg")
        self.assertNotEqual(k1, k2)

    def test_cache_key_varies_by_config(self):
        k1 = self.cache.cache_key("hash", "gitleaks", "cfg_a")
        k2 = self.cache.cache_key("hash", "gitleaks", "cfg_b")
        self.assertNotEqual(k1, k2)

    def test_cache_disabled_always_misses(self):
        cache = ScanResultCache(cache_dir=self.cache_dir, enabled=False)
        cache.put("abc", "gitleaks", "cfg", self._sample_result())
        self.assertIsNone(cache.get("abc", "gitleaks", "cfg"))

    def test_cache_put_and_get_roundtrip(self):
        result = self._sample_result(has_secrets=False)
        self.cache.put("clean", "gitleaks", "cfg", result)
        cached = self.cache.get("clean", "gitleaks", "cfg")
        self.assertIsNotNone(cached)
        self.assertFalse(cached.has_secrets)
        self.assertEqual(len(cached.secrets), 0)

    def test_cache_clear_removes_entries(self):
        self.cache.put("a", "gitleaks", "c", self._sample_result())
        self.cache.put("b", "gitleaks", "c", self._sample_result())
        count = self.cache.clear()
        self.assertEqual(count, 2)
        self.assertIsNone(self.cache.get("a", "gitleaks", "c"))

    def test_cache_stats(self):
        self.cache.put("a", "gitleaks", "c", self._sample_result())
        stats = self.cache.stats()
        self.assertTrue(stats["enabled"])
        self.assertEqual(stats["entry_count"], 1)
        self.assertGreater(stats["total_size_bytes"], 0)

    def test_cache_handles_corrupt_file(self):
        key = self.cache.cache_key("x", "y", "z")
        corrupt = self.cache_dir / f"{key}.json"
        corrupt.write_text("not valid json")
        result = self.cache.get("x", "y", "z")
        self.assertIsNone(result)

    def test_content_hash_deterministic(self):
        h1 = ScanResultCache.content_hash("hello world")
        h2 = ScanResultCache.content_hash("hello world")
        self.assertEqual(h1, h2)

    def test_content_hash_varies(self):
        h1 = ScanResultCache.content_hash("hello")
        h2 = ScanResultCache.content_hash("world")
        self.assertNotEqual(h1, h2)


class TestFileStateTracker(unittest.TestCase):

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.state_dir = Path(self.tmp.name) / "state"
        self.tracker = FileStateTracker(state_dir=self.state_dir)

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_scan_always_changed(self):
        self.assertTrue(self.tracker.has_changed("file.py", "content"))

    def test_unchanged_file_not_changed(self):
        self.tracker.record_scan("file.py", "content", "gitleaks")
        self.assertFalse(self.tracker.has_changed("file.py", "content"))

    def test_changed_file_detected(self):
        self.tracker.record_scan("file.py", "old content", "gitleaks")
        self.assertTrue(self.tracker.has_changed("file.py", "new content"))

    def test_different_files_independent(self):
        self.tracker.record_scan("a.py", "content", "gitleaks")
        self.assertTrue(self.tracker.has_changed("b.py", "content"))

    def test_state_persists_across_instances(self):
        self.tracker.record_scan("file.py", "content", "gitleaks")
        new_tracker = FileStateTracker(state_dir=self.state_dir)
        self.assertFalse(new_tracker.has_changed("file.py", "content"))

    def test_clear_state_forces_rescan(self):
        self.tracker.record_scan("file.py", "content", "gitleaks")
        self.tracker.clear()
        self.assertTrue(self.tracker.has_changed("file.py", "content"))

    def test_record_scan_updates_state(self):
        self.tracker.record_scan("file.py", "v1", "gitleaks")
        self.tracker.record_scan("file.py", "v2", "gitleaks")
        self.assertFalse(self.tracker.has_changed("file.py", "v2"))
        self.assertTrue(self.tracker.has_changed("file.py", "v1"))


if __name__ == "__main__":
    unittest.main()

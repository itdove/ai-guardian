"""Tests for the running violation counter (Issue #853)."""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


from ai_guardian.violation_counter import ViolationCounter


class TestViolationCounterIncrement:
    def test_increment_creates_file(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"
        assert not counter_path.exists()

        counter = ViolationCounter(counter_path=counter_path)
        counter.increment("secret_detected")

        assert counter_path.exists()
        data = json.loads(counter_path.read_text())
        assert data["version"] == 1
        assert data["total"] == 1
        assert data["violation_totals"]["secret_detected"] == 1
        assert data["since"] != ""

    def test_increment_multiple_types(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"
        counter = ViolationCounter(counter_path=counter_path)

        counter.increment("secret_detected")
        counter.increment("secret_detected")
        counter.increment("pii_detected")
        counter.increment("prompt_injection")
        counter.increment("prompt_injection")
        counter.increment("prompt_injection")

        data = counter.get_counters()
        assert data["total"] == 6
        assert data["violation_totals"]["secret_detected"] == 2
        assert data["violation_totals"]["pii_detected"] == 1
        assert data["violation_totals"]["prompt_injection"] == 3

    def test_increment_persists(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"

        counter1 = ViolationCounter(counter_path=counter_path)
        counter1.increment("secret_detected")
        counter1.increment("secret_detected")

        counter2 = ViolationCounter(counter_path=counter_path)
        counter2.increment("secret_detected")

        data = counter2.get_counters()
        assert data["total"] == 3
        assert data["violation_totals"]["secret_detected"] == 3

    def test_increment_sets_since_on_first_call(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"
        counter = ViolationCounter(counter_path=counter_path)

        before = datetime.now(timezone.utc)
        counter.increment("secret_detected")
        after = datetime.now(timezone.utc)

        data = counter.get_counters()
        since_str = data["since"]
        assert since_str.endswith("Z") or "+" in since_str


class TestViolationCounterGetCounters:
    def test_no_file_returns_defaults(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"
        counter = ViolationCounter(counter_path=counter_path)

        data = counter.get_counters()
        assert data["total"] == 0
        assert data["violation_totals"] == {}
        assert data["since"] == ""

    def test_corrupt_file_returns_defaults(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"
        counter_path.write_text("not valid json", encoding="utf-8")

        counter = ViolationCounter(counter_path=counter_path)
        data = counter.get_counters()
        assert data["total"] == 0

    def test_partial_data_fills_defaults(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"
        counter_path.write_text(json.dumps({"version": 1, "since": "2026-01-01"}))

        counter = ViolationCounter(counter_path=counter_path)
        data = counter.get_counters()
        assert data["violation_totals"] == {}
        assert data["total"] == 0


class TestViolationCounterReset:
    def test_reset_to_current_log(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"
        log_path = Path(state_dir) / "violations.jsonl"

        violations = [
            {"violation_type": "secret_detected", "timestamp": "2026-05-01T00:00:00Z"},
            {"violation_type": "secret_detected", "timestamp": "2026-05-01T00:00:00Z"},
            {"violation_type": "pii_detected", "timestamp": "2026-05-01T00:00:00Z"},
        ]
        with open(log_path, "w", encoding="utf-8") as f:
            for v in violations:
                f.write(json.dumps(v) + "\n")

        counter = ViolationCounter(counter_path=counter_path)
        counter.increment("secret_detected")
        counter.increment("secret_detected")
        counter.increment("secret_detected")
        counter.increment("secret_detected")
        counter.increment("secret_detected")
        assert counter.get_counters()["total"] == 5

        result = counter.reset_to_current_log()
        assert result["total"] == 3
        assert result["violation_totals"]["secret_detected"] == 2
        assert result["violation_totals"]["pii_detected"] == 1

    def test_reset_sets_since_to_now(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"

        counter = ViolationCounter(counter_path=counter_path)
        before = datetime.now(timezone.utc)
        result = counter.reset_to_current_log()
        after = datetime.now(timezone.utc)

        since_str = result["since"]
        assert since_str != ""
        assert "2026" in since_str

    def test_reset_with_empty_log(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"

        counter = ViolationCounter(counter_path=counter_path)
        counter.increment("secret_detected")
        counter.increment("secret_detected")

        result = counter.reset_to_current_log()
        assert result["total"] == 0
        assert result["violation_totals"] == {}

    def test_reset_not_zero(self, _isolate_config_dir):
        """Reset uses current file count as baseline, not zero."""
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"
        log_path = Path(state_dir) / "violations.jsonl"

        with open(log_path, "w", encoding="utf-8") as f:
            for _ in range(5):
                f.write(json.dumps({"violation_type": "tool_permission"}) + "\n")

        counter = ViolationCounter(counter_path=counter_path)
        result = counter.reset_to_current_log()
        assert result["total"] == 5
        assert result["violation_totals"]["tool_permission"] == 5


class TestViolationCounterThreadSafety:
    def test_concurrent_increments(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        counter_path = Path(state_dir) / "violation_counters.json"
        counter = ViolationCounter(counter_path=counter_path)

        threads = []
        for _ in range(10):
            t = threading.Thread(target=counter.increment, args=("secret_detected",))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        data = counter.get_counters()
        assert data["total"] == 10
        assert data["violation_totals"]["secret_detected"] == 10

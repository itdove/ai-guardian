"""Tests for ai_guardian.logging_utils (quiet_logging)."""

import logging
import threading

from ai_guardian.logging_utils import quiet_logging, _quiet_lock, _quiet_depth


def test_quiet_logging_suppresses_and_restores():
    original = logging.root.level

    with quiet_logging():
        assert logging.root.manager.disable >= logging.CRITICAL

    assert logging.root.level == original
    assert logging.root.manager.disable < logging.CRITICAL


def test_quiet_logging_restores_on_exception():
    original = logging.root.level

    try:
        with quiet_logging():
            raise RuntimeError("boom")
    except RuntimeError:
        pass

    assert logging.root.level == original
    assert logging.root.manager.disable < logging.CRITICAL


def test_quiet_logging_reentrant():
    original = logging.root.level

    with quiet_logging():
        with quiet_logging():
            assert logging.root.manager.disable >= logging.CRITICAL
        assert logging.root.manager.disable >= logging.CRITICAL

    assert logging.root.level == original
    assert logging.root.manager.disable < logging.CRITICAL


def test_quiet_logging_concurrent_threads():
    original = logging.root.level
    barrier = threading.Barrier(2)
    errors = []

    def worker():
        try:
            with quiet_logging():
                barrier.wait(timeout=5)
                assert logging.root.manager.disable >= logging.CRITICAL
                barrier.wait(timeout=5)
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert not errors
    assert logging.root.level == original
    assert logging.root.manager.disable < logging.CRITICAL


def test_tui_utils_reexports():
    from ai_guardian.tui.utils import quiet_logging as tui_ql
    from ai_guardian.logging_utils import quiet_logging as root_ql

    assert tui_ql is root_ql

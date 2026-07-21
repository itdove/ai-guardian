"""Shared logging utilities."""

import contextlib
import logging
import threading

_quiet_lock = threading.Lock()
_quiet_depth = 0
_quiet_prev_level = logging.WARNING


@contextlib.contextmanager
def quiet_logging():
    """Temporarily suppress logging to avoid stdout noise.

    Thread-safe and reentrant: nested or concurrent calls share a single
    suppression window.  Logging is restored only when the last caller exits.
    """
    global _quiet_depth, _quiet_prev_level

    with _quiet_lock:
        if _quiet_depth == 0:
            _quiet_prev_level = logging.root.level
            logging.disable(logging.CRITICAL)
        _quiet_depth += 1

    try:
        yield
    finally:
        with _quiet_lock:
            _quiet_depth -= 1
            if _quiet_depth == 0:
                logging.disable(logging.NOTSET)
                logging.root.setLevel(_quiet_prev_level)

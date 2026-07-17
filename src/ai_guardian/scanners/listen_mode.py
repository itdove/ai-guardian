"""Persistent leaktk listen-mode process for zero-overhead secret scanning.

leaktk v0.3.x ``listen`` subcommand keeps a long-running process that reads
JSON-line scan requests on stdin and writes ``ScanResults`` JSON on stdout.
Patterns are cached in-process across requests, eliminating the ~200ms
subprocess spawn overhead per scan.

Used by the daemon via ``DaemonState.get_listen_manager()``.  When the daemon
is not running, the executor falls back to ``subprocess.run()`` automatically.
"""

import json
import logging
import subprocess
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from ai_guardian.scanners.output_parsers import _normalize_leaktk_result

logger = logging.getLogger(__name__)


class LeakTKListenProcess:
    """Wraps a persistent ``leaktk listen`` subprocess."""

    def __init__(self, binary: str, config_path: Optional[str] = None):
        self._binary = binary
        self._config_path = config_path
        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._stderr_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Spawn the leaktk listen process."""
        cmd: List[str] = [self._binary, "listen", "--format", "json"]
        if self._config_path:
            cmd.extend(["--config", self._config_path])

        logger.info("Starting leaktk listen process: %s", " ".join(cmd))
        self._process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True, name="leaktk-stderr"
        )
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        """Read stderr in background so the pipe doesn't block."""
        assert self._process is not None and self._process.stderr is not None
        for line in self._process.stderr:
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                logger.debug("leaktk: %s", text)

    def is_alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def scan(self, source_file: str, request_id: str) -> Dict[str, Any]:
        """Send a scan request and return the parsed ScanResults response.

        Thread-safe: a lock serializes stdin/stdout I/O so request-response
        pairing is maintained.

        Returns:
            Standardized dict: ``{has_secrets, findings, total_findings}``

        Raises:
            RuntimeError: if the process is not alive or I/O fails.
        """
        with self._lock:
            if not self.is_alive():
                raise RuntimeError("leaktk listen process is not running")

            assert self._process is not None
            assert self._process.stdin is not None
            assert self._process.stdout is not None

            request = json.dumps(
                {"kind": "Files", "id": request_id, "resource": source_file}
            )
            start = time.monotonic()

            self._process.stdin.write((request + "\n").encode("utf-8"))
            self._process.stdin.flush()

            line = self._process.stdout.readline()
            elapsed_ms = (time.monotonic() - start) * 1000

            if not line:
                raise RuntimeError(
                    "leaktk listen returned empty response (process may have died)"
                )

            response = json.loads(line.decode("utf-8"))
            logger.debug(
                "leaktk listen scan completed in %.1fms (request_id=%s)",
                elapsed_ms,
                request_id,
            )

            return parse_listen_results(response)

    def stop(self) -> None:
        """Stop the listen process gracefully."""
        if self._process is None:
            return

        logger.info("Stopping leaktk listen process (pid=%s)", self._process.pid)
        try:
            if self._process.stdin and not self._process.stdin.closed:
                self._process.stdin.close()
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("leaktk listen did not exit cleanly, killing")
            self._process.kill()
            self._process.wait(timeout=2)
        except Exception as exc:
            logger.warning("Error stopping leaktk listen: %s", exc)
            if self._process.poll() is None:
                self._process.kill()
        finally:
            self._process = None


def parse_listen_results(response: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a leaktk ``ScanResults`` response to the standardized format.

    Args:
        response: Parsed JSON from leaktk listen stdout.

    Returns:
        ``{has_secrets: bool, findings: list, total_findings: int}``
    """
    results = response.get("results", [])
    if not results:
        return {"has_secrets": False, "findings": [], "total_findings": 0}

    findings = [_normalize_leaktk_result(r) for r in results]
    return {
        "has_secrets": True,
        "findings": findings,
        "total_findings": len(findings),
    }


class ListenModeManager:
    """Manages the lifecycle of a persistent leaktk listen process.

    Thread-safe.  Lazily starts the process on first scan.  Restarts
    automatically if the process dies.
    """

    def __init__(self) -> None:
        self._process: Optional[LeakTKListenProcess] = None
        self._lock = threading.Lock()

    def scan(
        self,
        binary: str,
        source_file: str,
        config_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Scan a file via the persistent listen process.

        Starts the process lazily.  Restarts if it died since the last scan.

        Returns:
            Standardized dict: ``{has_secrets, findings, total_findings}``
        """
        with self._lock:
            if self._process is None or not self._process.is_alive():
                if self._process is not None:
                    logger.info("leaktk listen process died, restarting")
                    self._process.stop()
                self._process = LeakTKListenProcess(binary, config_path)
                self._process.start()

        request_id = uuid.uuid4().hex[:12]
        return self._process.scan(source_file, request_id)

    def stop(self) -> None:
        """Stop the managed process (if running)."""
        with self._lock:
            if self._process is not None:
                self._process.stop()
                self._process = None

    def restart(self) -> None:
        """Kill and clear the process so the next scan starts a fresh one."""
        with self._lock:
            if self._process is not None:
                self._process.stop()
                self._process = None

    def is_alive(self) -> bool:
        return self._process is not None and self._process.is_alive()

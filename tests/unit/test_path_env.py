"""Tests for PATH augmentation utility (issue #689)."""

import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest

import ai_guardian.daemon.path_env as path_env_mod
from ai_guardian.daemon.path_env import (
    _read_shell_path,
    _well_known_dirs_with_scanners,
    ensure_scanner_path,
)


@pytest.fixture(autouse=True)
def reset_augmented_flag():
    """Reset the module-level _augmented flag before each test."""
    path_env_mod._augmented = False
    yield
    path_env_mod._augmented = False


class TestWellKnownDirsWithScanners:
    def test_finds_directory_containing_scanner(self, tmp_path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        scanner = bin_dir / "betterleaks"
        scanner.write_text("#!/bin/sh\n")
        scanner.chmod(0o755)

        with mock.patch.object(path_env_mod, "_WELL_KNOWN_DIRS", [str(bin_dir)]):
            result = _well_known_dirs_with_scanners()

        assert str(bin_dir) in result

    def test_skips_directory_without_scanners(self, tmp_path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()

        with mock.patch.object(path_env_mod, "_WELL_KNOWN_DIRS", [str(bin_dir)]):
            result = _well_known_dirs_with_scanners()

        assert result == []

    def test_skips_nonexistent_directory(self):
        with mock.patch.object(path_env_mod, "_WELL_KNOWN_DIRS", ["/nonexistent/path"]):
            result = _well_known_dirs_with_scanners()

        assert result == []

    def test_does_not_duplicate_directories(self, tmp_path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        for name in ["betterleaks", "gitleaks"]:
            s = bin_dir / name
            s.write_text("#!/bin/sh\n")
            s.chmod(0o755)

        with mock.patch.object(path_env_mod, "_WELL_KNOWN_DIRS", [str(bin_dir)]):
            result = _well_known_dirs_with_scanners()

        assert result == [str(bin_dir)]


class TestReadShellPath:
    def test_returns_path_dirs_from_shell(self):
        fake_path = "/opt/homebrew/bin:/usr/local/bin:/usr/bin"
        with mock.patch("ai_guardian.daemon.path_env.subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(
                returncode=0, stdout=fake_path + "\n"
            )
            result = _read_shell_path()

        assert result == ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]

    def test_returns_empty_on_timeout(self):
        with mock.patch("ai_guardian.daemon.path_env.subprocess.run",
                        side_effect=subprocess.TimeoutExpired("cmd", 5)):
            result = _read_shell_path()

        assert result == []

    def test_returns_empty_on_oserror(self):
        with mock.patch("ai_guardian.daemon.path_env.subprocess.run",
                        side_effect=OSError("no shell")):
            result = _read_shell_path()

        assert result == []

    def test_returns_empty_when_no_shell_env(self, monkeypatch):
        monkeypatch.delenv("SHELL", raising=False)
        result = _read_shell_path()
        assert result == []

    def test_returns_empty_on_nonzero_exit(self):
        with mock.patch("ai_guardian.daemon.path_env.subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=1, stdout="")
            result = _read_shell_path()

        assert result == []


class TestEnsureScannerPath:
    def test_adds_existing_well_known_dir(self, tmp_path, monkeypatch):
        bin_dir = tmp_path / "homebrew" / "bin"
        bin_dir.mkdir(parents=True)

        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        with mock.patch.object(path_env_mod, "_WELL_KNOWN_DIRS", [str(bin_dir)]):
            with mock.patch.object(path_env_mod, "_SCANNER_BINARIES", []):
                with mock.patch("ai_guardian.daemon.path_env._read_shell_path",
                                return_value=[]):
                    ensure_scanner_path()

        assert str(bin_dir) in os.environ["PATH"]

    def test_skips_nonexistent_dir(self, monkeypatch):
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        original = os.environ["PATH"]

        with mock.patch.object(path_env_mod, "_WELL_KNOWN_DIRS",
                               ["/definitely/does/not/exist"]):
            with mock.patch("ai_guardian.daemon.path_env._read_shell_path",
                            return_value=[]):
                ensure_scanner_path()

        assert "/definitely/does/not/exist" not in os.environ["PATH"]

    def test_skips_dir_already_in_path(self, monkeypatch):
        monkeypatch.setenv("PATH", "/usr/bin:/bin:/usr/local/bin")
        original = os.environ["PATH"]

        with mock.patch.object(path_env_mod, "_WELL_KNOWN_DIRS", ["/usr/local/bin"]):
            with mock.patch("ai_guardian.daemon.path_env._read_shell_path",
                            return_value=[]):
                ensure_scanner_path()

        count = os.environ["PATH"].split(os.pathsep).count("/usr/local/bin")
        assert count == 1

    def test_idempotent(self, tmp_path, monkeypatch):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()

        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        with mock.patch.object(path_env_mod, "_WELL_KNOWN_DIRS", [str(bin_dir)]):
            with mock.patch("ai_guardian.daemon.path_env._read_shell_path",
                            return_value=[]):
                ensure_scanner_path()
                first_path = os.environ["PATH"]
                ensure_scanner_path()
                second_path = os.environ["PATH"]

        assert first_path == second_path

    def test_adds_dirs_from_shell_path(self, tmp_path, monkeypatch):
        shell_dir = tmp_path / "shell_bin"
        shell_dir.mkdir()

        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        with mock.patch.object(path_env_mod, "_WELL_KNOWN_DIRS", []):
            with mock.patch("ai_guardian.daemon.path_env._read_shell_path",
                            return_value=[str(shell_dir)]):
                ensure_scanner_path()

        assert str(shell_dir) in os.environ["PATH"]

    def test_scanner_dir_prioritized_over_well_known(self, tmp_path, monkeypatch):
        scanner_dir = tmp_path / "scanner_bin"
        scanner_dir.mkdir()
        scanner = scanner_dir / "betterleaks"
        scanner.write_text("#!/bin/sh\n")
        scanner.chmod(0o755)

        generic_dir = tmp_path / "generic_bin"
        generic_dir.mkdir()

        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        with mock.patch.object(path_env_mod, "_WELL_KNOWN_DIRS",
                               [str(scanner_dir), str(generic_dir)]):
            with mock.patch("ai_guardian.daemon.path_env._read_shell_path",
                            return_value=[]):
                ensure_scanner_path()

        path_dirs = os.environ["PATH"].split(os.pathsep)
        scanner_idx = path_dirs.index(str(scanner_dir))
        generic_idx = path_dirs.index(str(generic_dir))
        assert scanner_idx < generic_idx

    def test_graceful_when_shell_fails(self, tmp_path, monkeypatch):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()

        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        with mock.patch.object(path_env_mod, "_WELL_KNOWN_DIRS", [str(bin_dir)]):
            with mock.patch("ai_guardian.daemon.path_env._read_shell_path",
                            side_effect=Exception("unexpected")):
                ensure_scanner_path()

        assert str(bin_dir) in os.environ["PATH"]

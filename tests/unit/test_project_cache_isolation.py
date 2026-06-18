"""Tests for per-project cache isolation (#1227).

Verifies that the daemon's module-level caches are keyed per-project
so that project A's configs don't bleed into project B.
"""

import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest


class TestFindProjectRootPerCwd:
    """find_project_root() caches per-cwd, not globally."""

    def setup_method(self):
        from ai_guardian.gitleaks_config import reset_cache
        reset_cache()

    def test_different_cwds_get_separate_entries(self, tmp_path):
        from ai_guardian.gitleaks_config import find_project_root, _project_roots

        dir_a = tmp_path / "project_a"
        dir_b = tmp_path / "project_b"
        dir_a.mkdir()
        dir_b.mkdir()

        with patch("subprocess.check_output", side_effect=FileNotFoundError("no git")):
            root_a = find_project_root(cwd=str(dir_a))
            root_b = find_project_root(cwd=str(dir_b))

        assert root_a == Path(str(dir_a))
        assert root_b == Path(str(dir_b))
        assert root_a != root_b
        assert len(_project_roots) == 2

    def test_same_cwd_returns_cached(self, tmp_path):
        from ai_guardian.gitleaks_config import find_project_root, _project_roots

        dir_a = tmp_path / "project_a"
        dir_a.mkdir()

        with patch("subprocess.check_output", side_effect=FileNotFoundError("no git")):
            root_1 = find_project_root(cwd=str(dir_a))
            root_2 = find_project_root(cwd=str(dir_a))

        assert root_1 is root_2
        assert len(_project_roots) == 1

    def test_no_cwd_uses_os_getcwd(self, tmp_path, monkeypatch):
        from ai_guardian.gitleaks_config import find_project_root, _project_roots

        monkeypatch.chdir(tmp_path)
        with patch("subprocess.check_output", side_effect=FileNotFoundError("no git")):
            root = find_project_root()

        assert root == tmp_path
        assert str(tmp_path) in _project_roots


class TestAiguardignorePerProject:
    """load_aiguardignore() caches per-project root."""

    def setup_method(self):
        from ai_guardian.aiguardignore import reset_cache
        from ai_guardian.gitleaks_config import reset_cache as reset_gitleaks
        reset_cache()
        reset_gitleaks()

    @pytest.fixture
    def two_projects(self, tmp_path):
        proj_a = tmp_path / "project_a"
        proj_b = tmp_path / "project_b"
        proj_a.mkdir()
        proj_b.mkdir()

        toml_a = proj_a / ".aiguardignore.toml"
        toml_a.write_text('[allowlist]\npaths = ["tests/a/**"]\n')

        toml_b = proj_b / ".aiguardignore.toml"
        toml_b.write_text('[allowlist]\npaths = ["tests/b/**"]\n')

        return proj_a, proj_b

    def test_separate_cache_entries(self, two_projects):
        from ai_guardian.aiguardignore import load_aiguardignore, _cached_configs

        proj_a, proj_b = two_projects

        config_a = load_aiguardignore(project_root=proj_a)
        config_b = load_aiguardignore(project_root=proj_b)

        assert config_a is not None
        assert config_b is not None
        assert config_a.global_paths == ["tests/a/**"]
        assert config_b.global_paths == ["tests/b/**"]
        assert len(_cached_configs) == 2

    def test_mtime_reload(self, tmp_path):
        from ai_guardian.aiguardignore import load_aiguardignore

        toml = tmp_path / ".aiguardignore.toml"
        toml.write_text('[allowlist]\npaths = ["old/**"]\n')

        config_1 = load_aiguardignore(project_root=tmp_path)
        assert config_1.global_paths == ["old/**"]

        time.sleep(0.05)
        toml.write_text('[allowlist]\npaths = ["new/**"]\n')

        config_2 = load_aiguardignore(project_root=tmp_path)
        assert config_2.global_paths == ["new/**"]

    def test_no_cross_contamination(self, two_projects):
        from ai_guardian.aiguardignore import load_aiguardignore

        proj_a, proj_b = two_projects

        load_aiguardignore(project_root=proj_a)
        config_b = load_aiguardignore(project_root=proj_b)

        assert "tests/a/**" not in config_b.global_paths
        assert config_b.global_paths == ["tests/b/**"]


class TestGitleaksAllowlistPerProject:
    """load_gitleaks_allowlist() caches per-project root."""

    def setup_method(self):
        from ai_guardian.gitleaks_config import reset_cache
        reset_cache()

    def test_separate_allowlists(self, tmp_path):
        from ai_guardian.gitleaks_config import load_gitleaks_allowlist, _cached_allowlists

        proj_a = tmp_path / "project_a"
        proj_b = tmp_path / "project_b"
        proj_a.mkdir()
        proj_b.mkdir()

        (proj_a / ".gitleaks.toml").write_text(
            '[allowlist]\npaths = ["vendor/**"]\n'
        )
        (proj_b / ".gitleaks.toml").write_text(
            '[allowlist]\npaths = ["third_party/**"]\n'
        )

        al_a = load_gitleaks_allowlist(project_root=proj_a)
        al_b = load_gitleaks_allowlist(project_root=proj_b)

        assert al_a is not None
        assert al_b is not None
        assert al_a.paths == ["vendor/**"]
        assert al_b.paths == ["third_party/**"]
        assert len(_cached_allowlists) == 2


class TestConfigLoadersPerProject:
    """_load_config_file() caches per-project path."""

    def setup_method(self):
        from ai_guardian.config_loaders import _clear_config_cache
        _clear_config_cache()

    def test_separate_project_configs(self, tmp_path, monkeypatch):
        from ai_guardian.config_loaders import _load_config_file, _caches

        proj_a = tmp_path / "project_a"
        proj_b = tmp_path / "project_b"
        proj_a.mkdir()
        proj_b.mkdir()

        config_a_dir = proj_a / ".ai-guardian"
        config_b_dir = proj_b / ".ai-guardian"
        config_a_dir.mkdir()
        config_b_dir.mkdir()

        import json
        (config_a_dir / "ai-guardian.json").write_text(
            json.dumps({"secret_scanning": {"action": "block"}})
        )
        (config_b_dir / "ai-guardian.json").write_text(
            json.dumps({"secret_scanning": {"action": "warn"}})
        )

        monkeypatch.setattr(
            "ai_guardian.config_loaders.get_project_config_path",
            lambda: config_a_dir / "ai-guardian.json",
        )
        result_a, _ = _load_config_file()

        monkeypatch.setattr(
            "ai_guardian.config_loaders.get_project_config_path",
            lambda: config_b_dir / "ai-guardian.json",
        )
        result_b, _ = _load_config_file()

        assert result_a["secret_scanning"]["action"] == "block"
        assert result_b["secret_scanning"]["action"] == "warn"
        assert len(_caches) >= 2


class TestStaleCleanup:
    """Stale cache entries are cleaned up."""

    def test_gitleaks_cleanup(self, tmp_path):
        from ai_guardian.gitleaks_config import (
            _project_roots, _cache_last_accessed, cleanup_stale_entries,
        )
        _project_roots.clear()
        _cache_last_accessed.clear()

        _project_roots[str(tmp_path)] = tmp_path
        _cache_last_accessed[str(tmp_path)] = time.monotonic() - 100000

        cleanup_stale_entries(max_age=86400.0)
        assert str(tmp_path) not in _project_roots
        assert str(tmp_path) not in _cache_last_accessed

    def test_aiguardignore_cleanup(self, tmp_path):
        from ai_guardian.aiguardignore import (
            _cached_configs, _cache_last_accessed, cleanup_stale_entries,
        )
        _cached_configs.clear()
        _cache_last_accessed.clear()

        _cached_configs[tmp_path] = (tmp_path / ".aiguardignore.toml", 0, None)
        _cache_last_accessed[tmp_path] = time.monotonic() - 100000

        cleanup_stale_entries(max_age=86400.0)
        assert tmp_path not in _cached_configs
        assert tmp_path not in _cache_last_accessed

    def test_config_loaders_cleanup(self):
        from ai_guardian.config_loaders import (
            _caches, _ConfigCacheEntry, cleanup_stale_entries,
        )
        _caches.clear()

        _caches["__stale__"] = _ConfigCacheEntry(
            result=(None, None), last_accessed=time.monotonic() - 100000,
        )

        cleanup_stale_entries(max_age=86400.0)
        assert "__stale__" not in _caches

    def test_fresh_entries_preserved(self, tmp_path):
        from ai_guardian.gitleaks_config import (
            _project_roots, _cache_last_accessed, cleanup_stale_entries,
        )
        _project_roots.clear()
        _cache_last_accessed.clear()

        _project_roots[str(tmp_path)] = tmp_path
        _cache_last_accessed[str(tmp_path)] = time.monotonic()

        cleanup_stale_entries(max_age=86400.0)
        assert str(tmp_path) in _project_roots

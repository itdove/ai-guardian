"""Tests for scoped config read/write/delete/provenance (Issue #1250)."""

import json
import os
from unittest import mock


class TestWriteScopedConfig:
    """Tests for write_scoped_config()."""

    def test_global_write(self, tmp_path):
        config_dir = tmp_path / "global_cfg"
        config_dir.mkdir()
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(config_dir)}):
            from ai_guardian.config_writer import write_scoped_config

            success, msg = write_scoped_config(
                "global", "secret_scanning", "action", "ask"
            )
            assert success
            cfg = json.loads((config_dir / "ai-guardian.json").read_text())
            assert cfg["secret_scanning"]["action"] == "ask"

    def test_project_write(self, tmp_path):
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        from ai_guardian.config_writer import write_scoped_config

        success, msg = write_scoped_config(
            "project",
            "secret_scanning",
            "action",
            "warn",
            project_dir=str(project_dir),
        )
        assert success
        cfg_path = project_dir / ".ai-guardian" / "ai-guardian.json"
        assert cfg_path.exists()
        cfg = json.loads(cfg_path.read_text())
        assert cfg["secret_scanning"]["action"] == "warn"

    def test_project_stores_only_override(self, tmp_path):
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        from ai_guardian.config_writer import write_scoped_config

        write_scoped_config(
            "project",
            "secret_scanning",
            "action",
            "ask",
            project_dir=str(project_dir),
        )
        cfg = json.loads(
            (project_dir / ".ai-guardian" / "ai-guardian.json").read_text()
        )
        assert cfg == {"secret_scanning": {"action": "ask"}}

    def test_rejects_global_only_sections(self, tmp_path):
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        from ai_guardian.config_writer import write_scoped_config

        success, msg = write_scoped_config(
            "project",
            "daemon",
            "enabled",
            True,
            project_dir=str(project_dir),
        )
        assert not success
        assert "global-only" in msg

    def test_auto_creates_project_dir(self, tmp_path):
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        from ai_guardian.config_writer import write_scoped_config

        success, _ = write_scoped_config(
            "project",
            "ssrf_protection",
            "action",
            "warn",
            project_dir=str(project_dir),
        )
        assert success
        assert (project_dir / ".ai-guardian" / "ai-guardian.json").exists()

    def test_set_entire_section(self, tmp_path):
        config_dir = tmp_path / "global_cfg"
        config_dir.mkdir()
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(config_dir)}):
            from ai_guardian.config_writer import write_scoped_config

            section_val = {"enabled": True, "action": "block"}
            success, _ = write_scoped_config(
                "global", "secret_scanning", None, section_val
            )
            assert success
            cfg = json.loads((config_dir / "ai-guardian.json").read_text())
            assert cfg["secret_scanning"] == section_val


class TestDeleteProjectOverride:
    """Tests for delete_project_override()."""

    def test_remove_key(self, tmp_path):
        project_dir = tmp_path / "project"
        ai_dir = project_dir / ".ai-guardian"
        ai_dir.mkdir(parents=True)
        cfg_path = ai_dir / "ai-guardian.json"
        cfg_path.write_text(
            json.dumps({"secret_scanning": {"action": "ask", "enabled": True}})
        )

        with mock.patch(
            "ai_guardian.config_writer.get_project_config_path",
            return_value=cfg_path,
        ):
            from ai_guardian.config_writer import delete_project_override

            success, msg = delete_project_override("secret_scanning", "action")
            assert success
            cfg = json.loads(cfg_path.read_text())
            assert "action" not in cfg["secret_scanning"]
            assert cfg["secret_scanning"]["enabled"] is True

    def test_remove_section(self, tmp_path):
        project_dir = tmp_path / "project"
        ai_dir = project_dir / ".ai-guardian"
        ai_dir.mkdir(parents=True)
        cfg_path = ai_dir / "ai-guardian.json"
        cfg_path.write_text(
            json.dumps(
                {
                    "secret_scanning": {"action": "ask"},
                    "ssrf_protection": {"action": "warn"},
                }
            )
        )

        with mock.patch(
            "ai_guardian.config_writer.get_project_config_path",
            return_value=cfg_path,
        ):
            from ai_guardian.config_writer import delete_project_override

            success, _ = delete_project_override("secret_scanning")
            assert success
            cfg = json.loads(cfg_path.read_text())
            assert "secret_scanning" not in cfg
            assert "ssrf_protection" in cfg

    def test_no_project_config(self, tmp_path):
        with (
            mock.patch(
                "ai_guardian.config_writer.get_project_config_path",
                return_value=None,
            ),
            mock.patch(
                "ai_guardian.config_writer._find_git_root",
                return_value=tmp_path,
            ),
        ):
            from ai_guardian.config_writer import delete_project_override

            success, msg = delete_project_override("secret_scanning", "action")
            assert success
            assert (
                "No project config" in msg
                or "nothing to remove" in msg.lower()
                or "already" in msg.lower()
            )

    def test_remove_last_key_cleans_section(self, tmp_path):
        project_dir = tmp_path / "project"
        ai_dir = project_dir / ".ai-guardian"
        ai_dir.mkdir(parents=True)
        cfg_path = ai_dir / "ai-guardian.json"
        cfg_path.write_text(json.dumps({"secret_scanning": {"action": "ask"}}))

        with mock.patch(
            "ai_guardian.config_writer.get_project_config_path",
            return_value=cfg_path,
        ):
            from ai_guardian.config_writer import delete_project_override

            success, _ = delete_project_override("secret_scanning", "action")
            assert success
            cfg = json.loads(cfg_path.read_text())
            assert "secret_scanning" not in cfg


class TestComputeProvenance:
    """Tests for compute_provenance()."""

    def test_global_only(self, tmp_path):
        config_dir = tmp_path / "global_cfg"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text(
            json.dumps(
                {
                    "secret_scanning": {"enabled": True, "action": "block"},
                }
            )
        )

        with (
            mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(config_dir)}),
            mock.patch(
                "ai_guardian.config_writer.get_project_config_path",
                return_value=None,
            ),
        ):
            from ai_guardian.config_writer import compute_provenance

            prov = compute_provenance()
            assert prov["secret_scanning"]["enabled"] == "global"
            assert prov["secret_scanning"]["action"] == "global"

    def test_project_override(self, tmp_path):
        config_dir = tmp_path / "global_cfg"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text(
            json.dumps(
                {
                    "secret_scanning": {"enabled": True, "action": "block"},
                }
            )
        )

        project_dir = tmp_path / "project"
        ai_dir = project_dir / ".ai-guardian"
        ai_dir.mkdir(parents=True)
        (ai_dir / "ai-guardian.json").write_text(
            json.dumps(
                {
                    "secret_scanning": {"action": "ask"},
                }
            )
        )

        with (
            mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(config_dir)}),
            mock.patch(
                "ai_guardian.config_writer.get_project_config_path",
                return_value=ai_dir / "ai-guardian.json",
            ),
        ):
            from ai_guardian.config_writer import compute_provenance

            prov = compute_provenance()
            assert prov["secret_scanning"]["action"] == "project"
            assert prov["secret_scanning"]["enabled"] == "global"

    def test_merged_lists(self, tmp_path):
        config_dir = tmp_path / "global_cfg"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text(
            json.dumps(
                {
                    "secret_scanning": {"allowlist_patterns": ["test.*"]},
                }
            )
        )

        project_dir = tmp_path / "project"
        ai_dir = project_dir / ".ai-guardian"
        ai_dir.mkdir(parents=True)
        (ai_dir / "ai-guardian.json").write_text(
            json.dumps(
                {
                    "secret_scanning": {"allowlist_patterns": ["dev.*"]},
                }
            )
        )

        with (
            mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(config_dir)}),
            mock.patch(
                "ai_guardian.config_writer.get_project_config_path",
                return_value=ai_dir / "ai-guardian.json",
            ),
        ):
            from ai_guardian.config_writer import compute_provenance

            prov = compute_provenance()
            assert prov["secret_scanning"]["allowlist_patterns"] == "merged"

    def test_project_only_section(self, tmp_path):
        config_dir = tmp_path / "global_cfg"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text(
            json.dumps(
                {
                    "secret_scanning": {"enabled": True},
                }
            )
        )

        project_dir = tmp_path / "project"
        ai_dir = project_dir / ".ai-guardian"
        ai_dir.mkdir(parents=True)
        (ai_dir / "ai-guardian.json").write_text(
            json.dumps(
                {
                    "scan_pii": {"action": "warn"},
                }
            )
        )

        with (
            mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(config_dir)}),
            mock.patch(
                "ai_guardian.config_writer.get_project_config_path",
                return_value=ai_dir / "ai-guardian.json",
            ),
        ):
            from ai_guardian.config_writer import compute_provenance

            prov = compute_provenance()
            assert prov["scan_pii"]["action"] == "project"
            assert prov["secret_scanning"]["enabled"] == "global"


class TestLoadScopedConfig:
    """Tests for load_scoped_config()."""

    def test_global_scope(self, tmp_path):
        config_dir = tmp_path / "global_cfg"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text(
            json.dumps(
                {
                    "secret_scanning": {"action": "block"},
                }
            )
        )
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_CONFIG_DIR": str(config_dir)}):
            from ai_guardian.config_writer import load_scoped_config

            cfg = load_scoped_config("global")
            assert cfg["secret_scanning"]["action"] == "block"

    def test_project_scope(self, tmp_path):
        project_dir = tmp_path / "project"
        ai_dir = project_dir / ".ai-guardian"
        ai_dir.mkdir(parents=True)
        (ai_dir / "ai-guardian.json").write_text(
            json.dumps(
                {
                    "secret_scanning": {"action": "ask"},
                }
            )
        )

        with mock.patch(
            "ai_guardian.config_writer.get_project_config_path",
            return_value=ai_dir / "ai-guardian.json",
        ):
            from ai_guardian.config_writer import load_scoped_config

            cfg = load_scoped_config("project")
            assert cfg["secret_scanning"]["action"] == "ask"

    def test_project_scope_missing(self, tmp_path):
        with (
            mock.patch(
                "ai_guardian.config_writer.get_project_config_path",
                return_value=None,
            ),
            mock.patch(
                "ai_guardian.config_writer._find_git_root",
                return_value=tmp_path,
            ),
        ):
            from ai_guardian.config_writer import load_scoped_config

            cfg = load_scoped_config("project")
            assert cfg == {}

    def test_invalid_scope(self):
        from ai_guardian.config_writer import load_scoped_config

        cfg = load_scoped_config("invalid")
        assert cfg == {}

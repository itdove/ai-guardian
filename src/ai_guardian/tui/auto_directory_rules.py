#!/usr/bin/env python3
"""
Auto Directory Rules Tab Content

Manage auto-generated directory rules from skill permissions.
Toggle enabled/allow_symlinks and view discovered rules (read-only).
"""

import logging
import json
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Switch

from ai_guardian.config.utils import get_config_dir, get_project_config_path


class AutoDirectoryRulesContent(Container):
    """Content widget for Auto Directory Rules tab."""

    CSS = """
    #auto-dir-header {
        margin: 1;
        padding: 1;
        background: $primary;
        color: $text;
    }

    #auto-dir-container {
        height: 100%;
        padding: 1 2;
    }

    #auto-dir-status {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    #auto-dir-settings {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    .settings-row {
        height: auto;
        margin: 0 0 1 0;
    }

    .settings-row Switch {
        margin: 0 1 0 0;
    }

    #auto-dir-rules-list {
        max-height: 20;
        margin: 1 0;
        border: solid $primary;
    }

    .rule-card {
        margin: 0 0 1 0;
        padding: 1;
        background: $panel;
        border: solid $success;
    }

    .rule-header {
        margin: 0 0 0 0;
    }

    .rule-path {
        margin: 0 0 0 2;
        color: $text-muted;
    }

    .skill-matched {
        color: $success;
    }

    .skill-unmatched {
        color: $text-muted;
    }

    #auto-dir-info {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the auto directory rules panel."""
        yield Static(
            "[bold]Auto Directory Rules[/bold]",
            id="auto-dir-header",
        )

        with Container(id="auto-dir-container"):
            # Settings card
            with Container(id="auto-dir-settings"):
                yield Static("[bold]Settings[/bold]")

                with Horizontal(classes="settings-row"):
                    yield Switch(value=False, id="switch-enabled")
                    yield Static(
                        "Enable Auto Directory Rules",
                        id="label-enabled",
                    )

                with Horizontal(classes="settings-row"):
                    yield Switch(value=True, id="switch-symlinks")
                    yield Static(
                        "Allow Symlinks",
                        id="label-symlinks",
                    )

            # Status card
            yield Static("", id="auto-dir-status")

            # Rules list
            yield VerticalScroll(id="auto-dir-rules-list")

            # Info card
            yield Static(
                "[bold]How Auto Directory Rules Work[/bold]\n\n"
                "When enabled, AI Guardian scans standard skill directories "
                "(Claude Code, Cursor, VSCode, Windsurf) for installed skills. "
                "Skills matching your Skill permission allow patterns get "
                "automatic directory access rules.\n\n"
                "Rule order: User rules -> Auto-generated -> Immutable "
                "(last-match-wins)",
                id="auto-dir-info",
            )

    @property
    def _is_project_scope(self) -> bool:
        try:
            return self.app.config_scope == "project"
        except Exception:
            return False

    def _get_config_path(self) -> Path:
        if self._is_project_scope:
            project_path = get_project_config_path()
            if project_path:
                return project_path
            from ai_guardian.config.utils import _find_git_root

            root = _find_git_root() or Path.cwd()
            return root / ".ai-guardian" / "ai-guardian.json"
        return get_config_dir() / "ai-guardian.json"

    def on_mount(self) -> None:
        """Load config on mount."""
        self.load_config()

    def refresh_content(self) -> None:
        """Called by parent app on navigation or refresh."""
        self.load_config()

    def load_config(self) -> None:
        """Load configuration and update display."""
        config_path = self._get_config_path()

        config = {}
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
            except Exception as e:
                logging.warning("Failed to read config: %s", e)

        permissions = config.get("permissions", {})
        auto_config = (
            permissions.get("auto_directory_rules", {})
            if isinstance(permissions, dict)
            else {}
        )
        is_enabled = auto_config.get("enabled", False)
        allow_symlinks = auto_config.get("allow_symlinks", True)

        # Update switches (suppress change events during load)
        sw_enabled = self.query_one("#switch-enabled", Switch)
        sw_symlinks = self.query_one("#switch-symlinks", Switch)

        # Temporarily unbind to prevent save during load
        self._loading = True
        sw_enabled.value = bool(is_enabled)
        sw_symlinks.value = bool(allow_symlinks)
        self._loading = False

        # Run generator preview
        discovery = self._run_generator(config)

        # Update status
        n_dirs = len(discovery["skill_dirs"])
        n_discovered = len(discovery["discovered_skills"])
        n_matched = len(discovery["matched_skills"])
        n_rules = len(discovery["generated_rules"])

        if is_enabled and n_rules > 0:
            status_icon = "[green]ACTIVE[/green]"
        elif is_enabled:
            status_icon = "[yellow]ENABLED[/yellow]"
        else:
            status_icon = "[dim]DISABLED[/dim]"

        status_text = (
            f"[bold]Status:[/bold] {status_icon}\n"
            f"  Directories scanned: {n_dirs}  |  "
            f"Skills discovered: {n_discovered}  |  "
            f"Skills matched: {n_matched}  |  "
            f"Rules generated: {n_rules}"
        )

        if discovery["skill_patterns"]:
            pats = ", ".join(discovery["skill_patterns"])
            status_text += f"\n  Skill patterns: {pats}"

        self.query_one("#auto-dir-status", Static).update(status_text)

        # Update rules list
        rules_list = self.query_one("#auto-dir-rules-list", VerticalScroll)
        rules_list.remove_children()

        if discovery["generated_rules"]:
            for idx, rule in enumerate(discovery["generated_rules"]):
                mode = rule.get("mode", "allow")
                source = rule.get("_source", "")
                paths = rule.get("paths", [])
                paths_text = "\n".join(f"    {p}" for p in paths)
                text = (
                    f"[bold][green]{mode.upper()}[/green] "
                    f"Rule #{idx}[/bold] "
                    f"[dim](auto-generated | {source})[/dim]\n"
                    f"{paths_text}"
                )
                rules_list.mount(Static(text, classes="rule-card"))
        elif discovery["discovered_skills"]:
            # Show discovered skills even if no rules generated
            skills_text = "[bold]Discovered Skills:[/bold]\n"
            for name in sorted(discovery["discovered_skills"].keys()):
                is_match = name in discovery["matched_skills"]
                icon = "[green]v[/green]" if is_match else "[dim]x[/dim]"
                color = "skill-matched" if is_match else "skill-unmatched"
                paths = discovery["discovered_skills"][name]
                path_info = ", ".join(paths)
                skills_text += f"  {icon} {name} ({path_info})\n"

            if not is_enabled:
                skills_text += (
                    "\n[dim]Enable auto directory rules to generate "
                    "rules for matched skills.[/dim]"
                )
            rules_list.mount(Static(skills_text))
        else:
            if not is_enabled:
                rules_list.mount(
                    Static(
                        "[dim]Enable auto directory rules to see "
                        "generated rules.[/dim]"
                    )
                )
            else:
                rules_list.mount(
                    Static(
                        "[dim]No skills discovered in standard "
                        "skill directories.[/dim]"
                    )
                )

    def _run_generator(self, config):
        """Run the DirectoryRuleGenerator in preview mode."""
        try:
            from ai_guardian.directory_rule_generator import (
                DirectoryRuleGenerator,
            )

            gen = DirectoryRuleGenerator(config)
            permissions = config.get("permissions", {})
            auto_config = permissions.get("auto_directory_rules", {})

            skill_patterns = gen._get_skill_patterns()
            skill_dirs = gen._get_skill_directories(auto_config)
            skill_dir_strs = [str(d) for d in skill_dirs]

            discovered = gen._discover_skills(skill_dirs) if skill_dirs else {}
            discovered_strs = {
                name: [str(p) for p in paths] for name, paths in discovered.items()
            }

            matched = (
                gen._match_skills(discovered, skill_patterns) if discovered else set()
            )

            generated = gen._create_directory_rules(matched) if matched else []

            return {
                "generated_rules": generated,
                "skill_dirs": skill_dir_strs,
                "discovered_skills": discovered_strs,
                "matched_skills": matched,
                "skill_patterns": skill_patterns,
            }
        except Exception:
            return {
                "generated_rules": [],
                "skill_dirs": [],
                "discovered_skills": {},
                "matched_skills": set(),
                "skill_patterns": [],
            }

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Handle switch toggles."""
        if getattr(self, "_loading", False):
            return

        switch_id = event.switch.id
        if switch_id == "switch-enabled":
            self._save_field("enabled", event.value)
            self.load_config()
        elif switch_id == "switch-symlinks":
            self._save_field("allow_symlinks", event.value)

    def _save_field(self, field: str, value) -> None:
        """Save a single auto_directory_rules field."""
        config_path = self._get_config_path()

        try:
            config = {}
            if config_path.exists():
                with open(config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)

            permissions = config.get("permissions", {})
            if not isinstance(permissions, dict):
                permissions = {"enabled": True, "rules": []}

            auto_config = permissions.get("auto_directory_rules", {})
            if not isinstance(auto_config, dict):
                auto_config = {}

            auto_config[field] = value
            permissions["auto_directory_rules"] = auto_config
            config["permissions"] = permissions

            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)

            label = field.replace("_", " ").title()
            self.app.notify(
                f"{label} {'enabled' if value else 'disabled'}",
                severity="information",
            )
        except Exception as e:
            self.app.notify(
                f"Error saving {field}: {e}",
                severity="error",
            )

    def action_refresh(self) -> None:
        """Refresh via keybinding."""
        self.load_config()
        self.app.notify("Refreshed", severity="information")

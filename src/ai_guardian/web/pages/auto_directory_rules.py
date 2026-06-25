"""Auto Directory Rules page — manage auto-generated directory rules from skill permissions.

Configures permissions.auto_directory_rules and shows a read-only preview
of the rules that would be generated based on the current skill permissions
and discovered skill directories.
"""

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config


def _run_generator(config):
    """Run the DirectoryRuleGenerator and return discovery results.

    Returns a dict with:
        generated_rules: list of generated rule dicts
        skill_dirs: list of scanned directory path strings
        discovered_skills: dict mapping skill name -> list of path strings
        matched_skills: set of skill names that matched permission patterns
        skill_patterns: list of permission patterns used for matching
    """
    try:
        from ai_guardian.directory_rule_generator import DirectoryRuleGenerator

        gen = DirectoryRuleGenerator(config)
        permissions = config.get("permissions", {})
        auto_config = permissions.get("auto_directory_rules", {})

        # Get skill patterns
        skill_patterns = gen._get_skill_patterns()

        # Get skill directories
        skill_dirs = gen._get_skill_directories(auto_config)
        skill_dir_strs = [str(d) for d in skill_dirs]

        # Discover skills
        discovered = gen._discover_skills(skill_dirs) if skill_dirs else {}
        discovered_strs = {
            name: [str(p) for p in paths] for name, paths in discovered.items()
        }

        # Match skills
        matched = gen._match_skills(discovered, skill_patterns) if discovered else set()

        # Generate rules
        generated = gen._create_directory_rules(matched) if matched else []

        return {
            "generated_rules": generated,
            "skill_dirs": skill_dir_strs,
            "discovered_skills": discovered_strs,
            "matched_skills": matched,
            "skill_patterns": skill_patterns,
            "error": None,
        }
    except Exception as e:
        return {
            "generated_rules": [],
            "skill_dirs": [],
            "discovered_skills": {},
            "matched_skills": set(),
            "skill_patterns": [],
            "error": str(e),
        }


def create_auto_directory_rules_page(service, daemon_name: str):
    """Create the Auto Directory Rules page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(
            daemon_name,
            current=f"/{daemon_name}/auto-directory-rules",
        )

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Auto Directory Rules").classes("text-2xl font-bold")
            ui.label(
                "Auto-generate directory access rules from skill permissions. "
                "Eliminates duplication between permission rules and directory rules."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(load_web_config)

                with content:
                    permissions = config.get("permissions", {})
                    auto_config = (
                        permissions.get("auto_directory_rules", {})
                        if isinstance(permissions, dict)
                        else {}
                    )
                    is_enabled = auto_config.get("enabled", False)
                    allow_symlinks = auto_config.get("allow_symlinks", True)

                    # --- Settings card ---
                    with ui.card().classes("w-full"):
                        ui.label("Settings").classes("text-lg font-bold")

                        # Enabled toggle
                        with ui.row().classes("items-center gap-2 w-full"):
                            sw_enabled = ui.switch(
                                "Enable Auto Directory Rules",
                                value=bool(is_enabled),
                            ).classes("flex-grow")

                            async def on_toggle_enabled(e):
                                cfg = await run.io_bound(load_web_config)
                                perms = cfg.get("permissions", {})
                                if not isinstance(perms, dict):
                                    perms = {"enabled": True, "rules": []}
                                adr = perms.get("auto_directory_rules", {})
                                if not isinstance(adr, dict):
                                    adr = {}
                                adr["enabled"] = e.value
                                perms["auto_directory_rules"] = adr
                                cfg["permissions"] = perms
                                await run.io_bound(save_web_config, cfg)
                                ui.notify(
                                    "Auto directory rules "
                                    f"{'enabled' if e.value else 'disabled'}",
                                    type="positive",
                                )
                                await refresh()

                            sw_enabled.on_value_change(on_toggle_enabled)

                        ui.label(
                            "When enabled, directory access rules are automatically "
                            "generated for skills that match your permission rules."
                        ).classes("text-xs text-grey-6 ml-8")

                        ui.separator().classes("my-2")

                        # Allow symlinks toggle
                        with ui.row().classes("items-center gap-2 w-full"):
                            sw_symlinks = ui.switch(
                                "Allow Symlinks",
                                value=bool(allow_symlinks),
                            ).classes("flex-grow")

                            async def on_toggle_symlinks(e):
                                cfg = await run.io_bound(load_web_config)
                                perms = cfg.get("permissions", {})
                                if not isinstance(perms, dict):
                                    perms = {"enabled": True, "rules": []}
                                adr = perms.get("auto_directory_rules", {})
                                if not isinstance(adr, dict):
                                    adr = {}
                                adr["allow_symlinks"] = e.value
                                perms["auto_directory_rules"] = adr
                                cfg["permissions"] = perms
                                await run.io_bound(save_web_config, cfg)
                                ui.notify(
                                    "Symlinks "
                                    f"{'allowed' if e.value else 'disallowed'}",
                                    type="positive",
                                )

                            sw_symlinks.on_value_change(on_toggle_symlinks)

                        ui.label(
                            "Follow symlinks when discovering skills. Useful in "
                            "container environments where skills are installed as "
                            "symlinks. Broken symlinks are always skipped."
                        ).classes("text-xs text-grey-6 ml-8")

                    # --- Run the generator to show preview ---
                    discovery = await run.io_bound(_run_generator, config)

                    if discovery["error"]:
                        with ui.card().classes("w-full"):
                            with ui.row().classes("items-center gap-2"):
                                ui.icon("error").classes("text-red")
                                ui.label("Error running generator").classes(
                                    "font-bold text-red"
                                )
                            ui.label(discovery["error"]).classes(
                                "text-xs text-grey-6 ml-8"
                            )

                    # --- Status card ---
                    n_dirs = len(discovery["skill_dirs"])
                    n_discovered = len(discovery["discovered_skills"])
                    n_matched = len(discovery["matched_skills"])
                    n_rules = len(discovery["generated_rules"])
                    n_patterns = len(discovery["skill_patterns"])

                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-2"):
                            if is_enabled and n_rules > 0:
                                ui.icon("check_circle").classes("text-green")
                                ui.label("ACTIVE").classes("font-bold text-green")
                            elif is_enabled:
                                ui.icon("info").classes("text-amber")
                                ui.label("ENABLED").classes("font-bold text-amber")
                            else:
                                ui.icon("cancel").classes("text-grey-6")
                                ui.label("DISABLED").classes("font-bold text-grey-6")

                        with ui.row().classes("gap-6 ml-8 mt-2"):
                            with ui.column().classes("gap-0"):
                                ui.label(str(n_dirs)).classes("text-2xl font-bold")
                                ui.label("Directories scanned").classes(
                                    "text-xs text-grey-6"
                                )
                            with ui.column().classes("gap-0"):
                                ui.label(str(n_discovered)).classes(
                                    "text-2xl font-bold"
                                )
                                ui.label("Skills discovered").classes(
                                    "text-xs text-grey-6"
                                )
                            with ui.column().classes("gap-0"):
                                ui.label(str(n_matched)).classes("text-2xl font-bold")
                                ui.label("Skills matched").classes(
                                    "text-xs text-grey-6"
                                )
                            with ui.column().classes("gap-0"):
                                ui.label(str(n_rules)).classes("text-2xl font-bold")
                                ui.label("Rules generated").classes(
                                    "text-xs text-grey-6"
                                )

                    # --- Skill patterns card ---
                    with ui.card().classes("w-full"):
                        ui.label("Skill Permission Patterns").classes(
                            "text-sm font-bold"
                        )
                        ui.label(
                            "Patterns from permissions.rules where "
                            "matcher=Skill and mode=allow."
                        ).classes("text-xs text-grey-6")
                        if discovery["skill_patterns"]:
                            for pat in discovery["skill_patterns"]:
                                with ui.row().classes("items-center gap-2"):
                                    ui.icon("pattern").classes("text-blue text-sm")
                                    ui.label(pat).classes("text-sm font-mono")
                        else:
                            ui.label(
                                "No Skill allow patterns found in " "permission rules."
                            ).classes("text-grey-6 text-sm")
                            ui.label(
                                "Add a permission rule with matcher='Skill' "
                                "and mode='allow' to see auto-generated "
                                "directory rules."
                            ).classes("text-xs text-grey-6")

                    # --- Scanned directories card ---
                    with ui.card().classes("w-full"):
                        ui.label("Scanned Directories").classes("text-sm font-bold")
                        ui.label("Directories checked for installed skills.").classes(
                            "text-xs text-grey-6"
                        )
                        if discovery["skill_dirs"]:
                            for d in discovery["skill_dirs"]:
                                with ui.row().classes("items-center gap-2"):
                                    ui.icon("folder").classes("text-amber text-sm")
                                    ui.label(d).classes("text-sm font-mono")
                        else:
                            ui.label("No skill directories found.").classes(
                                "text-grey-6 text-sm"
                            )

                    # --- Discovered skills card ---
                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-2"):
                            ui.label("Discovered Skills").classes("text-sm font-bold")
                            ui.label(
                                f"({n_discovered} total, " f"{n_matched} matched)"
                            ).classes("text-xs text-grey-6")

                        if discovery["discovered_skills"]:
                            for name in sorted(discovery["discovered_skills"].keys()):
                                paths = discovery["discovered_skills"][name]
                                is_match = name in discovery["matched_skills"]
                                with ui.row().classes("items-center gap-2"):
                                    if is_match:
                                        ui.icon("check").classes("text-green text-sm")
                                    else:
                                        ui.icon("close").classes("text-grey-6 text-sm")
                                    ui.label(name).classes(
                                        "text-sm font-bold"
                                        + (
                                            " text-green"
                                            if is_match
                                            else " text-grey-6"
                                        )
                                    )
                                    for p in paths:
                                        ui.label(p).classes(
                                            "text-xs text-grey-6 font-mono"
                                        )
                        else:
                            ui.label(
                                "No skills discovered in skill directories."
                            ).classes("text-grey-6 text-sm")

                    # --- Generated rules card ---
                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-2"):
                            ui.label("Generated Rules").classes("text-sm font-bold")
                            ui.badge("read-only", color="blue-grey").classes(
                                "text-xs"
                            ).props("outline")

                        ui.label(
                            "These directory rules are auto-generated when "
                            "enabled and inserted after user rules but before "
                            "immutable rules."
                        ).classes("text-xs text-grey-6")

                        if discovery["generated_rules"]:
                            for idx, rule in enumerate(discovery["generated_rules"]):
                                with (
                                    ui.card()
                                    .classes("w-full")
                                    .style("border-left: 3px solid #4caf50")
                                ):
                                    with ui.row().classes("items-center gap-2"):
                                        ui.badge(str(idx), color="blue-grey").classes(
                                            "text-xs"
                                        ).props("outline")
                                        ui.badge(
                                            rule.get("mode", "allow").upper(),
                                            color="green",
                                        ).classes("text-xs")
                                        ui.badge(
                                            "auto-generated",
                                            color="blue-grey",
                                        ).classes("text-xs").props("outline")
                                        source = rule.get("_source", "")
                                        if source:
                                            ui.label(source).classes(
                                                "text-xs text-grey-6"
                                            )

                                    paths = rule.get("paths", [])
                                    if paths:
                                        with (
                                            ui.expansion(
                                                f"Paths ({len(paths)})",
                                                value=len(paths) <= 10,
                                            )
                                            .classes("ml-4 w-full text-xs")
                                            .props("dense")
                                        ):
                                            for p in paths:
                                                ui.label(p).classes(
                                                    "text-xs text-grey-4 " "font-mono"
                                                )
                        else:
                            if not is_enabled:
                                ui.label(
                                    "Enable auto directory rules to see "
                                    "generated rules."
                                ).classes("text-grey-6 text-sm")
                            elif not discovery["skill_patterns"]:
                                ui.label(
                                    "No Skill allow patterns configured. "
                                    "Add permission rules first."
                                ).classes("text-grey-6 text-sm")
                            elif not discovery["matched_skills"]:
                                ui.label(
                                    "No discovered skills match your "
                                    "permission patterns."
                                ).classes("text-grey-6 text-sm")
                            else:
                                ui.label("No rules generated.").classes(
                                    "text-grey-6 text-sm"
                                )

                    # --- Info card ---
                    with ui.card().classes("w-full"):
                        ui.label("How Auto Directory Rules Work").classes(
                            "text-sm font-bold"
                        )
                        ui.label(
                            "When enabled, AI Guardian scans standard skill "
                            "directories (Claude Code, Cursor, VSCode, "
                            "Windsurf) for installed skills. Skills that "
                            "match your Skill permission allow patterns get "
                            "automatic directory access rules. This "
                            "eliminates the need to manually create matching "
                            "directory rules for each allowed skill."
                        ).classes("text-xs text-grey-6")
                        ui.label(
                            "Rule order: User rules -> Auto-generated rules "
                            "-> Immutable rules (last-match-wins)"
                        ).classes("text-xs text-grey-6 mt-1")

            ui.timer(0.1, refresh, once=True)

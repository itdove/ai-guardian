"""
Project initialization with language auto-discovery.

Detects programming languages in a project and generates a project-level
ai-guardian config with prompt injection allowlist patterns. Only generates
entries for identifiers that actually trigger the current detection patterns.

Usage:
    ai-guardian init-project              # Human-readable output
    ai-guardian init-project --dry-run    # Show without writing
    ai-guardian init-project --json       # Machine-readable JSON
    ai-guardian init-project --force      # Overwrite existing config
"""

import json
import logging
import os
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ai_guardian.language_patterns import (
    LANGUAGE_REGISTRY,
    SKIP_DIRS,
    LanguageDefinition,
)

logger = logging.getLogger(__name__)

MAX_SCAN_FILES = 10_000
MAX_SCAN_DEPTH = 20

HTML_EXTENSIONS = frozenset({".html", ".htm", ".xhtml"})
HTML_IGNORE_GLOBS = ["**/*.html", "**/*.htm", "**/*.xhtml"]


@dataclass
class DetectedLanguage:
    """A language detected in the project."""

    definition: LanguageDefinition
    matched_files: int = 0
    matched_configs: List[str] = field(default_factory=list)


@dataclass
class AllowlistEntry:
    """An allowlist pattern generated for a language identifier."""

    pattern: str
    language: str
    identifier: str


@dataclass
class InitResult:
    """Result of the init-project command."""

    project_dir: Path
    detected_languages: List[DetectedLanguage] = field(default_factory=list)
    allowlist_entries: List[AllowlistEntry] = field(default_factory=list)
    ignore_files_entries: List[str] = field(default_factory=list)
    config_path: Optional[Path] = None
    config_created: bool = False
    config_existed: bool = False
    dry_run: bool = False


class ProjectInitializer:
    """Detects languages and generates project-level ai-guardian config."""

    def __init__(self, project_dir: Optional[Path] = None):
        self.project_dir = Path(project_dir) if project_dir else Path.cwd()

    def detect_languages(self) -> List[DetectedLanguage]:
        ext_to_langs: Dict[str, List[LanguageDefinition]] = {}
        for lang in LANGUAGE_REGISTRY:
            for ext in lang.file_extensions:
                ext_to_langs.setdefault(ext, []).append(lang)

        found: Dict[str, DetectedLanguage] = {}
        files_scanned = 0

        for lang in LANGUAGE_REGISTRY:
            for cfg_file in lang.config_files:
                cfg_path = self.project_dir / cfg_file
                if cfg_path.is_file():
                    if lang.name not in found:
                        found[lang.name] = DetectedLanguage(definition=lang)
                    found[lang.name].matched_configs.append(cfg_file)

        for dirpath, dirnames, filenames in os.walk(self.project_dir):
            depth = Path(dirpath).relative_to(self.project_dir).parts
            if len(depth) > MAX_SCAN_DEPTH:
                dirnames.clear()
                continue

            dirnames[:] = [
                d for d in dirnames
                if d not in SKIP_DIRS and not d.endswith(".egg-info")
            ]

            for filename in filenames:
                files_scanned += 1
                if files_scanned > MAX_SCAN_FILES:
                    break

                ext = Path(filename).suffix.lower()
                if ext in ext_to_langs:
                    for lang in ext_to_langs[ext]:
                        if lang.name not in found:
                            found[lang.name] = DetectedLanguage(definition=lang)
                        found[lang.name].matched_files += 1

            if files_scanned > MAX_SCAN_FILES:
                break

        return sorted(found.values(), key=lambda d: d.definition.name)

    def generate_allowlist(
        self, languages: List[DetectedLanguage]
    ) -> Tuple[List[AllowlistEntry], List[str]]:
        from ai_guardian.prompt_injection import PromptInjectionDetector

        detector = PromptInjectionDetector({"enabled": True})

        entries: List[AllowlistEntry] = []
        seen_patterns: Set[str] = set()
        needs_html_ignore = False

        for lang in languages:
            for identifier in lang.definition.identifiers:
                _, _, detected_file = detector.detect(
                    identifier, source_type="file_content"
                )
                _, _, detected_prompt = detector.detect(
                    identifier, source_type="user_prompt"
                )

                if not (detected_file or detected_prompt):
                    continue

                if any(
                    identifier.startswith(tag)
                    for tag in ("<script", "<iframe", "<object", "<embed", "<img")
                ):
                    needs_html_ignore = True
                    continue

                if identifier not in seen_patterns:
                    seen_patterns.add(identifier)
                    entries.append(
                        AllowlistEntry(
                            pattern=identifier,
                            language=lang.definition.name,
                            identifier=identifier,
                        )
                    )

        ignore_files: List[str] = []
        if needs_html_ignore:
            has_html = any(
                ext in HTML_EXTENSIONS
                for lang in languages
                for ext in lang.definition.file_extensions
            )
            if has_html:
                ignore_files = list(HTML_IGNORE_GLOBS)

        return entries, ignore_files

    def generate_config(
        self,
        entries: List[AllowlistEntry],
        ignore_files: List[str],
    ) -> Dict:
        config: Dict = {}

        if entries or ignore_files:
            pi_config: Dict = {}
            if entries:
                pi_config["allowlist_patterns"] = [e.pattern for e in entries]
            if ignore_files:
                pi_config["ignore_files"] = ignore_files
            config["prompt_injection"] = pi_config

        return config

    def write_config(
        self,
        config: Dict,
        force: bool = False,
        dry_run: bool = False,
    ) -> Tuple[Path, bool, bool]:
        config_dir = self.project_dir / ".ai-guardian"
        config_path = config_dir / "ai-guardian.json"
        existed = config_path.is_file()

        if dry_run:
            return config_path, False, existed

        if existed and not force:
            return config_path, False, existed

        if existed and force:
            backup_path = config_path.with_suffix(".json.backup")
            shutil.copy2(config_path, backup_path)
            logger.info("Backed up existing config to %s", backup_path)

        config_dir.mkdir(parents=True, exist_ok=True)

        output = json.dumps(config, indent=2) + "\n"
        config_path.write_text(output, encoding="utf-8")

        return config_path, True, existed

    def run(
        self,
        force: bool = False,
        dry_run: bool = False,
    ) -> InitResult:
        result = InitResult(project_dir=self.project_dir, dry_run=dry_run)

        result.detected_languages = self.detect_languages()

        if not result.detected_languages:
            return result

        entries, ignore_files = self.generate_allowlist(result.detected_languages)
        result.allowlist_entries = entries
        result.ignore_files_entries = ignore_files

        config = self.generate_config(entries, ignore_files)

        if not config:
            return result

        config_path, created, existed = self.write_config(
            config, force=force, dry_run=dry_run
        )
        result.config_path = config_path
        result.config_created = created
        result.config_existed = existed

        return result


def _format_evidence(lang: DetectedLanguage) -> str:
    parts = []
    if lang.matched_configs:
        parts.append(", ".join(lang.matched_configs))
    if lang.matched_files > 0:
        ext_list = ", ".join(lang.definition.file_extensions[:3])
        parts.append(f"{lang.matched_files} {ext_list} files")
    return " | ".join(parts) if parts else "detected"


def _print_result(result: InitResult) -> None:
    print("AI Guardian Project Initializer")
    print("=" * 40)
    print()
    print(f"Scanning: {result.project_dir}")
    print()

    if not result.detected_languages:
        print("No programming languages detected.")
        print("Tip: Run from a project root containing source files.")
        return

    print("Detected languages:")
    for lang in result.detected_languages:
        evidence = _format_evidence(lang)
        print(f"  - {lang.definition.name} ({evidence})")
    print()

    if not result.allowlist_entries and not result.ignore_files_entries:
        print("No allowlist entries needed.")
        print("None of the detected languages' identifiers trigger")
        print("current prompt injection detection patterns.")
        return

    print("Generated entries:")
    if result.allowlist_entries:
        by_lang: Dict[str, List[AllowlistEntry]] = {}
        for entry in result.allowlist_entries:
            by_lang.setdefault(entry.language, []).append(entry)
        for lang_name, lang_entries in sorted(by_lang.items()):
            print(f"  {lang_name} allowlist_patterns:")
            for entry in lang_entries:
                print(f"    - {entry.pattern}")

    if result.ignore_files_entries:
        print("  prompt_injection.ignore_files:")
        for pattern in result.ignore_files_entries:
            print(f"    - {pattern}")
    print()

    if result.dry_run:
        print("[dry-run] Would write to:", result.config_path)
        return

    if result.config_existed and not result.config_created:
        print(f"Config already exists: {result.config_path}")
        print("Use --force to overwrite (creates .backup).")
        return

    if result.config_created:
        print(f"Created: {result.config_path}")
        count = len(result.allowlist_entries)
        ignore_count = len(result.ignore_files_entries)
        parts = []
        if count:
            parts.append(f"{count} allowlist pattern{'s' if count != 1 else ''}")
        if ignore_count:
            parts.append(f"{ignore_count} ignore_files entr{'ies' if ignore_count != 1 else 'y'}")
        print(f"  {', '.join(parts)}")


def _print_json(result: InitResult) -> None:
    output = {
        "project_dir": str(result.project_dir),
        "detected_languages": [
            {
                "name": lang.definition.name,
                "matched_files": lang.matched_files,
                "matched_configs": lang.matched_configs,
            }
            for lang in result.detected_languages
        ],
        "allowlist_entries": [
            {
                "pattern": e.pattern,
                "language": e.language,
                "identifier": e.identifier,
            }
            for e in result.allowlist_entries
        ],
        "ignore_files_entries": result.ignore_files_entries,
        "config_path": str(result.config_path) if result.config_path else None,
        "config_created": result.config_created,
        "config_existed": result.config_existed,
        "dry_run": result.dry_run,
    }
    print(json.dumps(output, indent=2))


def init_project_command(args) -> int:
    """CLI entry point for init-project command."""
    project_dir = Path(getattr(args, "dir", ".")).resolve()
    force = getattr(args, "force", False)
    dry_run = getattr(args, "dry_run", False)
    json_output = getattr(args, "json", False)

    if not project_dir.is_dir():
        print(f"Error: Not a directory: {project_dir}", file=sys.stderr)
        return 1

    initializer = ProjectInitializer(project_dir)
    result = initializer.run(force=force, dry_run=dry_run)

    if json_output:
        _print_json(result)
    else:
        _print_result(result)

    if result.config_existed and not result.config_created and not dry_run:
        return 1

    return 0

#!/usr/bin/env python3
"""
Directory Rule Generator

Auto-generates directory access rules from skill permissions.
Eliminates duplication by creating directory rules for allowed skills.

Rule generation:
1. Scans standard skill locations for skill directories
2. Matches skill names against permission patterns
3. Generates 'allow' directory rules for matching skills
4. Marks rules with _generated: true metadata
5. Rules inserted at BEGINNING of directory_rules.rules array

Rule order (last-match-wins):
  Generated → User → Immutable
  (User can override Generated, Immutable overrides all)
"""

import fnmatch
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class DirectoryRuleGenerator:
    """Generate directory rules from skill permissions."""

    def __init__(self, config: Dict):
        """
        Initialize generator.

        Args:
            config: Full AI Guardian configuration
        """
        self.config = config

    def generate_directory_rules(self) -> List[Dict]:
        """
        Generate directory rules from skill permissions.

        Returns:
            List of directory rule dictionaries with _generated: true metadata.
            These should be inserted at the BEGINNING of directory_rules.rules.
        """
        # Check if auto-generation is enabled
        permissions = self.config.get("permissions", {})
        auto_config = permissions.get("auto_directory_rules", {})

        if not auto_config.get("enabled", False):
            logger.debug("Auto-generation disabled")
            return []

        # Get skill permission patterns
        skill_patterns = self._get_skill_patterns()
        if not skill_patterns:
            logger.debug("No skill permission patterns found")
            return []

        # Get skill directories to scan
        skill_dirs = self._get_skill_directories(auto_config)
        if not skill_dirs:
            logger.debug("No skill directories to scan")
            return []

        # Scan directories for skills
        discovered_skills = self._discover_skills(skill_dirs)
        if not discovered_skills:
            logger.debug("No skills discovered in skill directories")
            return []

        # Match skills against patterns
        matching_skills = self._match_skills(discovered_skills, skill_patterns)
        if not matching_skills:
            logger.debug("No skills matched permission patterns")
            return []

        # Generate directory rules
        generated_rules = self._create_directory_rules(matching_skills)

        logger.info(f"Generated {len(generated_rules)} directory rules from skill permissions")
        return generated_rules

    def _get_allow_symlinks(self) -> bool:
        """Return whether symlinks should be followed during skill discovery."""
        permissions = self.config.get("permissions", {})
        auto_config = permissions.get("auto_directory_rules", {})
        return auto_config.get("allow_symlinks", True)

    def _get_skill_patterns(self) -> List[str]:
        """
        Extract skill permission patterns from config.

        Returns:
            List of allow patterns for Skill matcher
        """
        patterns = []

        permissions = self.config.get("permissions", {})
        rules = permissions.get("rules", [])

        for rule in rules:
            matcher = rule.get("matcher")
            mode = rule.get("mode")

            # Only process allow rules for Skill matcher
            if matcher == "Skill" and mode == "allow":
                rule_patterns = rule.get("patterns", [])
                for pattern_entry in rule_patterns:
                    # Extract pattern string (supports both str and dict formats)
                    if isinstance(pattern_entry, str):
                        patterns.append(pattern_entry)
                    elif isinstance(pattern_entry, dict):
                        pattern = pattern_entry.get("pattern")
                        if pattern:
                            patterns.append(pattern)

        logger.debug(f"Found {len(patterns)} skill permission patterns: {patterns}")
        return patterns

    def _validate_env_path(self, env_var_name: str, path_str: str) -> Optional[Path]:
        """
        Validate environment variable path for security.

        Prevents path traversal attacks by rejecting paths with suspicious patterns.
        Allows absolute paths for flexibility in testing and deployment.

        Args:
            env_var_name: Name of environment variable (for logging)
            path_str: Path string from environment variable

        Returns:
            Validated Path object or None if validation fails
        """
        try:
            # Check for path traversal patterns before resolution
            if ".." in path_str:
                logger.warning(
                    f"Rejecting {env_var_name}={path_str}: "
                    f"Path contains traversal sequence '..'"
                )
                return None

            path = Path(path_str).resolve()

            # Ensure path is absolute after resolution
            if not path.is_absolute():
                logger.warning(
                    f"Rejecting {env_var_name}={path_str}: Path must be absolute"
                )
                return None

            return path
        except Exception as e:
            logger.warning(f"Invalid path from {env_var_name}={path_str}: {e}")
            return None

    def _get_skill_directories(self, auto_config: Dict) -> List[Path]:
        """
        Get list of skill directories to scan.

        Supports multiple IDE agents:
        - Claude Code: ./.claude/skills, ~/.claude/skills, $CLAUDE_CONFIG_DIR/skills
        - Claude Code plugins: ~/.claude/plugins/cache/*/*/*/skills
        - Cursor: ./.cursor/skills, ~/.cursor/skills
        - VSCode/Copilot: ./.vscode/skills, ~/.vscode/skills
        - Windsurf: ./.windsurf/skills, ~/.windsurf/skills

        Args:
            auto_config: auto_directory_rules configuration

        Returns:
            List of directory paths that exist
        """
        skill_dirs_config = auto_config.get("skill_directories", "auto")

        if skill_dirs_config == "auto":
            # Standard locations for all supported IDEs
            candidate_dirs = [
                # Project-local directories
                Path("./.claude/skills"),
                Path("./.cursor/skills"),
                Path("./.vscode/skills"),
                Path("./.windsurf/skills"),

                # User home directories
                Path.home() / ".claude" / "skills",
                Path.home() / ".cursor" / "skills",
                Path.home() / ".vscode" / "skills",
                Path.home() / ".windsurf" / "skills",
            ]

            # Plugin cache directories (skills installed via plugins)
            # Structure: ~/.claude/plugins/cache/<marketplace>/<plugin>/<hash>/skills/
            plugin_cache = Path.home() / ".claude" / "plugins" / "cache"
            if plugin_cache.is_dir():
                try:
                    for skills_dir in plugin_cache.glob("*/*/*/skills"):
                        if skills_dir.is_dir():
                            candidate_dirs.append(skills_dir)
                except Exception as e:
                    logger.warning(f"Error scanning plugin cache {plugin_cache}: {e}")

            # Add IDE-specific config directories from environment
            # Claude Code
            claude_config = os.environ.get("CLAUDE_CONFIG_DIR")
            if claude_config:
                validated = self._validate_env_path("CLAUDE_CONFIG_DIR", claude_config)
                if validated:
                    candidate_dirs.append(validated / "skills")

            # Cursor (uses CURSOR_PROJECT_PATH for project root)
            cursor_project = os.environ.get("CURSOR_PROJECT_PATH")
            if cursor_project:
                validated = self._validate_env_path("CURSOR_PROJECT_PATH", cursor_project)
                if validated:
                    candidate_dirs.append(validated / ".cursor" / "skills")

            # VSCode/Copilot
            vscode_cwd = os.environ.get("VSCODE_CWD")
            if vscode_cwd:
                validated = self._validate_env_path("VSCODE_CWD", vscode_cwd)
                if validated:
                    candidate_dirs.append(validated / ".vscode" / "skills")
        elif isinstance(skill_dirs_config, list):
            candidate_dirs = [Path(d) for d in skill_dirs_config]
        else:
            logger.warning(f"Invalid skill_directories config: {skill_dirs_config}")
            return []

        # Filter to existing directories
        existing_dirs = [d for d in candidate_dirs if d.exists() and d.is_dir()]

        logger.debug(f"Scanning {len(existing_dirs)} skill directories: {existing_dirs}")
        return existing_dirs

    def _discover_skills(self, skill_dirs: List[Path]) -> Dict[str, List[Path]]:
        """
        Discover skills in directories.

        Args:
            skill_dirs: List of directories to scan

        Returns:
            Dict mapping skill names to list of full paths
            Example: {"daf-git": [Path("~/.claude/skills/daf-git")], ...}
        """
        skills = {}
        allow_symlinks = self._get_allow_symlinks()

        for skill_dir in skill_dirs:
            try:
                for item in skill_dir.iterdir():
                    if item.is_symlink():
                        if not allow_symlinks:
                            logger.warning(f"Skipping symlink in skill directory: {item}")
                            continue
                        if not item.resolve().is_dir():
                            logger.warning(f"Skipping broken symlink in skill directory: {item}")
                            continue

                    if item.is_dir():
                        skill_name = item.name

                        if skill_name.startswith(".") or skill_name.startswith("__"):
                            continue

                        if skill_name not in skills:
                            skills[skill_name] = []
                        skills[skill_name].append(item)

            except Exception as e:
                logger.warning(f"Error scanning {skill_dir}: {e}")

        logger.debug(f"Discovered {len(skills)} unique skills")
        return skills

    def _match_skills(
        self,
        discovered_skills: Dict[str, List[Path]],
        patterns: List[str]
    ) -> Set[str]:
        """
        Match discovered skills against permission patterns.

        Args:
            discovered_skills: Dict of skill names to paths
            patterns: List of fnmatch patterns (e.g., ["daf-*", "gh-cli"])

        Returns:
            Set of skill names that match any pattern
        """
        matching = set()

        for skill_name in discovered_skills.keys():
            for pattern in patterns:
                if fnmatch.fnmatch(skill_name, pattern):
                    matching.add(skill_name)
                    logger.debug(f"Skill '{skill_name}' matches pattern '{pattern}'")
                    break

        logger.debug(f"Matched {len(matching)} skills against patterns")
        return matching

    def _create_directory_rules(self, skill_names: Set[str]) -> List[Dict]:
        """
        Create directory rules for matched skills.

        Args:
            skill_names: Set of skill names to create rules for

        Returns:
            List of directory rule dictionaries
        """
        # Group skills by directory location
        skill_locations = self._group_skills_by_location(skill_names)

        # Create one rule per location
        rules = []
        for location, skills in skill_locations.items():
            # Generate paths for all skills in this location
            paths = []
            for skill_name in sorted(skills):
                # Use ** for recursive matching
                path = f"{location}/{skill_name}/**"
                paths.append(path)

            # Create rule
            rule = {
                "mode": "allow",
                "paths": paths,
                "_generated": True,
                "_source": "permissions.rules[Skill]"
            }
            rules.append(rule)

        return rules

    def _group_skills_by_location(self, skill_names: Set[str]) -> Dict[str, Set[str]]:
        """
        Group skill names by their directory location.

        Args:
            skill_names: Set of skill names

        Returns:
            Dict mapping location to set of skill names in that location
            Example: {"~/.claude/skills": {"daf-git", "daf-jira"}, ...}
        """
        # Get skill directories
        permissions = self.config.get("permissions", {})
        auto_config = permissions.get("auto_directory_rules", {})
        skill_dirs = self._get_skill_directories(auto_config)

        locations = {}
        allow_symlinks = self._get_allow_symlinks()

        for skill_dir in skill_dirs:
            skills_in_dir = set()

            try:
                for item in skill_dir.iterdir():
                    if item.is_symlink() and not allow_symlinks:
                        continue
                    if item.is_symlink() and not item.resolve().is_dir():
                        continue
                    if item.is_dir() and item.name in skill_names:
                        skills_in_dir.add(item.name)
            except Exception as e:
                logger.warning(f"Error scanning {skill_dir}: {e}")

            if skills_in_dir:
                # Normalize path (use ~ for home directory)
                location = str(skill_dir)
                home = str(Path.home())
                if location.startswith(home):
                    location = location.replace(home, "~", 1)

                locations[location] = skills_in_dir

        return locations


def insert_generated_rules(
    config: Dict,
    generated_rules: List[Dict]
) -> Dict:
    """
    Insert generated rules at the BEGINNING of directory_rules.rules.

    Rule order (last-match-wins):
      Position 0-N: Generated rules (weakest - can be overridden)
      Position N+1+: User rules (override generated)
      Final positions: Immutable rules (strongest - override all)

    Args:
        config: Full configuration dict
        generated_rules: List of generated directory rules

    Returns:
        Modified configuration with generated rules inserted
    """
    if not generated_rules:
        return config

    # Get or create directory_rules section
    directory_rules = config.get("directory_rules", {})

    # Handle both old array format and new object format
    if isinstance(directory_rules, dict):
        existing_rules = directory_rules.get("rules", [])
        # Insert generated rules at BEGINNING
        merged_rules = generated_rules + existing_rules
        directory_rules["rules"] = merged_rules
        config["directory_rules"] = directory_rules
    elif isinstance(directory_rules, list):
        # Old array format - convert to new format
        merged_rules = generated_rules + directory_rules
        config["directory_rules"] = {
            "action": "block",
            "rules": merged_rules
        }
    else:
        # Create new directory_rules section
        config["directory_rules"] = {
            "action": "block",
            "rules": generated_rules
        }

    logger.info(f"Inserted {len(generated_rules)} generated rules at beginning of directory_rules")
    return config

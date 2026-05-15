"""
Language identifier database for init-project command.

Maps programming languages to file extensions, config files, and
identifiers that may trigger false positives in prompt injection detection.

The init-project command tests these identifiers against the live detector
and only generates allowlist entries for ones that actually trigger.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class LanguageDefinition:
    """A programming language with its detection signals and known identifiers."""

    name: str
    file_extensions: List[str]
    config_files: List[str] = field(default_factory=list)
    identifiers: List[str] = field(default_factory=list)


SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__", ".pytest_cache",
    ".venv", "venv", ".env", "env", ".tox", ".nox",
    "dist", "build", ".build", "target", "out",
    ".ai-guardian", ".claude", ".cursor",
    "vendor", "bower_components",
    ".mypy_cache", ".ruff_cache",
    ".eggs", "*.egg-info",
})


LANGUAGE_REGISTRY: List[LanguageDefinition] = [
    LanguageDefinition(
        name="Python",
        file_extensions=[".py", ".pyw", ".pyi"],
        config_files=["pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "requirements.txt"],
        identifiers=[
            "__init__",
            "__import__",
            "__class__",
            "__globals__",
            "__builtins__",
            "__mro__",
            "__subclasses__",
        ],
    ),
    LanguageDefinition(
        name="JavaScript",
        file_extensions=[".js", ".jsx", ".mjs", ".cjs"],
        config_files=["package.json"],
        identifiers=[
            "<script>",
            "<script src=\"app.js\">",
        ],
    ),
    LanguageDefinition(
        name="TypeScript",
        file_extensions=[".ts", ".tsx"],
        config_files=["tsconfig.json"],
        identifiers=[
            "<script>",
        ],
    ),
    LanguageDefinition(
        name="HTML",
        file_extensions=[".html", ".htm", ".xhtml"],
        config_files=[],
        identifiers=[
            "<script>",
            "<iframe>",
            "<object>",
            "<embed>",
        ],
    ),
    LanguageDefinition(
        name="PHP",
        file_extensions=[".php", ".phtml"],
        config_files=["composer.json"],
        identifiers=[
            "__CLASS__",
            "__construct",
            "__destruct",
            "__METHOD__",
            "__FUNCTION__",
        ],
    ),
    LanguageDefinition(
        name="Ruby",
        file_extensions=[".rb", ".rake"],
        config_files=["Gemfile", "Rakefile"],
        identifiers=[
            "__method__",
            "__dir__",
            "__FILE__",
            "__LINE__",
            "__ENCODING__",
        ],
    ),
    LanguageDefinition(
        name="C/C++",
        file_extensions=[".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"],
        config_files=["CMakeLists.txt", "Makefile"],
        identifiers=[
            "__FILE__",
            "__LINE__",
            "__func__",
            "__DATE__",
            "__TIME__",
            "__STDC__",
        ],
    ),
    LanguageDefinition(
        name="Go",
        file_extensions=[".go"],
        config_files=["go.mod", "go.sum"],
        identifiers=[],
    ),
    LanguageDefinition(
        name="Rust",
        file_extensions=[".rs"],
        config_files=["Cargo.toml", "Cargo.lock"],
        identifiers=[],
    ),
    LanguageDefinition(
        name="Java",
        file_extensions=[".java"],
        config_files=["pom.xml", "build.gradle", "build.gradle.kts"],
        identifiers=[],
    ),
    LanguageDefinition(
        name="Kotlin",
        file_extensions=[".kt", ".kts"],
        config_files=["build.gradle.kts"],
        identifiers=[],
    ),
    LanguageDefinition(
        name="Swift",
        file_extensions=[".swift"],
        config_files=["Package.swift"],
        identifiers=[],
    ),
    LanguageDefinition(
        name="Scala",
        file_extensions=[".scala", ".sc"],
        config_files=["build.sbt"],
        identifiers=[],
    ),
    LanguageDefinition(
        name="CSS",
        file_extensions=[".css", ".scss", ".sass", ".less"],
        config_files=[],
        identifiers=[],
    ),
    LanguageDefinition(
        name="Shell",
        file_extensions=[".sh", ".bash", ".zsh"],
        config_files=[],
        identifiers=[],
    ),
]

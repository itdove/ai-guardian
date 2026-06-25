"""Tests for ai-guardian init-project command."""

import json


from ai_guardian.language_patterns import (
    LANGUAGE_REGISTRY,
    SKIP_DIRS,
    LanguageDefinition,
)
from ai_guardian.project_init import (
    AllowlistEntry,
    DetectedLanguage,
    ProjectInitializer,
    _format_evidence,
    init_project_command,
)


class TestLanguagePatterns:
    """Tests for language_patterns.py data module."""

    def test_registry_has_languages(self):
        assert len(LANGUAGE_REGISTRY) > 0

    def test_python_in_registry(self):
        python = next(l for l in LANGUAGE_REGISTRY if l.name == "Python")
        assert ".py" in python.file_extensions
        assert "pyproject.toml" in python.config_files
        assert "__init__" in python.identifiers

    def test_all_languages_have_names(self):
        for lang in LANGUAGE_REGISTRY:
            assert lang.name
            assert len(lang.file_extensions) > 0

    def test_skip_dirs_includes_common(self):
        assert ".git" in SKIP_DIRS
        assert "node_modules" in SKIP_DIRS
        assert "__pycache__" in SKIP_DIRS


class TestDetectLanguages:
    """Tests for ProjectInitializer.detect_languages()."""

    def test_detect_python_from_py_files(self, tmp_path):
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("def foo(): pass")

        init = ProjectInitializer(tmp_path)
        languages = init.detect_languages()

        names = [l.definition.name for l in languages]
        assert "Python" in names
        python = next(l for l in languages if l.definition.name == "Python")
        assert python.matched_files == 2

    def test_detect_python_from_config(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'")

        init = ProjectInitializer(tmp_path)
        languages = init.detect_languages()

        names = [l.definition.name for l in languages]
        assert "Python" in names
        python = next(l for l in languages if l.definition.name == "Python")
        assert "pyproject.toml" in python.matched_configs

    def test_detect_javascript_from_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "test"}')

        init = ProjectInitializer(tmp_path)
        languages = init.detect_languages()

        names = [l.definition.name for l in languages]
        assert "JavaScript" in names

    def test_detect_multiple_languages(self, tmp_path):
        (tmp_path / "app.py").write_text("")
        (tmp_path / "main.go").write_text("")
        (tmp_path / "index.js").write_text("")

        init = ProjectInitializer(tmp_path)
        languages = init.detect_languages()

        names = [l.definition.name for l in languages]
        assert "Python" in names
        assert "Go" in names
        assert "JavaScript" in names

    def test_empty_project(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        languages = init.detect_languages()
        assert languages == []

    def test_skip_git_directory(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config.py").write_text("")

        init = ProjectInitializer(tmp_path)
        languages = init.detect_languages()
        assert languages == []

    def test_skip_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "lodash.js").write_text("")
        (tmp_path / "app.py").write_text("")

        init = ProjectInitializer(tmp_path)
        languages = init.detect_languages()

        names = [l.definition.name for l in languages]
        assert "Python" in names
        js = [l for l in languages if l.definition.name == "JavaScript"]
        assert not js or all(l.matched_files == 0 for l in js)

    def test_detect_html(self, tmp_path):
        (tmp_path / "index.html").write_text("<html></html>")

        init = ProjectInitializer(tmp_path)
        languages = init.detect_languages()

        names = [l.definition.name for l in languages]
        assert "HTML" in names

    def test_sorted_by_name(self, tmp_path):
        (tmp_path / "main.go").write_text("")
        (tmp_path / "app.py").write_text("")
        (tmp_path / "index.js").write_text("")

        init = ProjectInitializer(tmp_path)
        languages = init.detect_languages()

        names = [l.definition.name for l in languages]
        assert names == sorted(names)


class TestGenerateAllowlist:
    """Tests for ProjectInitializer.generate_allowlist()."""

    def test_python_generates_entries(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        python_def = next(l for l in LANGUAGE_REGISTRY if l.name == "Python")
        languages = [DetectedLanguage(definition=python_def, matched_files=10)]

        entries, ignore_files = init.generate_allowlist(languages)

        patterns = [e.pattern for e in entries]
        assert "__init__" in patterns
        assert "__class__" in patterns
        assert "__import__" in patterns
        assert "__globals__" in patterns
        assert "__builtins__" in patterns
        assert "__mro__" in patterns
        assert "__subclasses__" in patterns

    def test_c_cpp_generates_no_entries(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        c_def = next(l for l in LANGUAGE_REGISTRY if l.name == "C/C++")
        languages = [DetectedLanguage(definition=c_def, matched_files=5)]

        entries, ignore_files = init.generate_allowlist(languages)

        assert entries == []
        assert ignore_files == []

    def test_go_generates_no_entries(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        go_def = next(l for l in LANGUAGE_REGISTRY if l.name == "Go")
        languages = [DetectedLanguage(definition=go_def, matched_files=5)]

        entries, ignore_files = init.generate_allowlist(languages)

        assert entries == []

    def test_html_generates_ignore_files(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        html_def = next(l for l in LANGUAGE_REGISTRY if l.name == "HTML")
        languages = [DetectedLanguage(definition=html_def, matched_files=3)]

        entries, ignore_files = init.generate_allowlist(languages)

        assert len(ignore_files) > 0
        assert "**/*.html" in ignore_files

    def test_deduplication(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        python_def = next(l for l in LANGUAGE_REGISTRY if l.name == "Python")
        languages = [
            DetectedLanguage(definition=python_def, matched_files=10),
            DetectedLanguage(definition=python_def, matched_files=5),
        ]

        entries, _ = init.generate_allowlist(languages)

        patterns = [e.pattern for e in entries]
        assert len(patterns) == len(set(patterns))

    def test_entries_have_language_info(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        python_def = next(l for l in LANGUAGE_REGISTRY if l.name == "Python")
        languages = [DetectedLanguage(definition=python_def, matched_files=10)]

        entries, _ = init.generate_allowlist(languages)

        for entry in entries:
            assert entry.language == "Python"
            assert entry.identifier


class TestGenerateConfig:
    """Tests for ProjectInitializer.generate_config()."""

    def test_generates_valid_structure(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        entries = [
            AllowlistEntry(
                pattern="__init__", language="Python", identifier="__init__"
            ),
        ]

        config = init.generate_config(entries, [])

        assert "prompt_injection" in config
        assert "allowlist_patterns" in config["prompt_injection"]
        assert "__init__" in config["prompt_injection"]["allowlist_patterns"]

    def test_includes_ignore_files(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        config = init.generate_config([], ["**/*.html"])

        assert "prompt_injection" in config
        assert "ignore_files" in config["prompt_injection"]
        assert "**/*.html" in config["prompt_injection"]["ignore_files"]

    def test_empty_when_nothing_needed(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        config = init.generate_config([], [])

        assert config == {}

    def test_config_is_json_serializable(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        entries = [
            AllowlistEntry(
                pattern="__init__", language="Python", identifier="__init__"
            ),
            AllowlistEntry(
                pattern="__class__", language="Python", identifier="__class__"
            ),
        ]

        config = init.generate_config(entries, ["**/*.html"])
        output = json.dumps(config)
        parsed = json.loads(output)
        assert parsed == config


class TestWriteConfig:
    """Tests for ProjectInitializer.write_config()."""

    def test_creates_directory_and_file(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        config = {"prompt_injection": {"allowlist_patterns": ["__init__"]}}

        path, created, existed = init.write_config(config)

        assert created is True
        assert existed is False
        assert path.is_file()
        assert (tmp_path / ".ai-guardian").is_dir()

        content = json.loads(path.read_text())
        assert content == config

    def test_refuses_overwrite_without_force(self, tmp_path):
        config_dir = tmp_path / ".ai-guardian"
        config_dir.mkdir()
        config_path = config_dir / "ai-guardian.json"
        config_path.write_text('{"existing": true}')

        init = ProjectInitializer(tmp_path)
        config = {"prompt_injection": {"allowlist_patterns": ["__init__"]}}

        path, created, existed = init.write_config(config)

        assert created is False
        assert existed is True
        assert json.loads(config_path.read_text()) == {"existing": True}

    def test_overwrites_with_force(self, tmp_path):
        config_dir = tmp_path / ".ai-guardian"
        config_dir.mkdir()
        config_path = config_dir / "ai-guardian.json"
        config_path.write_text('{"existing": true}')

        init = ProjectInitializer(tmp_path)
        config = {"prompt_injection": {"allowlist_patterns": ["__init__"]}}

        path, created, existed = init.write_config(config, force=True)

        assert created is True
        assert existed is True
        assert json.loads(config_path.read_text()) == config

    def test_force_creates_backup(self, tmp_path):
        config_dir = tmp_path / ".ai-guardian"
        config_dir.mkdir()
        config_path = config_dir / "ai-guardian.json"
        config_path.write_text('{"existing": true}')

        init = ProjectInitializer(tmp_path)
        init.write_config({"new": True}, force=True)

        backup = config_dir / "ai-guardian.json.backup"
        assert backup.is_file()
        assert json.loads(backup.read_text()) == {"existing": True}

    def test_dry_run_does_not_write(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        config = {"prompt_injection": {"allowlist_patterns": ["__init__"]}}

        path, created, existed = init.write_config(config, dry_run=True)

        assert created is False
        assert not (tmp_path / ".ai-guardian").exists()


class TestRunPipeline:
    """Tests for ProjectInitializer.run() end-to-end."""

    def test_python_project(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'")
        (tmp_path / "app.py").write_text("class Foo:\n    def __init__(self): pass")

        init = ProjectInitializer(tmp_path)
        result = init.run()

        assert result.config_created is True
        names = [l.definition.name for l in result.detected_languages]
        assert "Python" in names
        patterns = [e.pattern for e in result.allowlist_entries]
        assert "__init__" in patterns

        config_path = tmp_path / ".ai-guardian" / "ai-guardian.json"
        assert config_path.is_file()
        config = json.loads(config_path.read_text())
        assert "__init__" in config["prompt_injection"]["allowlist_patterns"]

    def test_go_project_no_config_needed(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/test")
        (tmp_path / "main.go").write_text("package main")

        init = ProjectInitializer(tmp_path)
        result = init.run()

        names = [l.definition.name for l in result.detected_languages]
        assert "Go" in names
        assert result.allowlist_entries == []
        assert result.config_created is False

    def test_empty_project(self, tmp_path):
        init = ProjectInitializer(tmp_path)
        result = init.run()

        assert result.detected_languages == []
        assert result.config_created is False

    def test_dry_run(self, tmp_path):
        (tmp_path / "app.py").write_text("")

        init = ProjectInitializer(tmp_path)
        result = init.run(dry_run=True)

        assert result.dry_run is True
        assert not (tmp_path / ".ai-guardian").exists()

    def test_html_project_ignore_files(self, tmp_path):
        (tmp_path / "index.html").write_text("<html><script>alert(1)</script></html>")
        (tmp_path / "page.htm").write_text("<html></html>")

        init = ProjectInitializer(tmp_path)
        result = init.run()

        assert len(result.ignore_files_entries) > 0
        assert "**/*.html" in result.ignore_files_entries

    def test_mixed_project(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'")
        (tmp_path / "app.py").write_text("")
        (tmp_path / "go.mod").write_text("module test")
        (tmp_path / "main.go").write_text("")
        (tmp_path / "index.html").write_text("<html></html>")

        init = ProjectInitializer(tmp_path)
        result = init.run()

        names = [l.definition.name for l in result.detected_languages]
        assert "Python" in names
        assert "Go" in names
        assert "HTML" in names
        assert result.config_created is True
        patterns = [e.pattern for e in result.allowlist_entries]
        assert "__init__" in patterns


class TestFormatEvidence:
    """Tests for _format_evidence helper."""

    def test_config_and_files(self):
        lang_def = LanguageDefinition(
            name="Python", file_extensions=[".py"], config_files=["pyproject.toml"]
        )
        lang = DetectedLanguage(
            definition=lang_def, matched_files=10, matched_configs=["pyproject.toml"]
        )
        result = _format_evidence(lang)
        assert "pyproject.toml" in result
        assert "10" in result

    def test_files_only(self):
        lang_def = LanguageDefinition(name="Python", file_extensions=[".py"])
        lang = DetectedLanguage(definition=lang_def, matched_files=5)
        result = _format_evidence(lang)
        assert "5" in result

    def test_config_only(self):
        lang_def = LanguageDefinition(
            name="Go", file_extensions=[".go"], config_files=["go.mod"]
        )
        lang = DetectedLanguage(
            definition=lang_def, matched_files=0, matched_configs=["go.mod"]
        )
        result = _format_evidence(lang)
        assert "go.mod" in result


class TestInitProjectCommand:
    """Tests for the CLI entry point."""

    def test_nonexistent_directory(self):
        class Args:
            dir = "/nonexistent/path/12345"
            force = False
            dry_run = False
            json = False

        result = init_project_command(Args())
        assert result == 1

    def test_existing_config_returns_1(self, tmp_path):
        (tmp_path / "app.py").write_text("")
        config_dir = tmp_path / ".ai-guardian"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text("{}")

        class Args:
            dir = str(tmp_path)
            force = False
            dry_run = False
            json = False

        result = init_project_command(Args())
        assert result == 1

    def test_force_overwrites(self, tmp_path):
        (tmp_path / "app.py").write_text("")
        config_dir = tmp_path / ".ai-guardian"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text("{}")

        class Args:
            dir = str(tmp_path)
            force = True
            dry_run = False
            json = False

        result = init_project_command(Args())
        assert result == 0

    def test_dry_run_returns_0(self, tmp_path):
        (tmp_path / "app.py").write_text("")

        class Args:
            dir = str(tmp_path)
            force = False
            dry_run = True
            json = False

        result = init_project_command(Args())
        assert result == 0

    def test_json_output(self, tmp_path, capsys):
        (tmp_path / "app.py").write_text("")

        class Args:
            dir = str(tmp_path)
            force = False
            dry_run = True
            json = True

        result = init_project_command(Args())
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "detected_languages" in output
        assert "allowlist_entries" in output

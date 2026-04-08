# Agent Instructions for AI Guardian

## General Instructions

**IMPORTANT**: The following general instructions apply to the AI Guardian project and MUST be followed when contributing to this codebase.

---

### Git Workflow

**IMPORTANT**: Never commit directly to the `main` branch. Always create a feature branch before making any commits.

#### Creating Branches and Pull Requests

1. **Update main branch** before creating a new branch:
   ```bash
   git checkout main
   git pull origin main
   ```
   **IMPORTANT**: Always ensure your main branch is up-to-date before creating a new feature branch.

2. **Create a branch** from the updated main branch:
   ```bash
   git checkout -b <issue-key>-<short-description>
   ```
   Example: `git checkout -b feature-add-secret-scanning`

3. **Make your changes** and commit them to the branch

4. **Push the branch** to remote:
   ```bash
   git push -u origin <branch-name>
   ```

5. **Create a PR** using the GitHub CLI (`gh`) or web interface

#### Creating Pull Requests

```bash
# Install gh CLI if needed
brew install gh  # macOS
# For other platforms: https://cli.github.com/

# Authenticate
gh auth login

# Create a pull request
gh pr create --title "Your PR Title" --body "$(cat <<'EOF'
## Description

[Describe your changes here]

## Testing

### Steps to test
1. Pull down the PR
2. [Add specific test steps]
3. [Additional steps]

### Scenarios tested
- [ ] Test scenario 1
- [ ] Test scenario 2

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
)"
```

---

### Testing

**CRITICAL**: All code changes MUST include appropriate tests.

#### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=ai_guardian --cov-report=term-missing

# Run specific test file
pytest tests/test_specific.py

# Run with verbose output
pytest -v
```

#### Test Structure

- Place all tests in the `tests/` directory
- Test files should be named `test_*.py`
- Test functions should be named `test_*`
- Use pytest fixtures for common setup

#### Test Coverage

- **Target**: Maintain >70% code coverage
- Run coverage reports before submitting PRs
- Add tests for new features and bug fixes

---

## Release Management

### Overview

AI Guardian follows a structured release management process to ensure stable releases while enabling continuous development. The project uses semantic versioning and git flow branching strategy.

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR.MINOR.PATCH** (e.g., 1.0.0, 1.1.0, 1.1.1)
- **Development**: X.Y.Z-dev (on main branch)

Examples:
- `1.0.0` - First stable release
- `1.1.0` - Added new features
- `1.1.1` - Bug fixes only
- `1.2.0-dev` - Development version on main

### Branch Strategy

- **main**: Active development (version X.Y.0-dev)
- **release-X.Y**: Stable release branches (e.g., release-1.0, release-1.1)
- **hotfix-X.Y.Z**: Critical fixes for released versions
- **Tags**: vX.Y.Z for each release

### Quick Reference

**Automated Release Workflow (Recommended):**

```bash
# Using the /release skill in Claude Code (automated)
/release minor              # Create minor version release (1.1.0 -> 1.2.0)
/release patch              # Create patch version release (1.1.0 -> 1.1.1)
/release major              # Create major version release (1.0.0 -> 2.0.0)
/release hotfix v1.1.0      # Create hotfix from v1.1.0 tag
/release test               # Create TestPyPI test release
```

The `/release` skill automates:
- Version updates in both `pyproject.toml` and `src/ai_guardian/__init__.py`
- CHANGELOG.md updates with proper formatting
- Git branch creation and commit messages
- Safety checks and validation
- Post-release guidance

**Manual Release Workflow (Alternative):**

```bash
# Check version
python -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])"

# Release workflow (see RELEASING.md for details)
git checkout -b release-1.0 main    # Create release branch
# Update version in pyproject.toml, CHANGELOG.md, run tests
git tag -a v1.0.0 -m "Release 1.0.0"
git push origin v1.0.0  # Triggers GitHub Actions to publish to PyPI

# Hotfix workflow (see RELEASING.md for details)
git checkout -b hotfix-1.0.1 v1.0.0
# Fix bug, update version, update CHANGELOG.md
git tag -a v1.0.1 -m "Hotfix 1.0.1"
git push origin v1.0.1  # Triggers GitHub Actions
```

### Automated Publishing

AI Guardian uses GitHub Actions for automated publishing:

1. **Push a version tag** (e.g., `v1.0.0`)
2. **GitHub Actions automatically**:
   - Builds distribution packages
   - Publishes to PyPI
   - Creates GitHub Release with changelog notes

**No manual PyPI publishing needed** - just push the tag!

### Documentation

- **RELEASING.md**: Complete step-by-step release and hotfix procedures
- **CHANGELOG.md**: All notable changes, following [Keep a Changelog](https://keepachangelog.com/) format
- **Version storage**: `pyproject.toml` (line 7) and `src/ai_guardian/__init__.py` (line 13)
- **Release skill**: `/release` command for automated releases (see skill documentation)

See [RELEASING.md](RELEASING.md) for detailed instructions, or use the `/release` skill for automated workflow.

---

## Code Quality

### Linting

The project uses multiple linters to maintain code quality:

```bash
# Run pylint
pylint ai_guardian/

# Check formatting with black
black --check ai_guardian/ tests/

# Run ruff
ruff check ai_guardian/ tests/
```

### Pre-commit Checks

Before submitting a PR:
1. Run all tests: `pytest`
2. Check test coverage: `pytest --cov=ai_guardian`
3. Run linters (optional but recommended)
4. Update CHANGELOG.md if making notable changes

---

## Project Structure

```
ai-guardian/
├── ai_guardian/          # Main package
│   ├── __init__.py
│   ├── __main__.py      # CLI entry point
│   └── ...
├── tests/               # Test suite
│   └── test_*.py
├── .github/
│   └── workflows/       # GitHub Actions CI/CD
│       ├── test.yml     # Test workflow
│       ├── lint.yml     # Lint workflow
│       └── publish.yml  # PyPI publish workflow
├── pyproject.toml       # Package metadata and dependencies
├── CHANGELOG.md         # Version history
├── RELEASING.md         # Release process documentation
├── README.md            # Project documentation
└── LICENSE              # Apache 2.0 license
```

---

## Continuous Integration

### GitHub Actions Workflows

1. **Tests** (`.github/workflows/test.yml`)
   - Runs on: push to main, pull requests
   - Tests: Python 3.9, 3.10, 3.11, 3.12
   - Coverage: Uploaded to Codecov

2. **Lint** (`.github/workflows/lint.yml`)
   - Runs on: pull requests
   - Checks: pylint, black, ruff

3. **Publish** (`.github/workflows/publish.yml`)
   - Runs on: version tags (v*)
   - Actions: Build, publish to PyPI, create GitHub Release

---

## Common Tasks

### Adding a New Feature

1. Create feature branch: `git checkout -b feature-name`
2. Implement feature with tests
3. Update CHANGELOG.md under `[Unreleased]` section
4. Run tests: `pytest`
5. Commit changes
6. Push and create PR

### Fixing a Bug

1. Create bugfix branch: `git checkout -b fix-bug-description`
2. Write failing test that reproduces bug
3. Fix the bug
4. Verify test passes
5. Update CHANGELOG.md under `[Unreleased]` section
6. Commit and create PR

### Preparing a Release

**Recommended: Use the `/release` skill (automated)**
```bash
# In Claude Code
/release minor   # or /release patch, /release major
```

The skill automates steps 2-6 below and provides guidance for step 7.

**Manual alternative:**
1. Follow [RELEASING.md](RELEASING.md) step-by-step
2. Create release branch: `git checkout -b release-X.Y`
3. Update version in `pyproject.toml` and `src/ai_guardian/__init__.py`
4. Update `CHANGELOG.md` (move Unreleased to version section)
5. Run full test suite
6. Commit changes
7. Create and push tag: `git tag -a vX.Y.Z -m "Release X.Y.Z"`
8. GitHub Actions handles the rest automatically

---

## Questions?

For questions about:
- **Release process**: See [RELEASING.md](RELEASING.md)
- **Testing**: See Testing section above
- **Contributing**: Open an issue on GitHub

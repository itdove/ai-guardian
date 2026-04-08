# Release Management Process

This document describes the release management process for AI Guardian.

## Table of Contents

- [Version Numbering](#version-numbering)
- [Branch Strategy](#branch-strategy)
- [Release Workflow](#release-workflow)
- [Hotfix Workflow](#hotfix-workflow)
- [Release Checklist](#release-checklist)
- [Version Infrastructure](#version-infrastructure)
- [Testing Releases with TestPyPI](#testing-releases-with-testpypi)

## Version Numbering

We follow [Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes (incompatible API changes)
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)
- **Development**: X.Y.Z-dev (on main branch)

Examples:
- `1.0.0` - First stable release
- `1.1.0` - Added new features
- `1.1.1` - Bug fixes only
- `1.2.0-dev` - Development version on main branch

## Branch Strategy

### Main Branches

- **main**: Active development branch (latest features, version X.Y.0-dev)
- **release-X.Y**: Release branches (e.g., release-1.0, release-1.1)
- **hotfix-X.Y.Z**: Hotfix branches for critical fixes to released versions

### Tags

- **vX.Y.Z**: Git tags for each release (e.g., v1.0.0, v1.0.1, v1.1.0)

### Branch Lifecycle

```
main (v1.1.0-dev)
  |
  |--- release-1.0 (created from main when ready for v1.0.0)
  |      |
  |      |--- v1.0.0 (tagged after testing)
  |      |
  |      |--- hotfix-1.0.1 (created from v1.0.0 tag)
  |             |
  |             |--- v1.0.1 (tagged after fix)
  |             |
  |             (merged back to release-1.0 and cherry-picked to main)
  |
  |--- release-1.1 (created from main when ready for v1.1.0)
         |
         |--- v1.1.0 (tagged after testing)
```

## Release Workflow

### Prerequisites

1. All features for the release are merged to `main`
2. All tests pass on `main`
3. CHANGELOG.md is up-to-date in the Unreleased section
4. GitHub issues for the release are complete

### Step-by-Step Release Process

#### 1. Create Release Branch

```bash
# Ensure main is up-to-date
git checkout main
git pull origin main

# Create release branch (e.g., release-1.0)
git checkout -b release-1.0 main

# Push release branch
git push -u origin release-1.0
```

#### 2. Update Version Numbers

Update version in **pyproject.toml**:
```toml
[project]
name = "ai-guardian"
version = "1.0.0"  # Remove -dev suffix
```

Update version in **src/ai_guardian/__init__.py**:
```python
__version__ = "1.0.0"  # Remove -dev suffix
```

Commit the version bump:
```bash
git add pyproject.toml
git commit -m "$(cat <<'EOF'
chore: bump version to 1.0.0 for release

Prepare for v1.0.0 release:
- Update version in pyproject.toml

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
)"
```

#### 3. Update CHANGELOG.md

Move Unreleased section entries to a new version section:

```markdown
## [1.0.0] - 2025-01-15

### Added
- Initial stable release
- [List of features added]

### Changed
- [List of changes]

### Fixed
- [List of bug fixes]

[1.0.0]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.0
```

Commit the changelog:
```bash
git add CHANGELOG.md
git commit -m "$(cat <<'EOF'
docs: update CHANGELOG.md for v1.0.0 release

Move unreleased items to v1.0.0 section with release date.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
)"
```

#### 4. Run Tests and Final Validation

```bash
# Run full test suite (if tests exist)
pytest

# Verify version command
python -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])"

# Test installation in clean environment
python -m venv /tmp/test-ai-guardian-install
source /tmp/test-ai-guardian-install/bin/activate
pip install .
ai-guardian --help
deactivate
rm -rf /tmp/test-ai-guardian-install
```

#### 5. Push Release Branch

```bash
# Push the release branch with version bump and changelog
git push origin release-1.0
```

#### 6. Create Git Tag

```bash
# Create annotated tag
git tag -a v1.0.0 -m "Release version 1.0.0

See CHANGELOG.md for details.
"

# Push tag to remote - this triggers the GitHub Actions publish workflow
git push origin v1.0.0
```

**Important:** Pushing the tag will automatically trigger the GitHub Actions workflow that:
1. Builds the distribution packages
2. Publishes to PyPI (requires PyPI trusted publishing to be configured)
3. Creates a GitHub Release with changelog notes

#### 7. Verify GitHub Actions Workflow

After pushing the tag:

1. Go to GitHub Actions: https://github.com/itdove/ai-guardian/actions
2. Check the "Publish to PyPI" workflow run
3. Verify it completes successfully
4. Check PyPI: https://pypi.org/project/ai-guardian/
5. Check GitHub Releases: https://github.com/itdove/ai-guardian/releases

If the workflow fails, you may need to:
- Fix the issue
- Delete the tag: `git tag -d v1.0.0 && git push origin :refs/tags/v1.0.0`
- Increment the patch version and try again

#### 8. Merge Back to Main and Bump Dev Version

```bash
# Switch to main
git checkout main

# Merge release branch
git merge release-1.0 --no-ff -m "Merge release-1.0 into main"

# Bump version to next dev cycle in pyproject.toml
# Update version to "1.1.0-dev"
```

Edit pyproject.toml:
```toml
version = "1.1.0-dev"
```

Commit and push:
```bash
git add pyproject.toml
git commit -m "$(cat <<'EOF'
chore: bump version to 1.1.0-dev

Begin development cycle for v1.1.0.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
)"

# Push to remote
git push origin main
```

## Hotfix Workflow

### When to Use Hotfixes

Use hotfix branches for:
- Critical bugs in production releases
- Security vulnerabilities
- Data corruption issues
- Severe performance problems

**Do NOT use hotfixes for**:
- Minor bugs (wait for next minor release)
- New features
- Refactoring

### Step-by-Step Hotfix Process

#### 1. Create Hotfix Branch

```bash
# Checkout the release tag that needs the fix
git checkout -b hotfix-1.0.1 v1.0.0

# Alternatively, branch from the release branch
git checkout -b hotfix-1.0.1 release-1.0
```

#### 2. Fix the Bug

Make the necessary code changes to fix the critical bug.

```bash
# Make your fixes
# Write tests to verify the fix
pytest

# Commit the fix
git add <files>
git commit -m "$(cat <<'EOF'
fix: critical bug in permission validation

Fixes timeout issue when validating MCP permissions.

Fixes: #123

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
)"
```

#### 3. Update Version Numbers

Update to patch version in **pyproject.toml**:
```toml
version = "1.0.1"
```

Update to patch version in **src/ai_guardian/__init__.py**:
```python
__version__ = "1.0.1"
```

```bash
git add pyproject.toml src/ai_guardian/__init__.py
git commit -m "chore: bump version to 1.0.1"
```

#### 4. Update CHANGELOG.md

Add a new section for the hotfix:

```markdown
## [1.0.1] - 2025-01-20

### Fixed
- Critical timeout issue in permission validation (#123)

[1.0.1]: https://github.com/itdove/ai-guardian/releases/tag/v1.0.1
```

```bash
git add CHANGELOG.md
git commit -m "docs: update CHANGELOG for v1.0.1 hotfix"
```

#### 5. Tag and Release

```bash
# Create tag
git tag -a v1.0.1 -m "Hotfix release 1.0.1

Critical fix for permission validation timeout.
"

# Push hotfix branch and tag
git push origin hotfix-1.0.1
git push origin v1.0.1
```

The GitHub Actions workflow will automatically publish to PyPI and create a release.

#### 6. Merge Back to Release and Main

```bash
# Merge hotfix to release branch
git checkout release-1.0
git merge hotfix-1.0.1 --no-ff
git push origin release-1.0

# Cherry-pick the fix to main (NOT merge the version bumps)
git checkout main
git cherry-pick <commit-sha-of-the-fix>  # Only the fix commit, not version bumps
git push origin main

# Delete hotfix branch
git branch -d hotfix-1.0.1
git push origin --delete hotfix-1.0.1
```

## Release Checklist

Use this checklist for each release:

### Pre-Release
- [ ] All planned features merged to `main`
- [ ] All tests pass (`pytest`)
- [ ] CHANGELOG.md updated with all changes
- [ ] Version bump PR reviewed and approved
- [ ] GitHub issues marked as complete

### Release Branch
- [ ] Create release branch (`release-X.Y`)
- [ ] Update version in `pyproject.toml` (remove `-dev`)
- [ ] Update CHANGELOG.md (move Unreleased to version section)
- [ ] Run full test suite
- [ ] Test installation in clean environment
- [ ] Push release branch
- [ ] Create and push git tag (`vX.Y.Z`)

### GitHub Actions & Release
- [ ] Verify GitHub Actions workflow completes successfully
- [ ] Verify package published to PyPI
- [ ] Verify GitHub Release created
- [ ] Test installation from PyPI: `pip install ai-guardian`

### Post-Release
- [ ] Merge release branch back to `main`
- [ ] Bump version to next dev cycle (`X.Y+1.0-dev`)
- [ ] Announce release (if applicable)

### Hotfix (if needed)
- [ ] Create hotfix branch from release tag
- [ ] Fix bug and add tests
- [ ] Update version to patch level
- [ ] Update CHANGELOG.md
- [ ] Create and push tag
- [ ] Verify GitHub Actions completes
- [ ] Merge back to release branch
- [ ] Cherry-pick fix to `main`

## Version Infrastructure

### Version Storage

Version number is stored in two locations that must be kept in sync:

1. **pyproject.toml** - Package metadata
   ```toml
   [project]
   version = "1.0.0"
   ```

2. **src/ai_guardian/__init__.py** - Runtime version
   ```python
   __version__ = "1.0.0"
   ```

**Important:** Always update both files when bumping versions.

This uses the modern Python packaging standard (PEP 621) with hatchling as the build backend.

### Version Display

Users can check the version using:
```bash
ai-guardian --version
# Output: ai-guardian 1.0.0
```

### Development Versions

Development versions on `main` branch always have the `-dev` suffix:
- `1.0.0-dev` - Developing towards v1.0.0
- `1.1.0-dev` - Developing towards v1.1.0

This helps distinguish development builds from stable releases.

## GitHub Actions CI/CD

### Workflows

The repository includes four GitHub Actions workflows:

1. **test.yml** - Runs tests on Python 3.9, 3.10, 3.11, 3.12
   - Triggered on: push to main, pull requests
   - Includes coverage reporting

2. **lint.yml** - Runs code quality checks (pylint, black, ruff)
   - Triggered on: pull requests

3. **publish-test.yml** - Publishes to TestPyPI for testing (see [Testing Releases with TestPyPI](#testing-releases-with-testpypi))
   - Triggered on: test tags (v*-test*), manual workflow dispatch
   - Requires: TestPyPI trusted publishing configured

4. **publish.yml** - Publishes to PyPI and creates GitHub Release
   - Triggered on: version tags (v*)
   - Requires: PyPI trusted publishing configured

### Setting Up PyPI Trusted Publishing

To enable automatic PyPI publishing:

1. Go to PyPI project settings: https://pypi.org/manage/project/ai-guardian/settings/
2. Navigate to "Publishing" section
3. Add a new publisher:
   - **PyPI Project Name**: ai-guardian
   - **Owner**: itdove (your GitHub org/user)
   - **Repository**: ai-guardian
   - **Workflow**: publish.yml
   - **Environment**: (leave blank)

This allows GitHub Actions to publish without storing API tokens.

### Setting Up TestPyPI Trusted Publishing

To enable automatic TestPyPI publishing for testing (recommended):

1. Create TestPyPI account: https://test.pypi.org/account/register/
2. Verify your email address
3. Go to TestPyPI publishing settings: https://test.pypi.org/manage/account/publishing/
4. Click "Add a new pending publisher"
5. Configure publisher:
   - **PyPI Project Name**: ai-guardian
   - **Owner**: itdove (your GitHub org/user)
   - **Repository**: ai-guardian
   - **Workflow**: publish-test.yml
   - **Environment**: testpypi
6. Create GitHub environment at https://github.com/itdove/ai-guardian/settings/environments:
   - Name: `testpypi`
   - (Optional) Add protection rules

See [Testing Releases with TestPyPI](#testing-releases-with-testpypi) for detailed usage instructions.

## Testing Releases with TestPyPI

Before publishing to production PyPI, you can test the entire release process using TestPyPI.

### Why TestPyPI?

**Benefits:**
- ✅ Test the entire release process without touching production
- ✅ Verify PyPI Trusted Publishing configuration works
- ✅ Catch packaging/metadata issues early
- ✅ Safe experimentation with workflow changes
- ✅ Standard best practice for Python projects

### Prerequisites

#### 1. TestPyPI Account
Create an account at https://test.pypi.org/account/register/ and verify your email.

#### 2. Configure Trusted Publishing on TestPyPI

1. Go to https://test.pypi.org/manage/account/publishing/
2. Click "Add a new pending publisher"
3. Configure publisher settings:
   - **PyPI Project Name**: `ai-guardian`
   - **Owner**: `itdove`
   - **Repository name**: `ai-guardian`
   - **Workflow name**: `publish-test.yml`
   - **Environment name**: `testpypi`
4. Save configuration

#### 3. Create GitHub Environment

1. Go to https://github.com/itdove/ai-guardian/settings/environments
2. Click "New environment"
3. Name: `testpypi`
4. (Optional) Add protection rules:
   - Required reviewers: yourself
   - Deployment branches: only `release-*` branches
5. Save environment

### Testing a Release

#### Step 1: Create Test Release Branch

```bash
# Update main branch
git checkout main
git pull origin main

# Create test release branch
git checkout -b release-1.2-test main
```

#### Step 2: Update Version to Test Version

Update version in **pyproject.toml**:
```toml
[project]
version = "1.2.0-test1"  # Add -test suffix
```

Update version in **src/ai_guardian/__init__.py**:
```python
__version__ = "1.2.0-test1"  # Add -test suffix
```

Commit changes:
```bash
git add pyproject.toml src/ai_guardian/__init__.py
git commit -m "$(cat <<'EOF'
chore: bump version to 1.2.0-test1 for TestPyPI

Prepare test release for TestPyPI to verify release process.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
)"
```

#### Step 3: Create and Push Test Tag

```bash
# Create test tag
git tag -a v1.2.0-test1 -m "Test release for TestPyPI

Testing release process before production release.
"

# Push tag to trigger workflow
git push origin v1.2.0-test1
```

**Note:** The tag MUST match the pattern `v*-test*` to trigger the TestPyPI workflow.

#### Step 4: Monitor GitHub Actions

1. Go to https://github.com/itdove/ai-guardian/actions
2. Check the "Publish to TestPyPI" workflow run
3. Verify it completes successfully

#### Step 5: Verify TestPyPI Publication

1. Check TestPyPI: https://test.pypi.org/project/ai-guardian/
2. Verify the test version appears (e.g., 1.2.0-test1)

#### Step 6: Test Installation from TestPyPI

```bash
# Create clean test environment
python -m venv /tmp/test-ai-guardian-testpypi
source /tmp/test-ai-guardian-testpypi/bin/activate

# Install from TestPyPI
# Note: --extra-index-url allows installing dependencies from production PyPI
pip install --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  ai-guardian==1.2.0-test1

# Test the package
ai-guardian --version
ai-guardian --help

# Clean up
deactivate
rm -rf /tmp/test-ai-guardian-testpypi
```

#### Step 7: Proceed with Production Release (if successful)

If the TestPyPI release works correctly:

1. Delete test tag and branch:
   ```bash
   git tag -d v1.2.0-test1
   git push origin :refs/tags/v1.2.0-test1
   git branch -D release-1.2-test
   ```

2. Follow the normal [Release Workflow](#release-workflow) to create production release

### Tag Naming Convention

- **TestPyPI:** `v1.2.0-test`, `v1.2.0-test1`, `v1.2.0-test2`
  - Pattern: `v*-test*` triggers TestPyPI workflow
  - Use sequential numbers for multiple test attempts

- **Production PyPI:** `v1.2.0`, `v1.2.1`, `v1.3.0`
  - Pattern: `v*` (without `-test` suffix) triggers production workflow
  - Only create after TestPyPI validation succeeds

### Manual Workflow Trigger

You can also trigger the TestPyPI workflow manually without creating a tag:

1. Go to https://github.com/itdove/ai-guardian/actions/workflows/publish-test.yml
2. Click "Run workflow"
3. Select the branch you want to test
4. Click "Run workflow" button

This is useful for testing workflow changes without creating tags.

### Troubleshooting

**Workflow fails with authentication error:**
- Verify TestPyPI Trusted Publishing is configured correctly
- Check that the GitHub environment `testpypi` exists
- Ensure workflow name matches: `publish-test.yml`

**Package upload fails:**
- Verify version number is unique (TestPyPI doesn't allow re-uploading same version)
- Increment test number (e.g., `v1.2.0-test2`)

**Installation from TestPyPI fails:**
- TestPyPI may not have all dependencies
- Use `--extra-index-url https://pypi.org/simple/` to fetch dependencies from production PyPI

## Manual PyPI Publishing

If you need to publish manually (without GitHub Actions):

### 1. Install Build Tools

```bash
pip install --upgrade build twine
```

### 2. Build Distribution Packages

```bash
# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build packages
python -m build
```

### 3. Test on TestPyPI (Optional)

```bash
# Upload to TestPyPI
python -m twine upload --repository testpypi dist/*

# Test installation
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple ai-guardian
```

### 4. Publish to Production PyPI

```bash
python -m twine upload dist/*
```

**Note:** You'll need PyPI credentials configured in `~/.pypirc` or use environment variables:
```bash
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-YOUR_API_TOKEN
```

## References

- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [Python Packaging User Guide](https://packaging.python.org/)
- [PEP 621 - Storing project metadata in pyproject.toml](https://peps.python.org/pep-0621/)
- [Hatchling Build Backend](https://hatch.pypa.io/latest/)
- [GitHub Actions - Publishing to PyPI](https://docs.github.com/en/actions/automating-builds-and-tests/building-and-testing-python#publishing-to-package-registries)
- [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)

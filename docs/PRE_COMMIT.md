# Pre-commit Hook

AI Guardian can scan staged files for secrets before they are committed to your repository. This provides a **last line of defense** against accidentally committing sensitive data.

## Quick Start

```bash
ai-guardian setup --pre-commit
```

This auto-detects whether the [pre-commit framework](https://pre-commit.com/) is installed and chooses the best method:

- **pre-commit framework available**: installs `.pre-commit-config.yaml` and runs `pre-commit install`
- **No framework**: installs a standalone git hook at `.git/hooks/pre-commit`

## Installation Methods

### Method 1: `ai-guardian setup --pre-commit` (Recommended)

The setup command handles detection and installation automatically:

```bash
# Install pre-commit hook
ai-guardian setup --pre-commit

# Preview what would be installed (no changes)
ai-guardian setup --pre-commit --dry-run

# Remove AI Guardian pre-commit hooks
ai-guardian setup --pre-commit --uninstall-hooks
```

### Method 2: Direct Git Hook

Manually install a git hook that calls `ai-guardian scan` on staged files:

```bash
cat > .git/hooks/pre-commit << 'HOOK'
#!/bin/bash
# AI Guardian pre-commit hook
# Scans staged files for secrets before commit

set -e

echo "🛡️ AI Guardian: Scanning staged files for secrets..."

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)

if [ -z "$STAGED_FILES" ]; then
  echo "✓ No files staged for commit"
  exit 0
fi

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "$STAGED_FILES" | while IFS= read -r file; do
  if [ -z "$file" ]; then continue; fi
  mkdir -p "$TEMP_DIR/$(dirname "$file")"
  git show ":$file" > "$TEMP_DIR/$file" 2>/dev/null || true
done

if gitleaks detect \
    --source "$TEMP_DIR" \
    --no-git \
    --redact \
    --verbose \
    --exit-code 42; then
  echo "✓ No secrets detected in staged files"
  exit 0
else
  EXIT_CODE=$?
  if [ $EXIT_CODE -eq 42 ]; then
    echo ""
    echo "❌ COMMIT BLOCKED: Secrets detected in staged files"
    echo "Please remove sensitive information and try again."
    exit 1
  else
    echo "⚠️ Gitleaks scan failed (exit code: $EXIT_CODE)"
    echo "Allowing commit to proceed (fail-open policy)"
    exit 0
  fi
fi
HOOK

chmod +x .git/hooks/pre-commit
```

### Method 3: pre-commit Framework

If you use the [pre-commit framework](https://pre-commit.com/):

```bash
pip install pre-commit
```

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.1
    hooks:
      - id: gitleaks
        name: Detect secrets with gitleaks
        entry: gitleaks detect --no-git --redact --verbose --exit-code 42
        language: golang
        stages: [commit]
        pass_filenames: false
```

Then install:

```bash
pre-commit install
```

## Protection Scope

The pre-commit hook scans at **commit time**, not during AI generation:

| What it does | What it does NOT do |
|---|---|
| Blocks commits containing secrets | Scan prompts during AI interaction |
| Prevents secrets in git history | Prevent AI from seeing secrets in the working directory |
| Works with any IDE or CLI workflow | Replace real-time IDE hooks |

For real-time protection during AI interactions, use `ai-guardian setup --ide claude` (or `--ide cursor`, `--ide copilot`). The pre-commit hook is a complementary layer.

## Uninstalling

```bash
# Automatic removal
ai-guardian setup --pre-commit --uninstall-hooks

# Manual removal (direct git hook)
rm .git/hooks/pre-commit

# Manual removal (pre-commit framework)
# Remove the gitleaks entry from .pre-commit-config.yaml
```

## Configuration

### Fail Policy

The default behavior is **fail-open**: if the scanner encounters an error (not a secret detection), the commit proceeds. To change to fail-closed, edit the hook script and replace the fallback `exit 0` with `exit 1`.

### Gitleaks Rules

Customize detection with `.gitleaks.toml` in your project root:

```toml
[allowlist]
  description = "Allow test secrets"
  paths = [
    '''tests/fixtures/.*''',
  ]
```

See [Gitleaks documentation](https://github.com/gitleaks/gitleaks#configuration) for the full configuration reference.

### Skipping the Hook

To bypass the hook for a single commit:

```bash
git commit --no-verify
```

## Aider Integration

For [Aider](https://aider.chat) users, enable commit verification in `.aider.conf.yml`:

```yaml
git-commit-verify: true
```

See [docs/AIDER.md](AIDER.md) for detailed Aider integration instructions.

## Troubleshooting

**Hook not running**: Verify the hook is executable (`chmod +x .git/hooks/pre-commit`) and that Aider has `git-commit-verify: true` if applicable.

**Scanner not found**: Install a scanner engine first (`ai-guardian setup --install-scanner`).

**False positives**: Add allowlist rules to `.gitleaks.toml` or use inline `# gitleaks:allow` comments.

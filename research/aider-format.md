# Aider Git Hook Integration Research

**Research Date:** 2026-03-27
**Status:** ✅ Complete
**Finding:** **WRAPPER SCRIPT APPROACH** - Simple git hook integration

---

## Executive Summary

Aider integrates with git pre-commit hooks through its `--git-commit-verify` flag. ai-guardian can scan commits using a wrapper script that reads staged files and calls gitleaks. **No code changes to ai-guardian are required** - this is a documentation and example script task.

**Key Finding:**
- ✅ Configuration/documentation only (no ai-guardian code changes)
- ✅ Uses standard git pre-commit hooks
- ✅ Wrapper script reads staged files and calls gitleaks
- ⚠️ Limitation: Only works at commit time, not during AI generation

---

## 1. How Aider's `--git-commit-verify` Flag Works

**Default Behavior:**
```bash
aider [files]
```
- Aider bypasses pre-commit hooks using `--no-verify` flag
- Commits are made quickly without validation

**With Verification Enabled:**
```bash
aider --git-commit-verify=True [files]
```
- Aider respects git pre-commit hooks
- Any configured hooks run before commit completes
- If hook exits with non-zero code, commit is rejected

**Configuration:**
```yaml
# .aider.conf.yml
git-commit-verify: true
```

---

## 2. Data Available in Git Pre-Commit Hooks

### Accessing Staged Files

**List staged files:**
```bash
git diff --cached --name-only --diff-filter=ACMR
```
- Returns list of files being committed
- Excludes deleted files

**Get staged content:**
```bash
git show ":path/to/file"
```
- Returns the **staged version** of the file (what will be committed)
- Not the working directory version (which may have unstaged changes)

**Get diff:**
```bash
git diff --cached path/to/file
```
- Shows what changes are staged for commit

### Git Environment Variables

When a pre-commit hook runs:
- `GIT_DIR` - Repository directory (usually `.git`)
- `GIT_INDEX_FILE` - Path to staging area index file
- Current working directory is the repository root

### What's NOT Available

❌ Aider does **not** pass file content directly to hooks
❌ No special environment variables from Aider
❌ No file lists in structured format

**Conclusion:** Hooks must read staged files themselves using standard git commands.

---

## 3. Integration Architecture

### Recommended Approach: Wrapper Script

```
User: aider --git-commit-verify=True [files]
    ↓
Aider stages files
    ↓
Git triggers: .git/hooks/pre-commit
    ↓
Wrapper script:
  1. git diff --cached --name-only
  2. For each file: git show ":file"
  3. Scan with gitleaks
  4. Exit 0 (allow) or 1 (block)
    ↓
Commit allowed/rejected
```

### Why Wrapper Script?

**Advantages:**
- ✅ Simple - Standard bash script
- ✅ Compatible - Works with any git hook system
- ✅ Direct - No framework dependencies
- ✅ Flexible - Easy to customize logic

**Alternatives Considered:**
- ❌ pre-commit framework: Adds dependency, Aider doesn't integrate
- ❌ Modifying ai-guardian: Not needed, git hooks already provide access

---

## 4. Wrapper Script Implementation

### Option A: Direct Gitleaks Integration

**File:** `.git/hooks/pre-commit`

```bash
#!/bin/bash
# AI Guardian pre-commit hook for Aider
# Scans staged files for secrets before commit

set -e

echo "🛡️ AI Guardian: Scanning staged files for secrets..."

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)

if [ -z "$STAGED_FILES" ]; then
  echo "✓ No files staged for commit"
  exit 0
fi

# Create temporary directory for staged content
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Extract each staged file to temp directory
echo "$STAGED_FILES" | while IFS= read -r file; do
  if [ -z "$file" ]; then continue; fi

  # Create directory structure in temp
  mkdir -p "$TEMP_DIR/$(dirname "$file")"

  # Get staged content and save to temp
  git show ":$file" > "$TEMP_DIR/$file" 2>/dev/null || true
done

# Scan temp directory with gitleaks
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
    echo ""
    echo "Please remove sensitive information and try again."
    echo ""
    exit 1
  else
    # Gitleaks error (not secrets found)
    echo "⚠️ Warning: Gitleaks scan failed (exit code: $EXIT_CODE)"
    echo "Allowing commit to proceed (fail-open policy)"
    exit 0
  fi
fi
```

### Option B: Call ai-guardian Directly

**File:** `.git/hooks/pre-commit`

```bash
#!/bin/bash
# AI Guardian pre-commit hook (using ai-guardian CLI)

set -e

echo "🛡️ AI Guardian: Scanning staged files..."

# Get staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

SECRETS_FOUND=false

# Scan each file
echo "$STAGED_FILES" | while IFS= read -r file; do
  if [ -z "$file" ]; then continue; fi

  # Get staged content
  CONTENT=$(git show ":$file" 2>/dev/null)

  # Create temp file
  TEMP_FILE=$(mktemp)
  echo "$CONTENT" > "$TEMP_FILE"

  # Scan with ai-guardian (simulate hook input)
  echo "{\"prompt\": \"$(cat $TEMP_FILE | head -c 1000)\"}" | ai-guardian

  SCAN_EXIT=$?
  rm -f "$TEMP_FILE"

  if [ $SCAN_EXIT -ne 0 ]; then
    echo "❌ Secrets detected in: $file"
    SECRETS_FOUND=true
    break
  fi
done

if [ "$SECRETS_FOUND" = "true" ]; then
  echo "❌ COMMIT BLOCKED"
  exit 1
fi

echo "✓ No secrets detected"
exit 0
```

**Note:** Option A (direct gitleaks) is simpler and recommended. Option B shows how to use ai-guardian CLI if needed.

---

## 5. Installation Instructions

### Step 1: Install Prerequisites

```bash
# Install gitleaks
brew install gitleaks  # macOS
# OR
sudo apt install gitleaks  # Linux with gitleaks in repos
# OR manual install

# Install ai-guardian (optional, for future features)
pip install ai-guardian
```

### Step 2: Create Pre-Commit Hook

```bash
# Create the hook script
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# ... paste script from Option A above ...
EOF

# Make executable
chmod +x .git/hooks/pre-commit
```

### Step 3: Configure Aider

```bash
# Create .aider.conf.yml in your project
cat > .aider.conf.yml << 'EOF'
# Enable pre-commit hook verification
git-commit-verify: true
EOF
```

### Step 4: Test

```bash
# Test the hook manually
git add .
git commit -m "test commit"
# Should run gitleaks scan

# Test with Aider
aider --git-commit-verify=True test.py
# Make changes, Aider will trigger the hook
```

---

## 6. Using pre-commit Framework (Alternative)

For teams already using the `pre-commit` framework:

**File:** `.pre-commit-config.yaml`

```yaml
repos:
  # Use official gitleaks hook
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.1
    hooks:
      - id: gitleaks
        name: Detect secrets with gitleaks
        entry: gitleaks git --pre-commit --redact --staged --verbose
        language: golang
        stages: [commit]

  # OR use local ai-guardian wrapper
  - repo: local
    hooks:
      - id: ai-guardian-scan
        name: AI Guardian Secret Scanner
        entry: hooks/ai-guardian-git-wrapper.sh
        language: script
        stages: [commit]
        files: '.*'
```

**Then:**
```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Configure Aider
echo "git-commit-verify: true" > .aider.conf.yml
```

---

## 7. Limitations and Considerations

### ⚠️ Commit-Time Only

**What it protects:**
- ✅ Blocks commits with secrets
- ✅ Prevents secrets from entering git history

**What it doesn't protect:**
- ❌ Doesn't scan prompts **during** AI generation
- ❌ Doesn't prevent AI from seeing secrets in working directory
- ❌ Only activates when Aider makes a commit

**Implication:** This is a **last line of defense**, not real-time protection like Claude Code/Cursor hooks.

### 🔍 Staged Content vs. Working Directory

The hook scans **staged content only**:
- If a file is partially staged, only the staged portion is scanned
- Unstaged changes in working directory are NOT scanned
- This is correct behavior (we scan what will be committed)

### 💡 Fail-Open Policy

If gitleaks fails with an error (not secrets found):
- The hook allows the commit to proceed
- Logs a warning
- This ensures availability over security

**Change to fail-closed:**
```bash
# Replace the error handler with:
else
  echo "❌ COMMIT BLOCKED: Gitleaks scan failed"
  exit 1
fi
```

---

## 8. Integration with ai-guardian

### Current State

ai-guardian provides:
- ✅ Gitleaks-based secret scanning
- ✅ Directory blocking with `.ai-read-deny`
- ✅ Multi-IDE hook support (Claude Code, Cursor)

### For Aider Integration

We only need to provide:
- 📝 **Documentation** on git hook setup
- 📝 **Example scripts** for pre-commit hooks
- 📝 **Instructions** for enabling `--git-commit-verify`

**No code changes to ai-guardian required!**

---

## 9. Files to Create

### 1. Documentation

**File:** `docs/AIDER.md`

Contents:
- Introduction to Aider integration
- Prerequisites (gitleaks installation)
- Hook setup instructions
- Configuration examples
- Troubleshooting

### 2. Example Hook Script

**File:** `examples/aider/pre-commit-hook.sh`

Contents:
- Complete pre-commit hook script (Option A from above)
- Comments explaining each step
- Installation instructions

### 3. Example Configuration

**File:** `examples/aider/.aider.conf.yml`

Contents:
```yaml
git-commit-verify: true
```

### 4. pre-commit Framework Config

**File:** `examples/aider/.pre-commit-config.yaml`

Contents:
- Gitleaks hook configuration
- Alternative ai-guardian hook configuration

---

## 10. Implementation Estimate

**Effort:** 1-3 days (documentation only)

**Tasks:**
- ✏️ Write `docs/AIDER.md` (2-3 hours)
- ✏️ Create `examples/aider/pre-commit-hook.sh` (1 hour)
- ✏️ Create `examples/aider/.aider.conf.yml` (15 minutes)
- ✏️ Create `examples/aider/.pre-commit-config.yaml` (30 minutes)
- ✏️ Update `README.md` with Aider support (30 minutes)
- ✅ Test with real Aider installation (1-2 hours)
- 📝 Update issue #1 with findings (30 minutes)

**No code changes required!**

---

## 11. Comparison: Aider vs. Claude Code/Cursor

| Feature | Claude Code/Cursor | Aider |
|---------|-------------------|-------|
| **Hook Type** | IDE native hooks | Git pre-commit hooks |
| **Trigger Point** | Before prompt submission | Before git commit |
| **Protection Level** | Real-time (during AI use) | Commit-time (after AI use) |
| **Implementation** | ai-guardian CLI | Git hook wrapper |
| **Code Changes** | None (already supported) | None (wrapper script) |
| **Setup Complexity** | Medium (IDE config) | Low (git hook + Aider config) |

---

## 12. Recommended Implementation Path

**Phase 1: Documentation (This Phase)**
1. Create `docs/AIDER.md`
2. Create example scripts in `examples/aider/`
3. Update `README.md`

**Phase 2: Testing (Optional)**
1. Test with real Aider installation
2. Verify hook blocks commits with secrets
3. Verify hook allows clean commits

**Phase 3: Enhancement (Future)**
1. Consider creating ai-guardian CLI flag: `ai-guardian scan-git-staged`
2. This could simplify the wrapper script
3. Would provide better error messages

---

## 13. Conclusion

**Finding:** **Documentation-only integration** (no code changes)

**Approach:** Git pre-commit hook wrapper script

**Effort:** 1-3 days (documentation and examples)

**Next Steps:**
1. ✅ Document findings (this file)
2. ⏭️ Create example scripts and documentation
3. ⏭️ Update README.md
4. ⏭️ Test with real Aider

---

## 14. Sources

- [Aider Git Integration Documentation](https://aider.chat/docs/git.html)
- [Aider Configuration Options](https://aider.chat/docs/config.html)
- [Gitleaks Pre-commit Hook](https://github.com/gitleaks/gitleaks/blob/master/.pre-commit-hooks.yaml)
- [Git Hooks Documentation](https://git-scm.com/docs/githooks)
- [pre-commit Framework](https://pre-commit.com/)
- [IBM Security Guide - Gitleaks and Pre-commit](https://medium.com/@ibm_ptc_security/securing-your-repositories-with-gitleaks-and-pre-commit-27691eca478d)

---

**Last Updated:** 2026-03-27
**Confidence Level:** High - Based on Aider documentation and git hooks standards

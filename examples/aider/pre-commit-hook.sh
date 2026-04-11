#!/bin/bash
# AI Guardian pre-commit hook for Aider
# Scans staged files for secrets before commit
#
# Installation:
#   1. Copy this file to .git/hooks/pre-commit
#   2. Make it executable: chmod +x .git/hooks/pre-commit
#   3. Configure Aider: echo "git-commit-verify: true" > .aider.conf.yml

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
    echo "Common secrets detected:"
    echo "  • API keys and tokens"
    echo "  • Private keys (SSH, RSA, PGP)"
    echo "  • Database credentials"
    echo "  • Cloud provider keys (AWS, GCP, Azure)"
    echo ""
    exit 1
  else
    # Gitleaks error (not secrets found)
    echo "⚠️ Warning: Gitleaks scan failed (exit code: $EXIT_CODE)"
    echo "Allowing commit to proceed (fail-open policy)"
    exit 0
  fi
fi

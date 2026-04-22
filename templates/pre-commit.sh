#!/bin/bash
# AI Guardian pre-commit hook
# Scans staged files before commit for security issues
#
# Installation:
#   cp templates/pre-commit.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or use: ai-guardian setup --pre-commit

set -e

echo "🛡️ AI Guardian: Scanning staged files..."

# Get staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)

if [ -z "$STAGED_FILES" ]; then
  echo "✅ No files to scan"
  exit 0
fi

# Check if ai-guardian is installed
if ! command -v ai-guardian &> /dev/null; then
  echo "❌ ERROR: ai-guardian not found"
  echo "Install with: pip install ai-guardian"
  exit 1
fi

# Find config file
CONFIG_FILE=""
if [ -f ".ai-guardian.json" ]; then
  CONFIG_FILE=".ai-guardian.json"
elif [ -f "ai-guardian.json" ]; then
  CONFIG_FILE="ai-guardian.json"
fi

# Build scan command
SCAN_CMD="ai-guardian scan --exit-code"
if [ -n "$CONFIG_FILE" ]; then
  SCAN_CMD="$SCAN_CMD --config $CONFIG_FILE"
fi

# Create temporary directory for staged files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Copy staged files to temp directory (preserving structure)
echo "$STAGED_FILES" | while read -r file; do
  if [ -f "$file" ]; then
    mkdir -p "$TEMP_DIR/$(dirname "$file")"
    cp "$file" "$TEMP_DIR/$file"
  fi
done

# Run scan on temporary directory
if $SCAN_CMD "$TEMP_DIR" 2>&1; then
  echo "✅ No security issues detected"
  exit 0
else
  echo ""
  echo "❌ COMMIT BLOCKED: Security issues detected in staged files"
  echo ""
  echo "To see details, run:"
  echo "  ai-guardian scan ."
  echo ""
  echo "To fix issues:"
  echo "  1. Review and fix the security issues above"
  echo "  2. Stage your fixes: git add <files>"
  echo "  3. Try committing again"
  echo ""
  echo "To skip this check (NOT recommended):"
  echo "  git commit --no-verify"
  exit 1
fi

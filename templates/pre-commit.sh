#!/bin/bash
# AI Guardian pre-commit hook
# Scans staged changes before commit for security issues
#
# Installation:
#   cp templates/pre-commit.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or use: ai-guardian setup --pre-commit

set -e

echo "🛡️ AI Guardian: Scanning staged changes..."

# Check if ai-guardian is installed
if ! command -v ai-guardian &> /dev/null; then
  echo "❌ ERROR: ai-guardian not found"
  echo "Install with: pip install ai-guardian"
  exit 1
fi

# Scan only staged changes — no temp dir needed
if ai-guardian scan --diff --staged --exit-code 2>&1; then
  echo "✅ No security issues detected"
  exit 0
else
  echo ""
  echo "❌ COMMIT BLOCKED: Security issues in staged changes"
  echo "  ai-guardian scan --diff --staged    # see details"
  echo "  git commit --no-verify              # skip (NOT recommended)"
  exit 1
fi

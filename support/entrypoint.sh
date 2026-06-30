#!/usr/bin/env bash
set -euo pipefail

IDE="${AI_GUARDIAN_IDE:-claude}"

SUPPORTED_IDES="claude opencode gemini codex kiro openclaw cursor copilot windsurf augment cline zoocode junie aiderdesk"
if ! echo "$SUPPORTED_IDES" | grep -qw "$IDE"; then
    echo "Error: unsupported IDE '$IDE'"
    echo "Supported: $SUPPORTED_IDES"
    exit 1
fi

echo "Configuring ai-guardian for IDE: $IDE"
ai-guardian setup --ide "$IDE" --create-config --force --yes 2>&1 | tail -3

echo "Starting ai-guardian daemon..."
ai-guardian daemon start --background 2>/dev/null || true

REST_PORT="${AI_GUARDIAN_REST_PORT:-63152}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AI Guardian support container ready"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  IDE:          $IDE"
echo "  Web console:  port ${REST_PORT} (find host port: podman port \$(hostname))"
echo "  Doctor:       ai-guardian doctor"
echo "  Version:      $(ai-guardian --version 2>/dev/null || echo 'unknown')"
echo ""

exec "$@"

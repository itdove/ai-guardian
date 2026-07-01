#!/usr/bin/env bash
set -euo pipefail

IDE="${AI_GUARDIAN_IDE:-claude}"
PROFILE="${AI_GUARDIAN_PROFILE:-}"

SUPPORTED_IDES="claude opencode gemini codex kiro openclaw cursor copilot windsurf augment cline zoocode junie aiderdesk"
if ! echo "$SUPPORTED_IDES" | grep -qw "$IDE"; then
    echo "Error: unsupported IDE '$IDE'"
    echo "Supported: $SUPPORTED_IDES"
    exit 1
fi

SETUP_ARGS="--ide $IDE --create-config --force --yes"
if [ -n "$PROFILE" ]; then
    SETUP_ARGS="$SETUP_ARGS --profile $PROFILE"
fi

echo "Configuring ai-guardian for IDE: $IDE${PROFILE:+ (profile: $PROFILE)}"
eval "ai-guardian setup $SETUP_ARGS" 2>&1 | tail -3

echo "Starting ai-guardian daemon..."
ai-guardian daemon start --background 2>/dev/null || true

REST_PORT="${AI_GUARDIAN_REST_PORT:-63152}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AI Guardian support container ready"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  IDE:          $IDE"
echo "  Profile:      ${PROFILE:-standard (default)}"
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    echo "  Auth:         Anthropic API key"
elif [ -n "${ANTHROPIC_VERTEX_PROJECT_ID:-}" ]; then
    echo "  Auth:         Vertex AI"
else
    echo "  Auth:         not configured"
fi
echo "  Web console:  http://localhost:${REST_PORT} (internal port to find host port run: podman port \$(hostname))"
echo "  Doctor:       ai-guardian doctor"
echo "  Version:      $(ai-guardian --version 2>/dev/null || echo 'unknown')"
echo ""

exec "$@"

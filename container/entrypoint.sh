#!/usr/bin/env bash
set -euo pipefail

# _request_tos_consent: prompt user to accept ToS before installing a proprietary CLI.
# Returns 0 (proceed) or 1 (skip).
# Bypass: set ACCEPT_PROPRIETARY_TOS=true for non-interactive/CI use.
_request_tos_consent() {
  local name="$1"
  local tos_url="$2"

  if [ "${ACCEPT_PROPRIETARY_TOS:-}" = "true" ]; then
    echo "ACCEPT_PROPRIETARY_TOS=true — accepting ToS for ${name}"
    return 0
  fi

  if [ ! -t 0 ]; then
    echo "Non-interactive mode: skipping ${name} install (set ACCEPT_PROPRIETARY_TOS=true to enable)"
    return 1
  fi

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ${name} requires accepting its Terms of Service:"
  echo "  ${tos_url}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "  Install %s and accept the ToS? [y/N] " "${name}"
  read -r _tos_answer || true
  if [ "${_tos_answer:-}" = "y" ] || [ "${_tos_answer:-}" = "Y" ]; then
    return 0
  fi
  echo "  Skipping ${name} installation."
  return 1
}

IDE="${AI_GUARDIAN_IDE:-claude}"
PROFILE="${AI_GUARDIAN_PROFILE:-}"

SUPPORTED_IDES="claude opencode gemini codex kiro openclaw cursor copilot windsurf augment cline zoocode junie aiderdesk dummy-agent"
if ! echo "$SUPPORTED_IDES" | grep -qw "$IDE"; then
    echo "Error: unsupported IDE '$IDE'"
    echo "Supported: $SUPPORTED_IDES"
    exit 1
fi

# dummy-agent: no API key required — launch REPL directly
if [ "$IDE" = "dummy-agent" ]; then
    echo "Starting ai-guardian daemon..."
    ai-guardian daemon start --background 2>/dev/null || true
    REST_PORT="${AI_GUARDIAN_REST_PORT:-63152}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  AI Guardian dummy-agent ready (no LLM needed)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  Interactive: ai-guardian dummy-agent"
    echo "  Script mode: ai-guardian dummy-agent --script /sandbox/scenarios/basic-secret.yaml"
    echo "  Web console: http://localhost:${REST_PORT}"
    echo "  Version:     $(ai-guardian --version 2>/dev/null || echo 'unknown')"
    echo ""
    exec "$@"
fi

# Proprietary CLIs — install at runtime with ToS consent
if [ "$IDE" = "claude" ] && [ ! -x "${HOME}/.local/bin/claude" ]; then
  if _request_tos_consent "Claude Code" "https://www.anthropic.com/legal/consumer-terms"; then
    curl -fsSL https://claude.ai/install.sh | sh
    chmod 755 "${HOME}/.local/bin/claude" 2>/dev/null || true
  fi
fi

if [ "$IDE" = "kiro" ] && [ ! -x "${HOME}/.local/bin/kiro" ]; then
  if _request_tos_consent "Kiro CLI" "https://kiro.dev/license/"; then
    _kiro_arch=$(uname -m)
    curl --proto '=https' --tlsv1.2 -sSf \
      "https://desktop-release.q.us-east-1.amazonaws.com/latest/kirocli-${_kiro_arch}-linux.zip" \
      -o /tmp/kirocli.zip
    cd /tmp
    python3 -c "import zipfile; zipfile.ZipFile('kirocli.zip').extractall()"
    chmod +x kirocli/install.sh
    ./kirocli/install.sh --no-confirm
    rm -rf /tmp/kirocli*
    cd /sandbox
  fi
fi

# Custom GitLab host — glab needs explicit config since it can't infer the host from GITLAB_TOKEN alone
if [[ -n "${GITLAB_TOKEN:-}" && -n "${GITLAB_HOST:-}" ]]; then
    glab auth login --hostname "$GITLAB_HOST" --token "$GITLAB_TOKEN" 2>/dev/null || true
fi
# gitlab.com: glab reads GITLAB_TOKEN natively, no action needed
# gh: reads GH_TOKEN / GITHUB_TOKEN natively, no action needed

if [ "$IDE" != "dummy-agent" ]; then
    SETUP_ARGS="--ide $IDE --create-config --force --yes"
    if [ -n "$PROFILE" ]; then
        SETUP_ARGS="$SETUP_ARGS --profile $PROFILE"
    fi
    echo "Configuring ai-guardian for IDE: $IDE${PROFILE:+ (profile: $PROFILE)}"
    eval "ai-guardian setup $SETUP_ARGS" 2>&1 | tail -3
fi

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
if [ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]; then
    echo "  GitHub:       token set"
fi
if [ -n "${GITLAB_TOKEN:-}" ]; then
    echo "  GitLab:       token set${GITLAB_HOST:+ (${GITLAB_HOST})}"
fi
echo "  Web console:  http://localhost:${REST_PORT} (internal port to find host port run: podman port \$(hostname))"
echo "  Doctor:       ai-guardian doctor"
echo "  Version:      $(ai-guardian --version 2>/dev/null || echo 'unknown')"
echo ""

exec "$@"

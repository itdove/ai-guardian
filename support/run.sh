#!/usr/bin/env bash
set -euo pipefail

# ai-guardian support container launcher
#
# Usage:
#   ./support/run.sh                              # defaults: claude, standard profile
#   ./support/run.sh --ide opencode
#   ./support/run.sh --profile @strict
#   ./support/run.sh --ide gemini --profile @minimal
#   ./support/run.sh --repo ~/myproject
#   ./support/run.sh --api-key sk-ant-...         # direct Anthropic API
#   ./support/run.sh --                           # pass extra args to podman run
#   ./support/run.sh -- bash -c "ai-guardian scan ."

IMAGE="${AI_GUARDIAN_SUPPORT_IMAGE:-ai-guardian-support}"
IDE="${AI_GUARDIAN_IDE:-claude}"
PROFILE="${AI_GUARDIAN_PROFILE:-}"
REST_PORT="${AI_GUARDIAN_REST_PORT:-63152}"
REPO_PATH=""
API_KEY="${ANTHROPIC_API_KEY:-}"
EXTRA_ARGS=()

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ide)       IDE="$2"; shift 2 ;;
        --profile)   PROFILE="$2"; shift 2 ;;
        --repo)      REPO_PATH="$2"; shift 2 ;;
        --port)      REST_PORT="$2"; shift 2 ;;
        --image)     IMAGE="$2"; shift 2 ;;
        --api-key)   API_KEY="$2"; shift 2 ;;
        --)          shift; EXTRA_ARGS=("$@"); break ;;
        *)           EXTRA_ARGS+=("$1"); shift ;;
    esac
done

# --- Build env var list ---
env_args=(
    -e "AI_GUARDIAN_IDE=${IDE}"
    -e "AI_GUARDIAN_REST_PORT=${REST_PORT}"
)

[[ -n "$PROFILE" ]] && env_args+=(-e "AI_GUARDIAN_PROFILE=${PROFILE}")

# --- Volume mounts ---
volume_args=()
[[ -n "$REPO_PATH" ]] && volume_args+=(-v "${REPO_PATH}:/sandbox/repo")

# --- Authentication ---
# Priority: --api-key flag > ANTHROPIC_API_KEY env > Vertex AI auto-detect
if [[ -n "$API_KEY" ]]; then
    env_args+=(-e "ANTHROPIC_API_KEY=${API_KEY}")
elif [[ -n "${ANTHROPIC_VERTEX_PROJECT_ID:-}" ]]; then
    env_args+=(
        -e "CLAUDE_CODE_USE_VERTEX=1"
        -e "ANTHROPIC_VERTEX_PROJECT_ID=${ANTHROPIC_VERTEX_PROJECT_ID}"
        -e "CLOUD_ML_REGION=${CLOUD_ML_REGION:-global}"
    )
    # Mount GCP credentials
    ADC_PATH="${GOOGLE_APPLICATION_CREDENTIALS:-${HOME}/.config/gcloud/application_default_credentials.json}"
    if [[ -f "$ADC_PATH" ]]; then
        env_args+=(
            -e "GOOGLE_APPLICATION_CREDENTIALS=/sandbox/.config/gcloud/application_default_credentials.json"
        )
        volume_args+=(-v "${ADC_PATH}:/sandbox/.config/gcloud/application_default_credentials.json:ro")
    else
        echo "Warning: GCP credentials not found at ${ADC_PATH}" >&2
        echo "  Run: gcloud auth application-default login" >&2
        echo "  Or set GOOGLE_APPLICATION_CREDENTIALS" >&2
    fi
fi

# --- Launch ---
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AI Guardian Support Container"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Image:    ${IMAGE}"
echo "  IDE:      ${IDE}"
echo "  Profile:  ${PROFILE:-standard (default)}"
echo "  Port:     ${REST_PORT}"
[[ -n "$REPO_PATH" ]] && echo "  Repo:     ${REPO_PATH}"
[[ -n "$API_KEY" ]] && echo "  Auth:     Anthropic API key"
[[ -n "${ANTHROPIC_VERTEX_PROJECT_ID:-}" && -z "$API_KEY" ]] && echo "  Auth:     Vertex AI"
echo ""

exec podman run -it --rm \
    -p "${REST_PORT}" \
    "${env_args[@]}" \
    "${volume_args[@]+"${volume_args[@]}"}" \
    "${IMAGE}" \
    "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"

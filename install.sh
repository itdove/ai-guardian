#!/usr/bin/env bash
set -euo pipefail

VERSION=""
PROFILE="@standard"
USE_VENV=false
VENV_DIR="$HOME/.ai-guardian-venv"
IDE=""
SETUP_ARGS=()

usage() {
    cat <<'EOF'
AI Guardian — One-line installer

Usage:
    curl -fsSL https://raw.githubusercontent.com/itdove/ai-guardian/main/install.sh | bash
    curl -fsSL https://raw.githubusercontent.com/itdove/ai-guardian/main/install.sh | bash -s -- [OPTIONS]

Options:
    --venv              Create a virtual environment at ~/.ai-guardian-venv/
    --ide NAME          Setup hooks for a specific IDE (skipped if omitted)
                        Choices: claude, cursor, copilot, codex, windsurf,
                                 gemini, cline, zoocode, augment, kiro, junie, aiderdesk
    --profile PROFILE   Security profile: @minimal, @standard (default), @strict
    --version VERSION   Install a specific version or a local .whl file
    -h, --help          Show this help message

    Any additional flags are passed through to 'ai-guardian setup'.
    Run 'ai-guardian setup --help' for the full list (e.g. --no-mcp,
    --install-scanner, --force, --rules, --dry-run, --permissive).

Examples:
    # Default: install latest, @standard profile
    curl -fsSL .../install.sh | bash

    # Install in a venv with strict profile for Claude
    curl -fsSL .../install.sh | bash -s -- --venv --ide claude --profile @strict

    # Install a specific version
    curl -fsSL .../install.sh | bash -s -- --version 1.9.0

    # Install from a local wheel file
    bash install.sh --version ./dist/ai_guardian-1.10.0-py3-none-any.whl

    # Skip MCP server and install scanner only
    curl -fsSL .../install.sh | bash -s -- --ide claude --no-mcp --install-scanner
EOF
}

log() { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
ok()  { printf '\033[1;32m  ✓\033[0m %s\n' "$1"; }
err() { printf '\033[1;31mError:\033[0m %s\n' "$1" >&2; }

# --- Parse arguments ---

while [ $# -gt 0 ]; do
    case "$1" in
        --venv)    USE_VENV=true; shift ;;
        --ide)     IDE="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *)         SETUP_ARGS+=("$1"); shift ;;
    esac
done

# --- Step 1: Find Python 3.9+ ---

find_python() {
    local py
    for py in python3 python; do
        if command -v "$py" >/dev/null 2>&1; then
            if "$py" -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
                echo "$py"
                return
            fi
        fi
    done
    return 1
}

log "Checking Python version..."
PYTHON=$(find_python) || {
    err "Python 3.9+ is required but not found."
    echo "  Install Python from https://www.python.org/downloads/"
    exit 1
}
PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
ok "Python $PY_VERSION ($PYTHON)"

# --- Step 2: Create venv (optional) ---

if [ "$USE_VENV" = true ]; then
    log "Creating virtual environment at $VENV_DIR..."
    "$PYTHON" -m venv "$VENV_DIR"
    # shellcheck disable=SC1091
    . "$VENV_DIR/bin/activate"
    PYTHON="$VENV_DIR/bin/python"
    ok "Virtual environment activated"
fi

# --- Step 3: Install ai-guardian ---

log "Installing ai-guardian..."
PKG="ai-guardian"
if [ -n "$VERSION" ]; then
    case "$VERSION" in
        *.whl)
            if [ ! -f "$VERSION" ]; then
                err "Wheel file not found: $VERSION"
                exit 1
            fi
            PKG="$VERSION"
            ;;
        *)
            PKG="ai-guardian==$VERSION"
            ;;
    esac
fi
"$PYTHON" -m pip install --quiet "$PKG"
AG_VERSION=$("$PYTHON" -m ai_guardian --version 2>&1 | awk '{print $NF}')
ok "ai-guardian $AG_VERSION installed"

# --- Step 4: Create config ---

log "Creating configuration (profile: $PROFILE)..."
"$PYTHON" -m ai_guardian setup --create-config --profile "$PROFILE" --yes 2>&1 | tail -1
CONFIG_PATH="$HOME/.config/ai-guardian/ai-guardian.json"
ok "Config at $CONFIG_PATH"

# --- Step 5: Setup IDE hooks (only when --ide is provided) ---

if [ -n "$IDE" ]; then
    log "Setting up hooks for $IDE..."
    "$PYTHON" -m ai_guardian setup --ide "$IDE" --install-scanner --yes \
        "${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}" 2>&1 | grep -v "^$" | tail -3
    ok "Hooks installed for $IDE"
fi

# --- Step 6: Summary ---

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AI Guardian $AG_VERSION installed successfully"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Version:  $AG_VERSION"
echo "  Config:   $CONFIG_PATH"
echo "  Profile:  $PROFILE"
if [ "$USE_VENV" = true ]; then
    echo "  Venv:     $VENV_DIR"
fi
if [ -n "$IDE" ]; then
    echo "  IDE:      $IDE"
fi
echo ""
echo "  Next steps:"
if [ -z "$IDE" ]; then
    echo "    ai-guardian setup --ide <NAME>  # setup hooks for your IDE"
fi
echo "    ai-guardian doctor         # verify setup"
echo "    ai-guardian --help         # see all commands"
if [ "$USE_VENV" = true ]; then
    echo "    source $VENV_DIR/bin/activate  # activate venv"
fi
echo ""

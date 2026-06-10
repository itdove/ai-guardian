#!/usr/bin/env bash
set -euo pipefail

VERSION=""
PROFILE="@standard"
INSTALL_MODE=""
VENV_DIR="$HOME/.ai-guardian-venv"
IDE=""
INSTALL_TKINTER=false
NO_SETUP=false
SETUP_ARGS=()

usage() {
    cat <<'EOF'
AI Guardian — One-line installer

Usage:
    curl -fsSL https://raw.githubusercontent.com/itdove/ai-guardian/main/install.sh | bash
    curl -fsSL https://raw.githubusercontent.com/itdove/ai-guardian/main/install.sh | bash -s -- [OPTIONS]

Install modes (mutually exclusive, default: auto-detect):
    --pip               Force: bare pip install (no isolation)
    --venv              Force: python -m venv + pip install
    --uv                Force: uv tool install (isolated, binary in PATH)

    Auto-detect (no flag) tries the best available method:
      1. uv installed  → uv tool install
      2. uv missing    → python -m venv + pip install
      3. venv fails    → bare pip install

Options:
    --ide NAME          Setup hooks for a specific IDE (skipped if omitted)
                        Choices: claude, cursor, copilot, codex, windsurf,
                                 gemini, cline, zoocode, augment, kiro, junie,
                                 aiderdesk, opencode
    --no-setup          Install only, don't auto-detect or update IDE hooks
    --profile PROFILE   Security profile: @minimal, @standard (default), @strict
    --version VERSION   Install a specific version or a local .whl file
    --tkinter           Install tkinter for native popup dialogs (optional)
                        Without it, NiceGUI browser form is used (Python 3.10+)
                        or Textual terminal fallback (Python 3.9)
    -h, --help          Show this help message

    Any additional flags are passed through to 'ai-guardian setup'.
    Run 'ai-guardian setup --help' for the full list (e.g. --no-mcp,
    --install-scanner, --force, --rules, --dry-run, --permissive).

Examples:
    # Default: auto-detect best install method
    curl -fsSL .../install.sh | bash

    # Force uv tool install with Claude hooks
    curl -fsSL .../install.sh | bash -s -- --uv --ide claude --profile @strict

    # Force venv install
    curl -fsSL .../install.sh | bash -s -- --venv

    # Force bare pip install
    curl -fsSL .../install.sh | bash -s -- --pip

    # Install only, don't update existing IDE hooks
    curl -fsSL .../install.sh | bash -s -- --uv --no-setup

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

has_uv() { command -v uv >/dev/null 2>&1; }

detect_installed_agents() {
    local agents=()

    # JSON-config agents: check file exists + contains "ai-guardian"
    local claude_config="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json"
    [ -f "$claude_config" ] && grep -q "ai-guardian" "$claude_config" 2>/dev/null && agents+=("claude")
    [ -f "$HOME/.cursor/hooks.json" ] && grep -q "ai-guardian" "$HOME/.cursor/hooks.json" 2>/dev/null && agents+=("cursor")
    [ -f "$HOME/.github/hooks/hooks.json" ] && grep -q "ai-guardian" "$HOME/.github/hooks/hooks.json" 2>/dev/null && agents+=("copilot")
    [ -f "$HOME/.codex/hooks.json" ] && grep -q "ai-guardian" "$HOME/.codex/hooks.json" 2>/dev/null && agents+=("codex")
    [ -f "$HOME/.codeium/windsurf/hooks.json" ] && grep -q "ai-guardian" "$HOME/.codeium/windsurf/hooks.json" 2>/dev/null && agents+=("windsurf")
    [ -f "$HOME/.gemini/settings.json" ] && grep -q "ai-guardian" "$HOME/.gemini/settings.json" 2>/dev/null && agents+=("gemini")
    [ -f "$HOME/.augment/settings.json" ] && grep -q "ai-guardian" "$HOME/.augment/settings.json" 2>/dev/null && agents+=("augment")

    # Plugin-file agents: check file exists
    [ -f "$HOME/.config/opencode/plugins/ai-guardian.ts" ] && agents+=("opencode")

    # Extension-based agents: check index.ts exists + contains "ai-guardian"
    [ -f "$HOME/.aider-desk/extensions/ai-guardian/index.ts" ] && agents+=("aiderdesk")
    [ -f "$HOME/.openclaw/plugins/ai-guardian/index.ts" ] && agents+=("openclaw")

    echo "${agents[@]}"
}

# --- Parse arguments ---

while [ $# -gt 0 ]; do
    case "$1" in
        --pip)     [ -z "$INSTALL_MODE" ] || { err "--pip, --venv, and --uv are mutually exclusive"; exit 1; }; INSTALL_MODE=pip; shift ;;
        --venv)    [ -z "$INSTALL_MODE" ] || { err "--pip, --venv, and --uv are mutually exclusive"; exit 1; }; INSTALL_MODE=venv; shift ;;
        --uv)      [ -z "$INSTALL_MODE" ] || { err "--pip, --venv, and --uv are mutually exclusive"; exit 1; }; INSTALL_MODE=uv; shift ;;
        --ide)     [ $# -ge 2 ] || { echo "Error: --ide requires a value" >&2; exit 1; }; IDE="$2"; shift 2 ;;
        --profile) [ $# -ge 2 ] || { echo "Error: --profile requires a value" >&2; exit 1; }; PROFILE="$2"; shift 2 ;;
        --version) [ $# -ge 2 ] || { echo "Error: --version requires a value" >&2; exit 1; }; VERSION="$2"; shift 2 ;;
        --no-setup) NO_SETUP=true; shift ;;
        --tkinter) INSTALL_TKINTER=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *)         SETUP_ARGS+=("$1"); shift ;;
    esac
done

# --- Auto-detect install mode ---

if [ -z "$INSTALL_MODE" ]; then
    if has_uv; then
        case "$(uname -s)" in
            Linux)
                INSTALL_MODE=venv
                log "Auto-detected: Linux + uv — using venv (tray needs system gi access)"
                ;;
            *)
                INSTALL_MODE=uv
                log "Auto-detected: uv available, using uv tool install"
                ;;
        esac
    else
        INSTALL_MODE=venv
        log "Auto-detected: uv not found, using venv + pip"
    fi
fi

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

# --- Step 2: Build package spec ---

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

# --- Step 2b: Detect running daemon/tray (for restart after upgrade) ---

DAEMON_WAS_RUNNING=false
TRAY_WAS_RUNNING=false
STATE_DIR="${AI_GUARDIAN_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/ai-guardian}"

DAEMON_PID_FILE="$STATE_DIR/daemon.pid"
if [ -f "$DAEMON_PID_FILE" ]; then
    DAEMON_PID=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['pid'])" "$DAEMON_PID_FILE" 2>/dev/null)
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        DAEMON_WAS_RUNNING=true
    fi
fi

TRAY_LOCK="$STATE_DIR/tray.lock"
if [ -f "$TRAY_LOCK" ]; then
    TRAY_PID=$(cat "$TRAY_LOCK" 2>/dev/null)
    if [ -n "$TRAY_PID" ] && kill -0 "$TRAY_PID" 2>/dev/null; then
        TRAY_WAS_RUNNING=true
    fi
fi

# --- Step 2c: Install Linux system headers for PyGObject (if needed) ---

if [ "$(uname -s)" = "Linux" ]; then
    # Skip on headless — tray (and PyGObject) only needed with a display
    HEADERS_HAS_DISPLAY=false
    [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ] && HEADERS_HAS_DISPLAY=true

    if [ "$HEADERS_HAS_DISPLAY" = false ]; then
        echo "  Skipping GObject headers — no display detected (headless environment)"
    else
        NEED_GI_HEADERS=false
        "$PYTHON" -c "import gi" 2>/dev/null || NEED_GI_HEADERS=true

        if [ "$NEED_GI_HEADERS" = true ]; then
            log "Installing GObject Introspection headers (required for tray on Linux)..."
            if command -v dnf >/dev/null 2>&1; then
                sudo dnf install -y gobject-introspection-devel cairo-gobject-devel pkg-config python3-devel gcc 2>/dev/null && \
                    ok "GObject headers installed via dnf" || \
                    echo "  Warning: could not install GObject headers — tray may not work"
            elif command -v apt-get >/dev/null 2>&1; then
                sudo apt-get install -y libgirepository1.0-dev gcc libcairo2-dev pkg-config python3-dev gir1.2-ayatanaappindicator3-0.1 2>/dev/null && \
                    ok "GObject headers installed via apt" || \
                    echo "  Warning: could not install GObject headers — tray may not work"
            elif command -v zypper >/dev/null 2>&1; then
                sudo zypper install -y gobject-introspection-devel cairo-devel pkg-config python3-devel gcc 2>/dev/null && \
                    ok "GObject headers installed via zypper" || \
                    echo "  Warning: could not install GObject headers — tray may not work"
            elif command -v pacman >/dev/null 2>&1; then
                sudo pacman -S --noconfirm gobject-introspection cairo pkgconf python gcc 2>/dev/null && \
                    ok "GObject headers installed via pacman" || \
                    echo "  Warning: could not install GObject headers — tray may not work"
            else
                echo "  Warning: could not detect package manager for GObject headers."
                echo "  Install manually:"
                echo "    Fedora/RHEL:     sudo dnf install gobject-introspection-devel cairo-gobject-devel pkg-config python3-devel gcc"
                echo "    Debian/Ubuntu:   sudo apt install libgirepository1.0-dev gcc libcairo2-dev pkg-config python3-dev"
                echo "    openSUSE:        sudo zypper install gobject-introspection-devel cairo-devel pkg-config python3-devel gcc"
                echo "    Arch:            sudo pacman -S gobject-introspection cairo pkgconf python gcc"
            fi
        else
            ok "GObject Introspection already available"
        fi
    fi
fi

# --- Step 3: Install ai-guardian ---

INSTALL_DESC=""

case "$INSTALL_MODE" in
    uv)
        if ! has_uv; then
            err "uv is required but not installed."
            echo "  Install uv: https://docs.astral.sh/uv/getting-started/installation/"
            exit 1
        fi
        log "Installing ai-guardian via uv tool install..."
        uv tool install "$PKG"
        INSTALL_DESC="uv tool install"
        ;;
    venv)
        log "Creating virtual environment at $VENV_DIR..."
        if has_uv; then
            uv venv "$VENV_DIR" --python "$PYTHON" --quiet
        else
            "$PYTHON" -m venv "$VENV_DIR"
        fi
        # shellcheck disable=SC1091
        . "$VENV_DIR/bin/activate"
        PYTHON="$VENV_DIR/bin/python"
        ok "Virtual environment activated"

        log "Installing ai-guardian..."
        if has_uv; then
            uv pip install --python "$PYTHON" --quiet "$PKG"
        else
            "$PYTHON" -m pip install --quiet "$PKG"
        fi
        INSTALL_DESC="pip (venv at $VENV_DIR)"
        ;;
    pip)
        log "Installing ai-guardian via pip..."
        "$PYTHON" -m pip install --quiet "$PKG"
        INSTALL_DESC="pip (system)"
        ;;
esac

# Resolve the ai-guardian command for post-install steps
if [ "$INSTALL_MODE" = "uv" ]; then
    AG_CMD="ai-guardian"
    if ! command -v ai-guardian >/dev/null 2>&1; then
        AG_CMD="$HOME/.local/bin/ai-guardian"
    fi
    AG_VERSION=$("$AG_CMD" --version 2>&1 | awk '{print $NF}')
else
    AG_CMD="$PYTHON -m ai_guardian"
    AG_VERSION=$($AG_CMD --version 2>&1 | awk '{print $NF}')
fi
ok "ai-guardian $AG_VERSION installed ($INSTALL_DESC)"

# --- Step 3a: Install PyGObject for Linux tray support ---

if [ "$(uname -s)" = "Linux" ]; then
    # Skip on headless systems — tray needs a display
    LINUX_HAS_DISPLAY=false
    [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ] && LINUX_HAS_DISPLAY=true

    if [ "$LINUX_HAS_DISPLAY" = false ]; then
        echo "  Skipping PyGObject — no display detected (headless environment)"
    else
    log "Installing PyGObject for Linux tray support..."
    GI_INSTALLED=false
    case "$INSTALL_MODE" in
        uv)
            # Install into uv tool's isolated environment
            UV_TOOL_ENV="$HOME/.local/share/uv/tools/ai-guardian"
            if [ -d "$UV_TOOL_ENV" ]; then
                UV_TOOL_PYTHON=$(find "$UV_TOOL_ENV" -path "*/bin/python3" -type f 2>/dev/null | head -1)
                if [ -n "$UV_TOOL_PYTHON" ]; then
                    uv pip install --python "$UV_TOOL_PYTHON" --quiet PyGObject 2>/dev/null && GI_INSTALLED=true
                fi
            fi
            ;;
        venv)
            if has_uv; then
                uv pip install --python "$PYTHON" --quiet PyGObject 2>/dev/null && GI_INSTALLED=true
            fi
            if [ "$GI_INSTALLED" = false ]; then
                "$PYTHON" -m pip install --quiet PyGObject 2>/dev/null && GI_INSTALLED=true
            fi
            ;;
        pip)
            "$PYTHON" -m pip install --quiet PyGObject 2>/dev/null && GI_INSTALLED=true
            ;;
    esac
    if [ "$GI_INSTALLED" = true ]; then
        ok "PyGObject installed (tray will use AppIndicator backend)"
    else
        echo "  Warning: PyGObject install failed — tray may not work on Linux"
        echo "  System headers may be needed:"
        echo "    Fedora/RHEL:   sudo dnf install gobject-introspection-devel cairo-gobject-devel pkg-config python3-devel gcc"
        echo "    Debian/Ubuntu: sudo apt install libgirepository1.0-dev gcc libcairo2-dev pkg-config python3-dev"
    fi
    fi  # LINUX_HAS_DISPLAY
fi

# --- Step 3b: Restart daemon/tray if they were running before upgrade ---

RESTARTED=""
if [ "$DAEMON_WAS_RUNNING" = true ]; then
    log "Restarting daemon (was running before upgrade)..."
    $AG_CMD daemon stop 2>/dev/null || true
    $AG_CMD daemon start --background 2>/dev/null && {
        ok "Daemon restarted"
        RESTARTED="${RESTARTED:+$RESTARTED, }daemon"
    } || echo "  Warning: daemon restart failed — start manually with: ai-guardian daemon start"
fi

if [ "$TRAY_WAS_RUNNING" = true ]; then
    log "Restarting tray (was running before upgrade)..."
    $AG_CMD tray stop 2>/dev/null || true
    $AG_CMD tray start --background 2>/dev/null && {
        ok "Tray restarted"
        RESTARTED="${RESTARTED:+$RESTARTED, }tray"
    } || echo "  Warning: tray restart failed — start manually with: ai-guardian tray start"
fi

# --- Step 3c: Install tkinter (optional) ---

if [ "$INSTALL_TKINTER" = true ]; then
    # Skip on headless systems — tkinter needs a display
    HAS_DISPLAY=false
    case "$(uname -s)" in
        Darwin) HAS_DISPLAY=true ;;  # macOS always has a display
        Linux)  [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ] && HAS_DISPLAY=true ;;
        *)      HAS_DISPLAY=true ;;  # Windows always has a display
    esac

    if [ "$HAS_DISPLAY" = false ]; then
        echo "  Skipping tkinter — no display detected (headless environment)"
        echo "  Tray plugin forms will use NiceGUI browser form (Python 3.10+) or Textual terminal fallback"
    elif "$PYTHON" -c "import tkinter" 2>/dev/null; then
        ok "tkinter already available"
    else
        case "$(uname -s)" in
            Darwin)
                if command -v brew >/dev/null 2>&1; then
                    brew install tcl-tk 2>/dev/null || true
                    ok "tcl-tk installed via Homebrew (rebuild Python with pyenv to activate)"
                else
                    echo "  tkinter requires Tcl/Tk. Install options:"
                    echo "    - Use system Python (/usr/bin/python3) which includes tkinter"
                    echo "    - Install Homebrew (https://brew.sh) then: brew install tcl-tk"
                    echo "    - Download Tcl/Tk from https://www.tcl.tk/software/tcltk/"
                    echo "  Continuing without tkinter (NiceGUI browser fallback on Python 3.10+, Textual otherwise)"
                fi
                ;;
            Linux)
                if command -v dnf >/dev/null 2>&1; then
                    PY_MINOR=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
                    sudo dnf install -y "python${PY_MINOR}-tkinter" 2>/dev/null && ok "tkinter installed via dnf" || {
                        sudo dnf install -y python3-tkinter 2>/dev/null && ok "tkinter installed via dnf" || \
                            echo "  Could not install tkinter via dnf. Continuing with Textual fallback."
                    }
                elif command -v apt-get >/dev/null 2>&1; then
                    sudo apt-get install -y python3-tk 2>/dev/null && ok "tkinter installed via apt" || \
                        echo "  Could not install tkinter via apt. Continuing with Textual fallback."
                elif command -v apk >/dev/null 2>&1; then
                    sudo apk add py3-tkinter 2>/dev/null && ok "tkinter installed via apk" || \
                        echo "  Could not install tkinter via apk. Continuing with Textual fallback."
                else
                    echo "  Could not detect package manager. Install tkinter manually:"
                    echo "    RHEL/Fedora: dnf install python3-tkinter"
                    echo "    Debian/Ubuntu: apt install python3-tk"
                    echo "    Alpine: apk add py3-tkinter"
                    echo "  Continuing without tkinter (NiceGUI browser fallback on Python 3.10+, Textual otherwise)"
                fi
                ;;
            *)
                echo "  tkinter should be included with your Python installation."
                echo "  If not, reinstall Python from https://www.python.org/downloads/"
                echo "  Continuing without tkinter (NiceGUI browser fallback on Python 3.10+, Textual otherwise)"
                ;;
        esac
    fi
fi

# --- Step 3d: Auto-detect and update existing agent hooks ---

if [ -z "$IDE" ] && [ "$NO_SETUP" = false ]; then
    DETECTED=$(detect_installed_agents)
    if [ -n "$DETECTED" ]; then
        log "Detected existing hooks, updating..."
        UPDATED=()
        for agent in $DETECTED; do
            if $AG_CMD setup --ide "$agent" --force --yes \
                "${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}" >/dev/null 2>&1; then
                UPDATED+=("$agent")
            fi
        done
        if [ ${#UPDATED[@]} -gt 0 ]; then
            ok "Updated hooks for: ${UPDATED[*]}"
        fi
    else
        echo ""
        echo "  No existing hooks found. Run setup for your IDE:"
        echo "    ai-guardian setup --ide claude"
        echo "    ai-guardian setup --ide opencode"
        echo "    ai-guardian setup --ide cursor"
        echo ""
    fi
fi

# --- Step 4: Create config ---

log "Creating configuration (profile: $PROFILE)..."
$AG_CMD setup --create-config --profile "$PROFILE" --yes 2>&1 | tail -1
CONFIG_PATH="$HOME/.config/ai-guardian/ai-guardian.json"
ok "Config at $CONFIG_PATH"

# --- Step 5: Setup IDE hooks (only when --ide is provided) ---

if [ -n "$IDE" ]; then
    log "Setting up hooks for $IDE..."
    SETUP_OUTPUT=$($AG_CMD setup --ide "$IDE" --install-scanner --force --yes \
        "${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}" 2>&1) || true
    echo "$SETUP_OUTPUT" | grep -v "^$" | tail -3
    if echo "$SETUP_OUTPUT" | grep -q "already configured"; then
        ok "Hooks already configured for $IDE"
    else
        ok "Hooks installed for $IDE"
    fi
fi

# --- Step 6: Verify installation ---

log "Verifying installation..."
$AG_CMD doctor 2>&1 | tail -5 || true

# --- Step 7: Summary ---

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AI Guardian $AG_VERSION installed successfully"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Version:  $AG_VERSION"
echo "  Install:  $INSTALL_DESC"
echo "  Config:   $CONFIG_PATH"
echo "  Profile:  $PROFILE"
if [ "$INSTALL_MODE" = "venv" ]; then
    echo "  Venv:     $VENV_DIR"
fi
if [ -n "$IDE" ]; then
    echo "  IDE:      $IDE"
elif [ -n "${UPDATED+x}" ] && [ ${#UPDATED[@]} -gt 0 ]; then
    echo "  Updated:  ${UPDATED[*]}"
fi
if "$PYTHON" -c "import tkinter" 2>/dev/null; then
    echo "  Popups:   tkinter (native dialogs)"
    if [ "$INSTALL_MODE" = "uv" ]; then
        echo "            Note: uv's python-build-standalone may have incomplete Tcl/Tk."
        echo "            If native popups fail, NiceGUI browser fallback activates automatically."
    fi
elif "$PYTHON" -c "import nicegui" 2>/dev/null; then
    echo "  Popups:   NiceGUI (browser-based form)"
else
    echo "  Popups:   Textual (terminal fallback)"
fi
if [ -n "$RESTARTED" ]; then
    echo "  Restarted: $RESTARTED"
fi
echo ""
echo "  Popup override env vars:"
echo "    AI_GUARDIAN_NO_TKINTER=1   skip tkinter, use NiceGUI or Textual"
echo "    AI_GUARDIAN_NO_NICEGUI=1   skip NiceGUI, use Textual"
echo ""
echo "  Next steps:"
if [ -z "$IDE" ] && { [ -z "${UPDATED+x}" ] || [ ${#UPDATED[@]} -eq 0 ]; }; then
    echo "    ai-guardian setup --ide <NAME>  # setup hooks for your IDE"
fi
echo "    ai-guardian doctor              # verify setup"
echo "    ai-guardian --help              # see all commands"
if [ "$DAEMON_WAS_RUNNING" != true ] || [ "$TRAY_WAS_RUNNING" != true ]; then
    echo ""
    echo "  Optional (auto-starts on first prompt):"
    if [ "$DAEMON_WAS_RUNNING" != true ]; then
        echo "    ai-guardian daemon start        # start background daemon now"
    fi
    if [ "$TRAY_WAS_RUNNING" != true ]; then
        echo "    ai-guardian tray start          # start system tray now"
    fi
fi
if [ "$INSTALL_MODE" = "venv" ]; then
    echo "    source $VENV_DIR/bin/activate  # activate venv"
fi
echo ""

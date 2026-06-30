# AI Guardian Support Reproduction Image

Minimal UBI-based container for reproducing user-reported ai-guardian issues across IDEs and architectures.

## What's Included

| Component | Description |
|-----------|-------------|
| ai-guardian | Security hooks, daemon, web console, MCP server |
| gitleaks, betterleaks | Secret scanning engines |
| Claude Code | Anthropic CLI agent |
| OpenCode | Open-source model-agnostic agent |
| Gemini CLI | Google Gemini terminal agent |
| Codex CLI | OpenAI terminal agent |
| Kiro CLI | AWS terminal agent |
| OpenClaw | Open-source AI assistant |
| rapidocr-onnxruntime | Image scanning support (x86_64 + aarch64) |

## Build

```bash
# Default (latest release)
podman build -t ai-guardian-support support/

# Specific version
podman build --build-arg AI_GUARDIAN_VERSION=1.13.0 -t ai-guardian-support support/

# Local wheel (copy wheel into support/ first)
cp dist/ai_guardian-1.13.0-py3-none-any.whl support/vendor/
podman build --build-arg AI_GUARDIAN_VERSION=ai_guardian-1.13.0-py3-none-any.whl \
    -t ai-guardian-support support/

# Multi-arch
podman build --platform linux/amd64,linux/arm64 -t ai-guardian-support support/
```

## Run

```bash
# Default (Claude Code hooks)
podman run -it -p 63152:63152 ai-guardian-support

# Select IDE
podman run -it -p 63152:63152 -e AI_GUARDIAN_IDE=opencode ai-guardian-support
podman run -it -p 63152:63152 -e AI_GUARDIAN_IDE=gemini ai-guardian-support
podman run -it -p 63152:63152 -e AI_GUARDIAN_IDE=codex ai-guardian-support
podman run -it -p 63152:63152 -e AI_GUARDIAN_IDE=kiro ai-guardian-support
podman run -it -p 63152:63152 -e AI_GUARDIAN_IDE=openclaw ai-guardian-support

# Mount a repo to test
podman run -it -p 63152:63152 -v ~/myrepo:/sandbox/repo ai-guardian-support

# Run doctor
podman run -it ai-guardian-support ai-guardian doctor

# Custom command
podman run -it ai-guardian-support ai-guardian scan /sandbox/repo
```

## IDE Selection

Set `AI_GUARDIAN_IDE` to configure hooks for a specific IDE at container start:

| Value | IDE | Installed in image |
|-------|-----|--------------------|
| `claude` (default) | Claude Code | Yes |
| `opencode` | OpenCode | Yes |
| `gemini` | Gemini CLI | Yes |
| `codex` | Codex CLI | Yes |
| `kiro` | Kiro CLI | Yes |
| `openclaw` | OpenClaw | Yes |
| `cursor` | Cursor | No (hooks only) |
| `copilot` | GitHub Copilot | No (hooks only) |
| `windsurf` | Windsurf | No (hooks only) |
| `augment` | Augment | No (hooks only) |
| `cline` | Cline | No (hooks only) |
| `zoocode` | ZooCode | No (hooks only) |
| `junie` | Junie | No (hooks only) |
| `aiderdesk` | AiderDesk | No (hooks only) |

IDEs marked "hooks only" are not installed in the image (they require a GUI) but
ai-guardian hooks are configured for them. Mount the IDE binary into the container
if needed.

## Web Console

The ai-guardian daemon starts automatically and binds to `0.0.0.0` inside the
container (auto-detected via `/.dockerenv` / `/run/.containerenv`).

Access from the host: `http://localhost:63152`

## Build Args

| Arg | Default | Description |
|-----|---------|-------------|
| `AI_GUARDIAN_VERSION` | `1.13.0` | PyPI version or `.whl` filename |
| `AI_GUARDIAN_REST_PORT` | `63152` | Daemon REST API / web console port |
| `UV_VERSION` | `0.11.16` | uv package manager version |
| `OPENCODE_VERSION` | `1.17.3` | OpenCode version |

## Expected Doctor Warnings

In a container, `ai-guardian doctor` will show expected warnings for:

- **System tray**: Not available (no display server)
- **Terminal emulator**: Not detected (no desktop)
- **tkinter**: Not installed (no GUI needed)

All security-critical checks (config, hooks, scanners, daemon) should pass.

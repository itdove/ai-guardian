# AI Guardian Container Image

UBI-based container image with ai-guardian and all headless-capable IDEs.
Published to [quay.io/itdove/ai-guardian](https://quay.io/itdove/ai-guardian) on every merge and release.

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

## Pull

```bash
# Latest build from main branch
podman pull quay.io/itdove/ai-guardian:latest

# Specific release version
podman pull quay.io/itdove/ai-guardian:1.13.0
```

Tag conventions:
- `:latest` — tracks main branch (updated on every merge)
- `:<version>` — pinned stable release (e.g. `1.13.0`)

## Build Locally

```bash
# Default (latest release)
podman build -t ai-guardian container/

# Specific version
podman build --build-arg AI_GUARDIAN_VERSION=1.13.0 -t ai-guardian container/

# Local wheel (copy wheel into container/ first)
cp dist/ai_guardian-1.13.0-py3-none-any.whl container/vendor/
podman build --build-arg AI_GUARDIAN_VERSION=ai_guardian-1.13.0-py3-none-any.whl \
    -t ai-guardian container/

# Multi-arch
podman build --platform linux/amd64,linux/arm64 -t ai-guardian container/
```

## Run

Using `run.sh` (recommended):

```bash
./container/run.sh                                    # defaults: claude, standard
./container/run.sh --ide opencode                     # select IDE
./container/run.sh --profile @strict                  # select profile
./container/run.sh --repo ~/myproject                 # mount a repo
./container/run.sh --api-key sk-ant-...               # Anthropic API auth
./container/run.sh --ide gemini --profile @minimal    # combine options
./container/run.sh -- ai-guardian doctor              # run a command
```

Vertex AI auth is auto-detected from environment variables (see [Authentication](#authentication)).

<details>
<summary>Manual container run (podman / docker)</summary>

```bash
# Default (Claude Code hooks)
podman run -it -p 63152 ai-guardian

# Select IDE
podman run -it -p 63152 -e AI_GUARDIAN_IDE=opencode ai-guardian

# Select configuration profile
podman run -it -p 63152 -e AI_GUARDIAN_PROFILE=@strict ai-guardian

# Authenticate with Anthropic API
podman run -it -p 63152 -e ANTHROPIC_API_KEY=sk-ant-... ai-guardian

# Authenticate with Vertex AI
podman run -it -p 63152 \
    -e CLAUDE_CODE_USE_VERTEX=1 \
    -e ANTHROPIC_VERTEX_PROJECT_ID=my-gcp-project \
    -e CLOUD_ML_REGION=global \
    -e GOOGLE_APPLICATION_CREDENTIALS=/sandbox/gcp-key.json \
    -v ~/gcp-key.json:/sandbox/gcp-key.json:ro \
    ai-guardian

# Mount a repo to test
podman run -it -p 63152 -v ~/myrepo:/sandbox/repo ai-guardian

# Run doctor
podman run -it ai-guardian ai-guardian doctor
```

</details>

## Container Engine

By default, `run.sh` uses Podman. To use Docker instead:

```bash
CONTAINER_ENGINE=docker ./container/run.sh
# or export for the session:
export CONTAINER_ENGINE=docker
./container/run.sh --ide claude
```

Both engines support the same `-p` syntax for port mapping. Use `docker port <container>` (instead of `podman port`) to find the mapped host port when using Docker.

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

## Configuration Profile

Set `AI_GUARDIAN_PROFILE` to apply a security profile at container start:

| Value | Description |
|-------|-------------|
| (unset) | Standard profile (default) |
| `@minimal` | Minimal — fewer checks, lower false positive rate |
| `@standard` | Standard — balanced security and usability |
| `@strict` | Strict — maximum security, all checks enabled |

You can also pass a custom profile name or path if you have saved custom profiles.

## Authentication

Pass authentication credentials as environment variables at runtime.

> **Tested configurations:** Anthropic API key and Google Vertex AI have been
> validated with this image. Other providers (AWS Bedrock, Azure, self-hosted)
> may require additional environment variables or volume mounts — consult the
> IDE's documentation for the required configuration.

### Anthropic API (direct)

```bash
podman run -it -p 63152 \
    -e ANTHROPIC_API_KEY=sk-ant-... \
    ai-guardian
```

### Google Vertex AI ✓ tested

```bash
podman run -it -p 63152 \
    -e CLAUDE_CODE_USE_VERTEX=1 \
    -e ANTHROPIC_VERTEX_PROJECT_ID=my-gcp-project \
    -e CLOUD_ML_REGION=global \
    -e GOOGLE_APPLICATION_CREDENTIALS=/sandbox/gcp-key.json \
    -v ~/my-gcp-key.json:/sandbox/gcp-key.json:ro \
    ai-guardian
```

### Other providers (untested)

Other Claude-compatible providers may work by passing the appropriate env vars.
The container does not pre-configure any provider-specific tooling beyond
Claude Code, so extra setup (CLI login, credential files, proxy config) may be
needed inside the container after startup.

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic API key (direct API access) |
| `CLAUDE_CODE_USE_VERTEX` | Set to `1` to use Google Vertex AI |
| `ANTHROPIC_VERTEX_PROJECT_ID` | GCP project ID (with Vertex AI) |
| `CLOUD_ML_REGION` | GCP region, e.g. `global` (with Vertex AI) |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP service account JSON key file (with Vertex AI) |

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

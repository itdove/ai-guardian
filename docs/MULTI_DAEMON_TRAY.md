# Multi-Daemon Tray Client

The system tray client discovers and manages AI Guardian daemons across multiple environments.

## Quick Start

```bash
ai-guardian daemon start          # Start local daemon (headless)
ai-guardian tray start            # Start tray (discovers all daemons)
ai-guardian tray start -b         # Start tray in background
ai-guardian tray stop             # Stop the tray
ai-guardian tray restart          # Restart the tray
```

> **Note**: The daemon runs headless. The tray is always a separate process.

## Instance Name

Set a human-friendly name in your config to identify this ai-guardian instance:

```json
{
  "name": "my-workstation"
}
```

The name appears in the Console banner, tray menu, REST API, and MCP.

If not set, defaults to `hostname`. For containers, the priority is:

1. Container label `ai-guardian.name` (set at run time)
2. Config `name` field (from `ai-guardian.json`)
3. Container name (from `podman ps`)
4. Hostname

## Tray Menu Structure

Each discovered daemon appears as a top-level menu item with its own submenu:

```
● local                         >
  Statistics                    >
  Console
  Violations
  Metrics
  Mode: auto                    >
  MCP Proactive: low            >
  Pause...                      >
  Resume
  Stop daemon
  Restart daemon
○ my-container (container)      >
  Console
  Violations
  Metrics
  Mode: auto                    >
  MCP Proactive: low            >
  Start daemon
─────────────
Restart
Quit
```

- **●** Running daemon — full submenu with Statistics, Pause/Resume, Stop/Restart
- **○** Stopped daemon — limited submenu with Console, Mode, Start daemon

## Discovery Methods

The tray discovers daemons using four methods:

| Runtime | Discovery | How |
|---------|-----------|-----|
| Local | PID file + socket ping | Check `~/.local/state/ai-guardian/daemon.pid` |
| Podman/Docker | `podman ps` / `docker ps` | Label filter + port filter (cascading) |
| Kubernetes | `kubectl get pods` | Label selector + user filter |
| Manual | Config file | `~/.config/ai-guardian/tray-targets.json` |

Discovery runs on-demand when the tray icon is clicked (~1 second to refresh).

### Container Discovery

Containers are discovered using two cascading filters:

1. **Label filter** (primary): Containers with `ai-guardian.daemon=true` label
2. **Port filter** (fallback): Containers with a port mapping to the REST port (default 63152)

Run a container daemon:

```bash
podman run -l ai-guardian.daemon=true -p :63152 your-image
```

Optional labels:
- `ai-guardian.name=my-sandbox` — display name in tray (defaults to container name)
- `ai-guardian.rest-port=8080` — custom REST port (defaults to 63152)

### Kubernetes Discovery

Disabled by default. Enable in config:

```json
{
  "daemon": {
    "tray": {
      "discover_kubernetes": true,
      "kubernetes": {
        "namespace": "ai-sdlc",
        "label_selector": "app=ai-guardian"
      }
    }
  }
}
```

Pods are filtered by the current user (`user=$USER` label added automatically).

### Manual Targets

Create `~/.config/ai-guardian/tray-targets.json`:

```json
{
  "daemons": [
    {
      "name": "central-server",
      "url": "https://guardian.company.com:63152",
      "token": "your-auth-token"
    }
  ]
}
```

Use `--no-discover` to skip auto-discovery and only load manual targets:

```bash
ai-guardian tray start --no-discover
```

## REST API

Each daemon exposes a REST API for tray communication:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/status` | GET | Daemon status (name, version, paused) |
| `/api/stats` | GET | Full stats (requests, blocked, violations) |
| `/api/pause` | POST | Pause scanning (`{"minutes": 15}`) |
| `/api/resume` | POST | Resume scanning |

### Bind Address

The REST API bind address is determined automatically:

- **Host machine**: `127.0.0.1` (localhost only, secure default)
- **Inside containers**: `0.0.0.0` (auto-detected via `/.dockerenv` or `/run/.containerenv`)
- **Override**: Set `daemon.rest_host` in config

The REST port is configurable via `daemon.rest_port` (default 63152, 0 = OS-assigned).

## Configuration Reference

```json
{
  "name": "my-workstation",
  "daemon": {
    "rest_port": 63152,
    "rest_host": "127.0.0.1",
    "tray": {
      "discover_containers": true,
      "discover_kubernetes": false,
      "kubernetes": {
        "namespace": "ai-sdlc",
        "label_selector": "app=ai-guardian"
      }
    }
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `name` | hostname | Instance name shown in tray, Console, REST API, MCP |
| `daemon.rest_port` | `63152` | REST API port (0 = OS-assigned) |
| `daemon.rest_host` | `127.0.0.1` | REST API bind address. Auto-set to `0.0.0.0` inside containers |
| `daemon.tray.discover_containers` | `true` | Enable Podman/Docker container discovery (scans all available engines) |
| `daemon.tray.discover_kubernetes` | `false` | Enable Kubernetes pod discovery |

## Action Routing

Each daemon's submenu routes actions to the correct transport:

| Action | Local | Container | Kubernetes |
|--------|-------|-----------|------------|
| Statistics | Unix socket | REST API | REST API |
| Console | New terminal | `podman exec -it` | `kubectl exec -it` |
| Pause/Resume | Unix socket | REST API | REST API |
| Start/Stop/Restart | Subprocess | `podman exec` | `kubectl exec` |

## CLI Reference

```bash
ai-guardian tray start              # Start tray (foreground)
ai-guardian tray start -b           # Start tray (background)
ai-guardian tray start --no-discover  # Manual targets only
ai-guardian tray stop               # Stop running tray
ai-guardian tray restart            # Restart tray
```

## Tray Plugins

Plugins add custom menu items to the tray. Each daemon loads plugins from its own `tray-plugins/` directory and serves them via the REST API. The tray fetches and displays them automatically.

### Creating a Plugin

Create a JSON file in `~/.config/ai-guardian/tray-plugins/`:

```json
{
    "name": "My Tools",
    "items": [
        {
            "label": "Say Hello",
            "command": "echo 'Hello {tray.name}!'",
            "type": "terminal",
            "params": [
                {"name": "name", "hint": "Your name", "default": "World"}
            ]
        },
        {
            "label": "Pod Count",
            "command": "kubectl get pods --no-headers | wc -l",
            "type": "notification"
        },
        {
            "label": "Copy Pod IP",
            "command": "kubectl get svc my-app -o jsonpath='{.spec.clusterIP}'",
            "type": "clipboard"
        },
        {
            "label": "Rebuild",
            "command": "make build",
            "type": "background"
        }
    ]
}
```

Each `.json` file in the directory becomes a submenu in the tray.

### Command Types

| Type | Behavior |
|------|----------|
| `terminal` | Opens a new terminal window and runs the command |
| `background` | Runs silently with no visible output |
| `notification` | Runs silently, shows stdout as a system notification |
| `clipboard` | Runs silently, copies stdout to the system clipboard |
| `modal` | Runs silently, shows output in a native OS dialog with OK button |

### Interactive Parameters

Items with `params` show a form before executing. The user fills in values, then the placeholders `{tray.name}` in the command are substituted.

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Matches `{tray.name}` placeholder in command |
| `hint` | No | Help text shown as label/placeholder |
| `default` | No | Pre-filled value |
| `options` | No | List of allowed values — renders as dropdown |

Example with a dropdown:

```json
{
    "label": "Deploy Branch",
    "command": "make deploy BRANCH={tray.branch} ENV={tray.environment}",
    "type": "terminal",
    "params": [
        {"name": "branch", "hint": "Git branch", "default": "main"},
        {"name": "environment", "default": "dev", "options": ["dev", "staging", "prod"]}
    ]
}
```

Items without `params` execute immediately on click.

### Platform-Aware Commands

Commands can vary by platform using a command map instead of a string:

```json
{
    "label": "Open Shell",
    "command": {
        "darwin": "open -a Terminal",
        "linux": "gnome-terminal",
        "windows": "cmd.exe /k",
        "default": "bash"
    },
    "type": "terminal"
}
```

Platform keys match `platform.system().lower()`: `darwin`, `linux`, `windows`. The `default` key is the fallback. If no key matches and no default is set, the menu item is hidden on that platform.

### Target Variables

Plugin commands can reference the daemon's target context using built-in variables. These are automatically substituted from the `DaemonTarget` before execution:

| Variable | Source | Example |
|---|---|---|
| `{container_id}` | `target.container_id` | `a1b2c3d4e5f6` |
| `{container_engine}` | `target.container_engine` | `podman` |
| `{host}` | `target.host` | `127.0.0.1` |
| `{port}` | `target.port` | `63152` |
| `{name}` | `target.name` | `carbonite-dev` |
| `{pod_name}` | `target.pod_name` | `guardian-pod-1` |
| `{namespace}` | `target.namespace` | `ai-guardian` |

Example:

```json
{
    "label": "Container Logs",
    "command": "{container_engine} logs --tail 50 {container_id}",
    "type": "terminal"
}
```

Target variables use bare `{name}` syntax (no prefix), while user parameters use `{tray.name}`. Both can coexist in the same command. If a target field is `null`, the placeholder is replaced with an empty string.

### Run on Target

When `run_on_target` is `true`, the tray automatically wraps the command for the daemon's runtime:

| Runtime | Wrapping |
|---------|----------|
| Container | `<engine> exec [-it] <container_id> <command>` |
| Kubernetes | `oc exec [-it] <pod> -n <namespace> -- <command>` (falls back to `kubectl` if `oc` is not installed) |
| Local | No wrapping — runs as-is |

The plugin author writes the command as if running locally inside the target. The tray handles routing:

```json
{
    "label": "Doctor",
    "command": "ai-guardian doctor",
    "run_on_target": true,
    "type": "terminal"
}
```

For container targets, this becomes: `podman exec -it a1b2c3d4e5f6 ai-guardian doctor`

Both features can coexist:

```json
{
    "items": [
        {"label": "Doctor", "command": "ai-guardian doctor", "run_on_target": true, "type": "terminal"},
        {"label": "Logs", "command": "{container_engine} logs --tail 50 {container_id}", "type": "terminal"},
        {"label": "Restart", "command": "{container_engine} restart {container_id}", "type": "notification"}
    ]
}
```

- **Doctor**: runs inside the container (automatic wrapping via `run_on_target`)
- **Logs**: runs on host, references the container (target variable substitution)
- **Restart**: runs on host, references the container (target variable substitution)

### Plugin Discovery via REST API

The tray does not read plugin files directly. Each daemon serves its plugins via:

```
GET /api/tray-plugins
```

This means plugins work uniformly across all daemon types:

| Daemon | Plugin location |
|--------|----------------|
| Local | `~/.config/ai-guardian/tray-plugins/` |
| Container | `/home/user/.config/ai-guardian/tray-plugins/` inside the container |
| Remote | `~/.config/ai-guardian/tray-plugins/` on the remote host |

The tray polls plugins alongside the stats refresh (every 10 seconds). Local plugins load even when the daemon is stopped.

### Plugin Limits

- Up to 8 plugins per daemon
- Up to 12 items per plugin
- These are pre-allocated pystray slots (macOS requires fixed menu structure)

## Migration from v1.7.x

In v1.7.x, `ai-guardian daemon start` launched both the daemon and the system tray. In v1.8.0+, these are separate:

```bash
# Before (v1.7.x)
ai-guardian daemon start          # Started daemon + tray

# After (v1.8.0+)
ai-guardian daemon start          # Headless daemon only
ai-guardian tray start            # Separate tray process
```

To restore the old behavior, add both commands to your startup/login items.

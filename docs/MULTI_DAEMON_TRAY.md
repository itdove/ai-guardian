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

## Daemon Name

Set a human-friendly name in your config to identify daemons in the tray:

```json
{
  "daemon": {
    "name": "my-workstation"
  }
}
```

If not set, the tray shows the container name (for containers) or "local" (for the local daemon).

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
  "daemon": {
    "name": "my-workstation",
    "rest_port": 63152,
    "rest_host": "127.0.0.1",
    "container_engine": "auto",
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
| `daemon.name` | *(unset)* | Display name in tray. Shows container name or "local" if not set |
| `daemon.rest_port` | `63152` | REST API port (0 = OS-assigned) |
| `daemon.rest_host` | `127.0.0.1` | REST API bind address. Auto-set to `0.0.0.0` inside containers |
| `daemon.container_engine` | `auto` | `auto` (podman > docker), `podman`, or `docker` |
| `daemon.tray.discover_containers` | `true` | Enable Podman/Docker container discovery |
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

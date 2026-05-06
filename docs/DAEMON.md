# Daemon & API Proxy

AI Guardian includes a background daemon service for faster hook processing and an opt-in HTTP reverse proxy for scanning IDE-to-API traffic.

## Daemon

The daemon is a long-running process that processes hook requests over Unix sockets (or TCP on Windows), eliminating per-invocation Python startup overhead and enabling cross-hook state sharing.

### Modes

| Mode | Behavior |
|------|----------|
| `auto` (default) | Daemon with fallback to per-process. Lazy start on first hook call. |
| `local` | Always per-process (for CI/CD and containers). |
| `daemon` | Require daemon, log errors if unavailable (testing/compliance). |

Override with `AI_GUARDIAN_DAEMON_MODE` environment variable.

### CLI Commands

```bash
ai-guardian daemon start [--background] [--idle-timeout N] [--no-tray]
ai-guardian daemon stop
ai-guardian daemon status
ai-guardian daemon restart
```

### Configuration

```json
{
  "daemon": {
    "mode": "auto",
    "idle_timeout_minutes": 30,
    "client_timeout_seconds": 2.0,
    "tray": {
      "enabled": true
    }
  }
}
```

## API Proxy

The proxy is an opt-in feature that runs alongside the daemon. It sits between the IDE and the AI backend API, scanning both outgoing requests (user prompts) and incoming responses (AI outputs) at the network level.

### How It Works

1. Enable proxy in config and point your IDE to the proxy URL
2. The proxy receives API requests from the IDE
3. It extracts text content from the API payload (messages, system prompt, etc.)
4. It applies all enabled ai-guardian scans (secrets, PII, prompt injection, etc.)
5. If violations are found, it acts according to each scan's configured action
6. Clean requests are forwarded to the backend API
7. Responses are scanned the same way before being returned to the IDE

### Setup: Direct Anthropic API

**Option A: Edit config file** (`~/.config/ai-guardian/ai-guardian.json`):
```json
{
  "daemon": {
    "proxy": {
      "enabled": true,
      "backend_url": "https://api.anthropic.com"
    }
  }
}
```

**Option B: Use the interactive console:**
```bash
ai-guardian console
# Navigate to Daemon panel → Proxy section → set Enabled to true
```

Then point your IDE to the proxy and start the daemon:
```bash
export ANTHROPIC_BASE_URL=http://localhost:63152
ai-guardian daemon start
```

**URL rule:** `backend_url` is the host only (no path). The SDK includes the path (e.g., `/v1/messages`) which the proxy appends to `backend_url`.

### Setup: GCP Vertex AI

Edit your config file (`~/.config/ai-guardian/ai-guardian.json`). The `backend_url` depends on your `CLOUD_ML_REGION`:

| Region | `backend_url` |
|--------|---------------|
| `global` | `https://aiplatform.googleapis.com` |
| `us-east5` | `https://us-east5-aiplatform.googleapis.com` |
| `europe-west4` | `https://europe-west4-aiplatform.googleapis.com` |
| Other regions | `https://{REGION}-aiplatform.googleapis.com` |

**Example for `global` region:**
```json
{
  "daemon": {
    "proxy": {
      "enabled": true,
      "backend_url": "https://aiplatform.googleapis.com"
    }
  }
}
```

**Example for `us-east5` region:**
```json
{
  "daemon": {
    "proxy": {
      "enabled": true,
      "backend_url": "https://us-east5-aiplatform.googleapis.com"
    }
  }
}
```

**Important:** The `backend_url` must be the host only -- do NOT include `/v1`. The SDK already includes `/v1` in the request path it sends to the proxy. The `global` region uses `aiplatform.googleapis.com` without a region prefix.

Or use `ai-guardian console` → Daemon panel → set Backend URL to your Vertex host (without `/v1`).

Then set the environment variables and start:
```bash
# Point Claude Code's Vertex client to the proxy
# Must include /v1 to match the SDK's default base URL structure
export ANTHROPIC_VERTEX_BASE_URL=http://localhost:63152/v1

# Keep your normal Vertex env vars
export CLAUDE_CODE_USE_VERTEX=1
export ANTHROPIC_VERTEX_PROJECT_ID=your-project-id
export CLOUD_ML_REGION=us-east5

# Start daemon (proxy starts automatically)
ai-guardian daemon start
```

**URL path flow:**
1. SDK sends to `http://localhost:63152/v1/projects/{project}/...`
2. Proxy receives path `/v1/projects/{project}/...`
3. Proxy forwards to `https://us-east5-aiplatform.googleapis.com` + `/v1/projects/{project}/...`

The proxy forwards all request headers (including Google Cloud `Authorization: Bearer ...` tokens), so Vertex authentication works transparently.

### Configuration

```json
{
  "daemon": {
    "mode": "auto",
    "proxy": {
      "enabled": false,
      "listen_port": 63152,
      "backend_url": "https://api.anthropic.com",
      "tls": {
        "verify_backend": true,
        "client_cert": null,
        "client_key": null
      },
      "auth": {
        "mode": "pass-through"
      }
    }
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `enabled` | `false` | Enable the proxy |
| `listen_port` | `63152` | Port to listen on (dynamic range) |
| `backend_url` | `https://api.anthropic.com` | Backend API host to forward to (no path -- the SDK provides the path) |
| `tls.verify_backend` | `true` | Verify backend SSL certificate |
| `tls.client_cert` | `null` | Client cert for mTLS |
| `tls.client_key` | `null` | Client key for mTLS |
| `auth.mode` | `pass-through` | Authentication mode |

### Scanning

The proxy reuses all existing scan configurations. There are no separate scan toggles -- if `secret_scanning.enabled` is `true`, the proxy scans for secrets. If `prompt_injection.action` is `block`, the proxy blocks requests with detected injections.

Scans applied:
- **Secrets** (both directions) -- uses `secret_scanning` config
- **PII** (both directions) -- uses `scan_pii` config
- **Prompt Injection** (requests only) -- uses `prompt_injection` config

### Mode Interaction

| `daemon.mode` | `proxy.enabled` | Behavior |
|---|---|---|
| `local` | ignored | Per-process hooks, no daemon, no proxy |
| `auto` | `false` | Daemon for IPC + in-memory state, no proxy |
| `auto` | `true` | Daemon + proxy on configured port |

### Authentication Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `pass-through` | Forward IDE's auth headers as-is | Developer has their own API key |
| `credential-injection` | Proxy injects API key from secure storage | Enterprise -- developers never see the API key |
| `oauth` | Proxy manages OAuth client credentials flow | Corporate SSO environments |
| `user-auth` | Developers authenticate to proxy via SSO | Centralized deployment with per-user tracking |

Phase 1 supports `pass-through` only. Other modes are planned for future releases.

### TLS Settings

The TLS section controls the connection between the proxy and the backend:

- **`verify_backend`**: Set to `false` for corporate environments with self-signed certificates on internal API endpoints.
- **`client_cert`/`client_key`**: For mTLS where the proxy authenticates to the backend on behalf of all users.

### Streaming

Streaming requests (`"stream": true` in the API payload) are currently passed through without scanning. Streaming support (SSE buffering and scanning) is planned for Phase 2.

### Port Selection

The default port 63152 was chosen because:
- It's in the dynamic/private range (49152-65535)
- It's deterministic (derived from hash of "ai-guardian-proxy")
- It's unlikely to conflict with common services

### System Tray

The system tray icon includes a proxy menu item showing:
- Current proxy status (enabled/disabled with port and request count)
- Toggle to enable/disable proxy (updates config and reloads)

### Monitoring

```bash
# Check daemon and proxy status
ai-guardian daemon status

# Output includes proxy stats:
# Proxy: port 63152 (42 requests, 3 violations, 0 blocked)
```

The interactive console (`ai-guardian console` -> Daemon panel) also shows proxy statistics.

# AI Guardian SDK

Programmatic security checking for Python agent programs.

## Overview

AI Guardian's hook-based protection covers IDE sessions (Claude Code, Cursor, VS Code). The SDK extends this protection to **programmatic use cases** — custom agents, LangChain pipelines, direct LLM API calls, and any Python program that processes untrusted content.

The SDK is **additive protection**. It cannot bypass or weaken existing hook-based enforcement. Hooks remain the enforcement layer for IDE sessions; the SDK serves programs where hooks don't apply.

## Installation

The SDK is included with ai-guardian. No additional installation required.

```bash
pip install ai-guardian
```

## Quick Start

```python
from ai_guardian.sdk import monitor

# Check content for threats (secrets, prompt injection, context poisoning)
with monitor(action="block") as session:
    session.check_content(user_input)
    session.check_file("/path/to/config.json")
    session.check_command("curl http://example.com")
```

## API Reference

### `monitor(action, mode, config)`

Context manager that creates a guarded session.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | str | `"block"` | `"block"` raises `SecurityViolation`, `"warn"` emits warning, `"log"` records silently |
| `mode` | str | `"direct"` | `"direct"` runs checks in-process, `"rest"` delegates to daemon |
| `config` | dict | `None` | Config override. If `None`, loads from `ai-guardian.json` |

**Yields:** `GuardSession` with the methods below.

### `session.check_content(text, *, filename="input")`

Checks text for:
- **Secrets** — API keys, passwords, tokens (via Gitleaks)
- **Prompt injection** — attempts to override system instructions
- **Context poisoning** — hidden instructions in seemingly benign content

Returns `CheckResult`.

### `session.check_file(file_path, content=None)`

Checks a file path against directory access rules. If `content` is provided, also scans for:
- **Config file exfiltration** — attempts to read sensitive config files
- **Supply chain threats** — suspicious agent configuration patterns
- All content checks (secrets, prompt injection, context poisoning)

Returns `CheckResult`.

### `session.check_command(command)`

Checks a bash command for:
- **Config exfiltration patterns** — commands that attempt to read/send sensitive files

Returns `CheckResult`.

### `session.sanitize(text)`

Redacts secrets, PII, and sensitive patterns from text.

Returns a dict:
```python
{
    "sanitized_text": "...",
    "redactions": [...],
    "stats": {"secrets": 0, "pii": 0, "total": 0}
}
```

### `session.results`

Property that returns all `CheckResult` objects collected during the session.

### `CheckResult`

Dataclass returned by all check methods.

| Field | Type | Description |
|-------|------|-------------|
| `blocked` | bool | Whether the check triggered a block |
| `detected` | bool | Whether any issue was detected |
| `violation_type` | str or None | Type: `secret_detected`, `prompt_injection`, `context_poisoning`, `directory_blocked`, `config_file_exfil`, `supply_chain_threat` |
| `message` | str or None | Human-readable description |
| `details` | dict or None | Additional context from the detector |

### `SecurityViolation`

Exception raised when `action="block"` and a threat is detected.

```python
try:
    with monitor(action="block") as session:
        session.check_content(untrusted_text)
except SecurityViolation as e:
    print(f"Blocked: {e.result.violation_type} — {e.result.message}")
```

## Modes

### Direct Mode (default)

Calls detection functions in-process. No daemon required. Best for single-program use.

```python
with monitor(mode="direct") as session:
    session.check_content(text)
```

### REST Mode

Delegates checks to the ai-guardian daemon via socket protocol. Auto-starts the daemon if not running. Best for shared daemon usage across multiple programs.

```python
with monitor(mode="rest") as session:
    session.check_content(text)
```

**Auto-start behavior:**
1. Checks if daemon is running (socket ping)
2. If not, starts it in the background
3. Waits for daemon to become responsive
4. Proceeds with checks via daemon
5. Does **not** stop daemon on session exit (other programs may use it)

## Action Modes

### `"block"` (default)

Raises `SecurityViolation` immediately when a threat is detected. Use for strict enforcement.

```python
with monitor(action="block") as session:
    session.check_content(text)  # raises SecurityViolation if threat found
```

### `"warn"`

Emits a Python `UserWarning` when a threat is detected. Execution continues.

```python
import warnings
warnings.filterwarnings("error", category=UserWarning)  # optional: treat as error

with monitor(action="warn") as session:
    session.check_content(text)  # warnings.warn() if threat found
```

### `"log"`

Silently records results. No exceptions, no warnings. Access results via `session.results`.

```python
with monitor(action="log") as session:
    session.check_content(text1)
    session.check_content(text2)
    
for result in session.results:
    if result.detected:
        print(f"Found: {result.violation_type}")
```

## Examples

### Protect a LangChain Agent

```python
from ai_guardian.sdk import monitor, SecurityViolation

def safe_agent_call(prompt):
    with monitor(action="block") as guard:
        # Check user input before sending to LLM
        guard.check_content(prompt)
        
        # Call your LLM
        response = llm.invoke(prompt)
        
        # Check LLM output before returning to user
        guard.check_content(response.content, filename="llm_output")
        
        return response.content
```

### Scan Files Before Processing

```python
from ai_guardian.sdk import monitor

with monitor(action="warn") as guard:
    for path in uploaded_files:
        content = open(path).read()
        result = guard.check_file(path, content=content)
        if result.blocked:
            print(f"Skipping {path}: {result.message}")
```

### Sanitize Output

```python
from ai_guardian.sdk import monitor

with monitor() as guard:
    sanitized = guard.sanitize(potentially_sensitive_text)
    print(sanitized["sanitized_text"])  # secrets and PII redacted
```

### Batch Content Screening

```python
from ai_guardian.sdk import monitor

with monitor(action="log") as guard:
    for item in documents:
        guard.check_content(item.text)
    
    threats = [r for r in guard.results if r.detected]
    print(f"Found {len(threats)} issues in {len(documents)} documents")
```

## Configuration

The SDK respects `ai-guardian.json` configuration. Features can be enabled/disabled:

```json
{
    "secret_scanning": {"enabled": true},
    "prompt_injection": {"enabled": true, "action": "block"},
    "context_poisoning": {"enabled": true},
    "config_scanner": {"enabled": true},
    "supply_chain": {"enabled": true}
}
```

Override configuration per-session:

```python
custom_config = {
    "secret_scanning": {"enabled": True},
    "prompt_injection": {"enabled": False},  # skip for this session
}

with monitor(config=custom_config) as session:
    session.check_content(text)
```

## REST API (Multi-Language)

For non-Python languages (TypeScript, Go, Java, Rust, etc.), ai-guardian exposes HTTP endpoints on the daemon's REST API. The daemon must be running:

```bash
ai-guardian daemon start
```

The REST API port is shown in `ai-guardian daemon status`. Default: `19200`.

### POST /api/check

Scan content for security threats.

**Request:**

```bash
curl -X POST http://localhost:19200/api/check \
  -H "Content-Type: application/json" \
  -d '{
    "content": "text to scan",
    "checks": ["secrets", "pii", "injection", "context_poisoning"],
    "action": "block",
    "source": "sdk"
  }'
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `content` | string | **required** | Text to scan |
| `checks` | array | all checks | Which checks to run: `secrets`, `pii`, `injection`, `ssrf`, `context_poisoning` |
| `action` | string | `"block"` | Action mode: `block`, `warn`, or `log` (recorded in findings) |
| `source` | string | `"sdk"` | Optional source identifier for audit trail |

**Response:**

```json
{
  "clean": false,
  "findings": [
    {
      "type": "secret_detected",
      "message": "GitHub token detected",
      "action_taken": "block"
    }
  ],
  "redacted": "text with [REDACTED] token",
  "elapsed_ms": 12.3
}
```

| Field | Type | Description |
|-------|------|-------------|
| `clean` | bool | `true` if no threats detected |
| `findings` | array | List of detected threats |
| `redacted` | string or null | Auto-redacted text (only when findings exist) |
| `elapsed_ms` | float | Processing time in milliseconds |

### POST /api/redact

Redact secrets and PII from text without checking for threats.

**Request:**

```bash
curl -X POST http://localhost:19200/api/redact \
  -H "Content-Type: application/json" \
  -d '{"content": "my token is ghp_abc123..."}'
```

**Response:**

```json
{
  "redacted": "my token is [REDACTED]",
  "redaction_count": 1
}
```

### Authentication

If the daemon has `auth_token` configured in `ai-guardian.json`:

```bash
curl -X POST http://localhost:19200/api/check \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content": "text to scan"}'
```

### Language SDK Examples

Each language SDK is a thin HTTP client wrapper around these endpoints.

**TypeScript/Node:**

```typescript
const response = await fetch('http://localhost:19200/api/check', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ content: text }),
});
const result = await response.json();
if (!result.clean) {
  throw new Error(result.findings[0].message);
}
```

**Go:**

```go
body, _ := json.Marshal(map[string]string{"content": text})
resp, err := http.Post(
    "http://localhost:19200/api/check",
    "application/json",
    bytes.NewReader(body),
)
var result struct {
    Clean    bool `json:"clean"`
    Findings []struct {
        Type    string `json:"type"`
        Message string `json:"message"`
    } `json:"findings"`
}
json.NewDecoder(resp.Body).Decode(&result)
```

**Java:**

```java
HttpClient client = HttpClient.newHttpClient();
String json = "{\"content\": \"" + text + "\"}";
HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("http://localhost:19200/api/check"))
    .header("Content-Type", "application/json")
    .POST(HttpRequest.BodyPublishers.ofString(json))
    .build();
HttpResponse<String> response = client.send(request,
    HttpResponse.BodyHandlers.ofString());
```

**Rust:**

```rust
let client = reqwest::Client::new();
let result: serde_json::Value = client
    .post("http://localhost:19200/api/check")
    .json(&serde_json::json!({"content": text}))
    .send().await?
    .json().await?;
```

**Shell (no SDK needed):**

```bash
result=$(curl -s -X POST http://localhost:19200/api/check \
  -H "Content-Type: application/json" \
  -d "{\"content\": \"$TEXT\"}")
clean=$(echo "$result" | jq -r '.clean')
```

## Security Model

- **Additive only**: The SDK adds protection to programs that have none. It cannot disable or bypass hook-based enforcement.
- **No pattern exposure**: `CheckResult` returns blocked/detected status and a human-readable message, not internal detection patterns or regex rules.
- **Same detection engine**: Both direct and REST modes use the same detection functions as the hook system.
- **Config-gated**: Each detector respects its `enabled` flag in the configuration.

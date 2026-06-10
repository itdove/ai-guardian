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

## Security Model

- **Additive only**: The SDK adds protection to programs that have none. It cannot disable or bypass hook-based enforcement.
- **No pattern exposure**: `CheckResult` returns blocked/detected status and a human-readable message, not internal detection patterns or regex rules.
- **Same detection engine**: Both direct and REST modes use the same detection functions as the hook system.
- **Config-gated**: Each detector respects its `enabled` flag in the configuration.

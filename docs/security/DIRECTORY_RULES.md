# Directory Rules

AI Guardian's Directory Rules control what files and directories the AI assistant can access, preventing unauthorized reading or modification of sensitive files.

## What are Directory Rules?

**Directory Rules** define which paths the AI can and cannot access:
- ✅ **Allow specific directories** - Let AI work in project folders
- ❌ **Deny sensitive paths** - Block access to credentials, keys, system files
- 🔒 **Layer with .ai-read-deny** - Per-directory markers for extra protection
- 🎯 **Last match wins** - Flexible rule ordering for complex scenarios

Think of it as a **firewall for your file system** - controlling exactly which files the AI can see and touch.

---

## What You're Protected Against

### 1. Credential File Access

**Threat:** AI reads sensitive credential files

**Examples Blocked:**
```
~/.ssh/id_rsa              # SSH private key
~/.aws/credentials         # AWS credentials
~/.config/gcloud/          # Google Cloud credentials
~/.docker/config.json      # Docker registry tokens
~/.netrc                   # Network credentials
~/.pgpass                  # PostgreSQL passwords
```

**Protection:** Directory rules block access to credential directories

---

### 2. System Configuration

**Threat:** AI reads or modifies system files

**Examples Blocked:**
```
/etc/shadow               # Password hashes
/etc/sudoers             # Sudo configuration
/etc/passwd              # User accounts
/root/*                  # Root directory
/sys/*                   # System files
/proc/*/environ          # Process environment variables
```

**Protection:** System directories are off-limits

---

### 3. Private Keys & Certificates

**Threat:** AI accesses encryption keys

**Examples Blocked:**
```
*.key                    # Key files
*.pem                    # Certificate files
*.p12                    # PKCS#12 keystores
*.keystore              # Java keystores
*.pfx                   # Personal Information Exchange
```

**Protection:** File extension patterns block key files

---

### 4. Source Control Internals

**Threat:** AI accesses git history or internal files

**Examples Blocked:**
```
.git/config             # Git configuration (may contain URLs with tokens)
.git/hooks/             # Git hooks (could contain scripts)
.svn/                   # Subversion internals
.hg/                    # Mercurial internals
```

**Protection:** Version control directories blocked

---

### 5. Environment & Secrets

**Threat:** AI reads environment variables or secret files

**Examples Blocked:**
```
.env                    # Environment variables
.env.local              # Local environment
secrets.yml             # Secret configuration
credentials.json        # Service credentials
*.secret                # Secret files
```

**Protection:** Environment and secret file patterns blocked

---

## How It Works

### Rule Evaluation

Rules are evaluated **in order**, with the **last matching rule winning**:

```
1. AI tries to read a file
   ↓
2. Check directory rules in order (top to bottom)
   ↓
3. Each rule checks if pattern matches
   ↓
4. Last matching rule determines outcome
   ↓
5. If no rules match, default behavior applies
   ↓
6. Action: ALLOW or BLOCK
```

### Rule Types

Each rule can:

| Type | Effect | Example |
|------|--------|---------|
| **Allow** | Permit access to matching paths | Allow `~/projects/*` |
| **Deny** | Block access to matching paths | Deny `~/.ssh/*` |

### Last Match Wins

This allows flexible configurations:

```json
{
  "directory_rules": {
    "rules": [
      {"pattern": "~/projects/*", "action": "allow"},
      {"pattern": "~/projects/sensitive/*", "action": "deny"}
    ]
  }
}
```

Result:
- ✅ `~/projects/app/src/` - Allowed (matches first rule)
- ❌ `~/projects/sensitive/keys/` - Denied (matches second rule, which is last)

---

## Configuration

Directory rules are configured in `directory_rules` section:

```json
{
  "directory_rules": {
    "action": "block",
    "rules": [
      {
        "pattern": "~/.ssh/*",
        "action": "deny",
        "reason": "SSH private keys"
      },
      {
        "pattern": "~/.aws/*",
        "action": "deny",
        "reason": "AWS credentials"
      },
      {
        "pattern": "~/projects/*",
        "action": "allow",
        "reason": "Project files OK"
      }
    ]
  }
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `action` | Default action when no rules match | `"block"` |
| `rules` | Array of directory rule objects | `[]` |

### Rule Object

| Field | Required | Description |
|-------|----------|-------------|
| `pattern` | Yes | Glob pattern (e.g., `~/.ssh/*`) |
| `action` | Yes | `"allow"` or `"deny"` |
| `reason` | No | Human-readable explanation |

---

## Pattern Syntax

Directory rules support glob patterns:

| Pattern | Matches | Example |
|---------|---------|---------|
| `*` | Any characters except `/` | `*.key` matches `private.key` |
| `**` | Any characters including `/` | `~/.ssh/**` matches all files in .ssh recursively |
| `?` | Single character | `file?.txt` matches `file1.txt`, `file2.txt` |
| `[abc]` | Character set | `file[123].txt` matches `file1.txt`, `file2.txt`, `file3.txt` |

### Examples

```json
{
  "rules": [
    {
      "pattern": "~/.ssh/*",
      "action": "deny",
      "reason": "Block SSH directory"
    },
    {
      "pattern": "**/.env",
      "action": "deny",
      "reason": "Block all .env files"
    },
    {
      "pattern": "~/projects/**/*.py",
      "action": "allow",
      "reason": "Allow Python files in projects"
    },
    {
      "pattern": "/etc/**",
      "action": "deny",
      "reason": "Block system configuration"
    }
  ]
}
```

---

## .ai-read-deny Markers

In addition to directory rules, you can place `.ai-read-deny` marker files:

**Create marker:**
```bash
touch ~/.ssh/.ai-read-deny
```

**Effect:** Blocks AI from reading **any file** in that directory and subdirectories.

**Precedence:** `.ai-read-deny` markers override directory rules.

### Use Cases for Markers

**1. Quick protection:**
```bash
# Protect entire directory
touch ~/sensitive-data/.ai-read-deny
```

**2. Team-wide protection:**
```bash
# Commit marker to git (team-wide)
touch secrets/.ai-read-deny
git add secrets/.ai-read-deny
git commit -m "Block AI access to secrets/"
```

**3. Temporary protection:**
```bash
# Protect for this session only
touch /tmp/work/.ai-read-deny
# Remove later
rm /tmp/work/.ai-read-deny
```

---

## Real-World Scenarios

### Scenario 1: SSH Key Protection

**Without Directory Rules:**
```
User: "Show me my SSH configuration"
AI: cat ~/.ssh/id_rsa
```
💥 **Disaster:** Private SSH key exposed

**With Directory Rules:**
```json
{
  "rules": [
    {"pattern": "~/.ssh/*", "action": "deny"}
  ]
}
```
🛡️ **Protected:**
```
🚨 BLOCKED BY DIRECTORY RULES

File: ~/.ssh/id_rsa
Reason: SSH private keys
Pattern: ~/.ssh/*

This directory contains sensitive credentials.
```

---

### Scenario 2: Environment Variables

**Without Directory Rules:**
```
User: "Check the environment configuration"
AI: cat .env
```
💥 **Disaster:** API keys and database passwords exposed

**With Directory Rules:**
```json
{
  "rules": [
    {"pattern": "**/.env", "action": "deny"},
    {"pattern": "**/.env.*", "action": "deny"}
  ]
}
```
🛡️ **Protected:** All `.env` files blocked across all directories

---

### Scenario 3: Project-Specific Access

**Goal:** Allow AI to work in projects, but not in sensitive subdirectories

**Configuration:**
```json
{
  "rules": [
    {"pattern": "~/projects/*", "action": "allow"},
    {"pattern": "~/projects/*/secrets/**", "action": "deny"},
    {"pattern": "~/projects/*/.env", "action": "deny"}
  ]
}
```

**Results:**
- ✅ `~/projects/app/src/main.py` - Allowed
- ✅ `~/projects/api/tests/test.py` - Allowed
- ❌ `~/projects/app/secrets/keys.json` - Denied (secrets subdirectory)
- ❌ `~/projects/api/.env` - Denied (environment file)

---

## Default Protection

AI Guardian ships with sensible defaults:

### Commonly Blocked Paths

```
~/.ssh/                  (SSH keys)
~/.aws/                  (AWS credentials)
~/.config/gcloud/        (GCP credentials)
~/.docker/config.json    (Docker credentials)
/etc/shadow              (Password hashes)
/root/                   (Root directory)
**/.env                  (Environment variables)
**/*.key                 (Key files)
**/*.pem                 (Certificate files)
```

### Commonly Allowed Paths

```
~/projects/              (Project files)
~/Documents/             (User documents)
/tmp/                    (Temporary files)
```

You can override defaults with your own rules.

---

## Integration with Tool Policy

Directory Rules work **alongside** Tool Policy:

```
Layer 1: Tool Policy
         ↓ Checks if "Read" tool allowed for this file
         ↓ (Allowed)
         
Layer 2: Directory Rules ← YOU ARE HERE
         ↓ Checks if file path matches deny rules
         ↓ (Denied: ~/.ssh/id_rsa)
         
Result: 🛡️ Blocked by Directory Rules
```

**Both must allow** for the operation to succeed.

---

## Performance Impact

Directory rule checking is **extremely fast**:

- **Pattern matching:** ~0.05ms per file access
- **Marker check:** ~0.01ms per directory
- **Total:** <0.1ms per file operation

**Impact:** Negligible - file access is not slowed down.

---

## Best Practices

### Start Restrictive

```json
{
  "directory_rules": {
    "action": "block",
    "rules": [
      {"pattern": "~/projects/*", "action": "allow"},
      {"pattern": "~/Documents/*", "action": "allow"}
    ]
  }
}
```

**Strategy:** Block everything by default, explicitly allow needed paths.

### Layer Protection

```json
{
  "rules": [
    {"pattern": "~/work/*", "action": "allow"},
    {"pattern": "~/work/secrets/**", "action": "deny"},
    {"pattern": "~/work/**/.env", "action": "deny"}
  ]
}
```

**Strategy:** Allow broad category, then deny specific sensitive areas.

### Use Markers for Directories

```bash
# Instead of complex patterns, use simple marker
touch ~/sensitive/.ai-read-deny
```

**Benefits:**
- Simpler than glob patterns
- Team-wide (committed to git)
- Self-documenting

---

## See Also

- [Tool Policy](../TOOL_POLICY.md) - Command execution controls
- [SSRF Protection](SSRF_PROTECTION.md) - Network attack prevention
- [Configuration Guide](../CONFIGURATION.md) - Full configuration reference
- [Violation Logging](../VIOLATION_LOGGING.md) - Audit trail documentation

---

## Summary

**Directory Rules** protect you by:

🔒 **Blocking credential access** - SSH keys, AWS credentials, API tokens protected  
🔒 **Preventing system file access** - /etc/, /root/ off-limits  
🔒 **Protecting sensitive directories** - .env files, secrets/ folders blocked  
🔒 **Flexible rule ordering** - Last match wins for complex scenarios  
🔒 **.ai-read-deny markers** - Per-directory protection anyone can add

**You control** which files and directories the AI can access on your system.

---

## Version History

- **v1.0.0** - Initial directory rules with glob patterns
- **v1.2.0** - Added .ai-read-deny marker support
- **v1.3.0** - Last-match-wins rule ordering
- **v1.5.0** - Enhanced violation logging integration

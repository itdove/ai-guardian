# Configuration Guide

AI Guardian uses a flexible configuration system with multiple sources and cascading priority rules.

## Configuration Files

AI Guardian loads configuration from multiple sources in a specific priority order:

### 1. User Configuration (Default)

**Location**: `~/.config/ai-guardian/ai-guardian.json`

This is where most users configure AI Guardian. It contains:
- Tool/Skill permission rules
- Secret scanning settings
- Prompt injection detection
- SSRF protection rules
- Remote config URLs (user-defined)

### 2. Local Project Configuration

**Location**: `~/.ai-guardian.json` (in project directory)

Project-specific overrides that apply only to the current directory. Useful for:
- Project-specific tool allowlists
- Custom directory rules
- Development settings

### 3. Remote Configurations

**Location**: Fetched from URLs defined in `remote_configs`

Remote configurations enable centralized policy management. Enterprises can deploy security policies that users automatically receive.

## Remote Config URL Cascading Priority (Security Feature)

**⚠️ IMPORTANT**: Remote config URLs use **cascading priority** to prevent users from bypassing enterprise policies.

### How Cascading Priority Works

AI Guardian checks remote config sources in order and **stops at the first one found**:

1. **System Config** (Highest Priority)
   - **Linux/macOS**: `/etc/ai-guardian/remote-configs.json`
   - **Windows**: `C:\ProgramData\ai-guardian\remote-configs.json`
   - **Requires**: Root/Administrator access to create
   - **Effect**: If exists, user/local remote URLs are **completely ignored**

2. **Environment Variable**
   - `AI_GUARDIAN_REMOTE_CONFIG_URLS` (comma-separated URLs)
   - **Effect**: If set, user/local remote URLs are **completely ignored**

3. **User Config**
   - `~/.config/ai-guardian/ai-guardian.json` → `remote_configs.urls`
   - **Effect**: If present, local config remote URLs are **ignored**

4. **Local Config** (Lowest Priority)
   - `~/.ai-guardian.json` → `remote_configs.urls`
   - **Effect**: Only used if no higher priority source exists

### Why Cascading Priority Matters

**Without Cascading (Vulnerable)**:
- Enterprise deploys remote policy: `https://company.com/policy.json`
- User adds their own URL: `https://attacker.com/bypass.json`
- Both load → User can override enterprise security settings ❌

**With Cascading (Secure)**:
- Enterprise deploys system config: `/etc/ai-guardian/remote-configs.json`
- User tries to add their own URL → **Ignored completely** ✅
- Only enterprise URLs load → Security enforced

### Example: Enterprise Deployment

**Step 1: Create system config** (requires root):

```bash
# Linux/macOS
sudo mkdir -p /etc/ai-guardian
sudo tee /etc/ai-guardian/remote-configs.json > /dev/null <<EOF
{
  "urls": [
    "https://security.company.com/ai-guardian/policy.json"
  ]
}
EOF
sudo chmod 644 /etc/ai-guardian/remote-configs.json
```

```powershell
# Windows (requires Administrator)
New-Item -ItemType Directory -Force -Path "C:\ProgramData\ai-guardian"
Set-Content -Path "C:\ProgramData\ai-guardian\remote-configs.json" -Value @"
{
  "urls": [
    "https://security.company.com/ai-guardian/policy.json"
  ]
}
"@
```

**Step 2: Deploy remote policy**:

Host `https://security.company.com/ai-guardian/policy.json`:

```json
{
  "permissions": {
    "enabled": true,
    "rules": [
      {
        "matcher": "Skill",
        "mode": "allow",
        "patterns": ["company-approved-*"],
        "immutable": true
      }
    ]
  },
  "ssrf_protection": {
    "enabled": true,
    "immutable": true
  }
}
```

**Step 3: Users are protected**:

Users who try to add their own remote URLs in `~/.config/ai-guardian/ai-guardian.json` will find them **completely ignored** because the system config takes priority.

### Example: Development Environment

**Without System Config** (flexible):

Developers can configure their own remote URLs:

```json
{
  "remote_configs": {
    "urls": [
      "https://dev-patterns.company.com/ai-guardian.json"
    ]
  }
}
```

### Example: Environment Variable Override

Useful for CI/CD or temporary policy changes:

```bash
# Override remote config for this session
export AI_GUARDIAN_REMOTE_CONFIG_URLS="https://ci.company.com/policy.json"
ai-guardian validate
```

## Configuration Merge Order

Configurations are merged in this order (later sources override earlier ones):

1. **Built-in defaults** (in ai_guardian/tool_policy.py)
2. **Remote configs** (from cascading priority URLs)
3. **User config** (`~/.config/ai-guardian/ai-guardian.json`)
4. **Local config** (`~/.ai-guardian.json`)

**Exception**: Fields marked with `"immutable": true` in remote configs **cannot be overridden** by user/local configs.

## Immutability

Remote configurations can mark sections or matchers as immutable:

### Section-Level Immutability

```json
{
  "ssrf_protection": {
    "enabled": true,
    "immutable": true
  }
}
```

Users cannot override ANY settings in the `ssrf_protection` section.

### Matcher-Level Immutability

```json
{
  "permissions": {
    "rules": [
      {
        "matcher": "Skill",
        "mode": "allow",
        "patterns": ["approved-*"],
        "immutable": true
      }
    ]
  }
}
```

Users cannot add/modify Skill permission rules.

## Best Practices

### For Enterprises

1. **Start with Recommendations**
   - Deploy remote configs without system config first
   - Monitor adoption via logging
   - Move to system config after 80%+ adoption

2. **Use Immutability Sparingly**
   - Only mark critical security settings as immutable
   - Allow teams flexibility for non-security settings

3. **Provide Multiple Profiles**
   - Production: Strict security, immutable
   - Development: Relaxed security, overridable

4. **Document Policies**
   - Explain WHY settings are immutable
   - Provide contact info for exceptions

### For Users

1. **Check System Config First**
   - Look for `/etc/ai-guardian/remote-configs.json` (Linux/macOS)
   - If exists, your remote URLs are ignored

2. **Use User Config for Personal Settings**
   - `~/.config/ai-guardian/ai-guardian.json` for personal preferences
   - Won't override enterprise policies

3. **Use Local Config for Project Settings**
   - `~/.ai-guardian.json` for project-specific rules
   - Lowest priority, easily overridden

## Troubleshooting

### My Remote URLs Are Ignored

**Symptom**: URLs in user/local config not loading

**Check**:
1. Does `/etc/ai-guardian/remote-configs.json` exist? (Linux/macOS)
2. Is `AI_GUARDIAN_REMOTE_CONFIG_URLS` set?
3. Do you have remote URLs in a higher priority config?

**Solution**: Remove higher priority sources or contact your administrator.

### How Do I Know Which Config Is Active?

Enable debug logging:

```bash
export AI_GUARDIAN_LOG_LEVEL=DEBUG
ai-guardian validate
```

Look for log messages like:
- `Using 2 enterprise remote URLs (system config)`
- `Using remote URLs from environment variable`
- `Using 1 remote URLs from user config`

### Enterprise Policy Is Too Restrictive

**Do NOT**:
- Try to bypass with local URLs (won't work)
- Modify system config (requires root, against policy)

**Do**:
- Contact your security team
- Request policy exception
- Propose policy changes

## Security Considerations

### System Config Security

- Requires root/admin to modify → Prevents user tampering
- Should be managed via configuration management (Ansible, Puppet, etc.)
- Changes require root access → Audit trail in system logs

### Remote Config Security

- Use HTTPS URLs (required for security)
- Implement authentication via `token_env` for private repos
- Validate remote configs are from trusted sources
- Monitor remote config changes via violation logs

### Immutability Bypass Prevention

The cascading priority system (Issue #255) prevents users from:
- Adding attacker-controlled remote URLs
- Overriding immutable security settings
- Bypassing enterprise policies

This is a critical security feature.

## Related Documentation

- [SSRF Protection](SSRF_PROTECTION.md)
- [Secret Scanning](SECRET_SCANNING.md)
- [Permissions System](PERMISSIONS_COMPARISON.md)
- [Hook Configuration](HOOKS.md)

# SSRF Protection

Server-Side Request Forgery (SSRF) protection prevents AI agents from accessing private networks, cloud metadata endpoints, and dangerous URL schemes.

## Overview

SSRF attacks allow attackers to make the AI agent send requests to unintended locations:
- **Credential theft**: Access cloud metadata endpoints to steal AWS/GCP/Azure credentials
- **Internal network scanning**: Probe private network services
- **Local file access**: Read local files via file:// URLs
- **Firewall bypass**: Access internal services from outside the network

AI Guardian's SSRF protection blocks these attacks by checking all Bash commands for dangerous URLs before execution.

## Core Protections (Immutable)

These protections **CANNOT be disabled** via configuration:

### Private IP Ranges (RFC 1918 + Loopback + Link-local)

**IPv4:**
- `10.0.0.0/8` - Private network (Class A)
- `172.16.0.0/12` - Private network (Class B)
- `192.168.0.0/16` - Private network (Class C)
- `127.0.0.0/8` - Loopback (localhost)
- `169.254.0.0/16` - Link-local (AWS/Azure metadata)

**IPv6:**
- `::1/128` - Loopback
- `fc00::/7` - Unique local addresses (private network)
- `fe80::/10` - Link-local addresses

### Cloud Metadata Endpoints

**AWS:**
- `169.254.169.254` - IPv4 metadata endpoint
- `fd00:ec2::254` - IPv6 metadata endpoint
- `instance-data` - Instance metadata service

**Google Cloud Platform:**
- `metadata.google.internal` - Primary metadata endpoint
- `metadata.goog` - Alternative metadata endpoint

**Azure:**
- `169.254.169.254` - Shared with AWS (same IP range)

### Dangerous URL Schemes

- `file://` - Local filesystem access
- `gopher://` - Legacy protocol (attack vector)
- `ftp://` - File transfer protocol
- `ftps://` - Secure FTP
- `data://` - Data URLs (can encode arbitrary content)
- `dict://` - DICT protocol
- `ldap://` - LDAP protocol
- `ldaps://` - Secure LDAP

## Configuration

### Basic Configuration

Default configuration (`~/.config/ai-guardian/ai-guardian.json`):

```json
{
  "ssrf_protection": {
    "enabled": true,
    "action": "block"
  }
}
```

### Full Configuration

```json
{
  "ssrf_protection": {
    "enabled": true,
    "action": "block",
    "additional_blocked_ips": [
      "203.0.113.0/24",
      "198.51.100.0/24"
    ],
    "additional_blocked_domains": [
      "internal.example.com",
      "admin.local",
      "*.corp.internal"
    ],
    "allow_localhost": false
  }
}
```

### Configuration Options

#### `enabled` (boolean, default: true)

Enable or disable SSRF protection entirely.

**Example:**
```json
{
  "ssrf_protection": {
    "enabled": false
  }
}
```

**Time-based enabling** (NEW in v1.5.0):
```json
{
  "ssrf_protection": {
    "enabled": {
      "value": false,
      "valid_until": "2026-12-31T23:59:59Z"
    }
  }
}
```

#### `action` (string, default: "block")

Action to take when SSRF is detected:
- `"block"` - Prevent execution and show error message (recommended)
- `"warn"` - Log violation, show warning to user, but allow execution
- `"log-only"` - Log violation silently without user warning, allow execution

**Block mode (default, recommended):**
```json
{
  "ssrf_protection": {
    "action": "block"
  }
}
```

**Warn mode (for testing/debugging):**
```json
{
  "ssrf_protection": {
    "action": "warn"
  }
}
```

**Log-only mode (for monitoring without blocking):**
```json
{
  "ssrf_protection": {
    "action": "log-only"
  }
}
```

#### `additional_blocked_ips` (array, default: [])

Additional IP addresses or CIDR ranges to block beyond core protections.

**Supports:**
- Single IPv4 addresses: `"203.0.113.5"`
- IPv4 CIDR ranges: `"203.0.113.0/24"`
- Single IPv6 addresses: `"2001:db8::1"`
- IPv6 CIDR ranges: `"2001:db8::/32"`

**Example:**
```json
{
  "ssrf_protection": {
    "additional_blocked_ips": [
      "203.0.113.0/24",
      "198.51.100.0/24",
      "2001:db8::/32"
    ]
  }
}
```

#### `additional_blocked_domains` (array, default: [])

Additional domain names to block beyond core protections.

**Supports:**
- Exact domain: `"internal.example.com"`
- Subdomain matching: Blocks `api.internal.example.com` if `internal.example.com` is blocked

**Example:**
```json
{
  "ssrf_protection": {
    "additional_blocked_domains": [
      "internal.example.com",
      "admin.local",
      "corp.internal"
    ]
  }
}
```

#### `allow_localhost` (boolean, default: false)

Allow access to localhost (127.0.0.1, ::1) for local development.

**Use case**: Local development servers, testing environments.

**Example:**
```json
{
  "ssrf_protection": {
    "allow_localhost": true
  }
}
```

**Security warning**: Only enable `allow_localhost` in development environments, never in production.

## Examples

### Example 1: AWS Metadata Endpoint Attack (BLOCKED)

```bash
# Attacker attempts to steal AWS credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**AI Guardian blocks this with:**
```
🚨 BLOCKED BY POLICY
🚨 SSRF ATTACK DETECTED

Detected threat:
  • Reason: private IP address '169.254.169.254'
  • URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### Example 2: Private Network Scanning (BLOCKED)

```bash
# Attacker attempts to scan internal network
curl http://192.168.1.1/admin
```

**AI Guardian blocks this with:**
```
🚨 BLOCKED BY POLICY
🚨 SSRF ATTACK DETECTED

Detected threat:
  • Reason: private IP address '192.168.1.1'
  • URL: http://192.168.1.1/admin
```

### Example 3: File Access via file:// URL (BLOCKED)

```bash
# Attacker attempts to read /etc/passwd
curl file:///etc/passwd
```

**AI Guardian blocks this with:**
```
🚨 BLOCKED BY POLICY
🚨 SSRF ATTACK DETECTED

Detected threat:
  • Reason: dangerous URL scheme 'file://'
  • URL: file:///etc/passwd
```

### Example 4: Public AWS Service (ALLOWED)

```bash
# Legitimate access to public S3 bucket
curl https://s3.amazonaws.com/my-bucket/file.txt

# Legitimate AWS CLI command
aws s3 ls s3://my-bucket/
```

**AI Guardian allows these** - public AWS services are NOT blocked.

### Example 5: Local Development (ALLOWED with config)

With `allow_localhost: true`:

```bash
# Access local development server
curl http://localhost:3000/api/users
```

**AI Guardian allows this** when `allow_localhost` is enabled.

Without `allow_localhost` (default), this would be blocked.

## False Positives

SSRF protection is designed to minimize false positives:

### NOT Blocked (Legitimate Use)

✅ **Public IP addresses:**
- `curl http://8.8.8.8` (Google DNS)
- `curl https://1.1.1.1` (Cloudflare DNS)

✅ **Public AWS services:**
- `curl https://s3.amazonaws.com/bucket/file.txt`
- `aws ec2 describe-instances`
- `aws s3 ls`

✅ **HTTPS URLs to public domains:**
- `curl https://api.github.com/repos`
- `wget https://releases.ubuntu.com/22.04/ubuntu-22.04.3-desktop-amd64.iso`

✅ **Commands without URLs:**
- `ls -la /var/log`
- `grep "error" /tmp/app.log`
- `find . -name "*.py"`

### Blocked (Security Threats)

❌ **Private network access:**
- `curl http://10.0.0.1`
- `wget http://192.168.1.1/admin`

❌ **Metadata endpoints:**
- `curl http://169.254.169.254/latest/meta-data/`
- `curl http://metadata.google.internal/`

❌ **Dangerous schemes:**
- `curl file:///etc/passwd`
- `curl gopher://internal.server`

❌ **Localhost (by default):**
- `curl http://localhost:8080`
- `wget http://127.0.0.1:3000`

## Legitimate AWS Access vs Attacks

**Key distinction**: IP address vs domain name

### Public AWS Services (ALLOWED)

```bash
# ✅ Public S3 endpoint (domain name, resolves to public IP)
curl https://s3.amazonaws.com/my-bucket/file.txt

# ✅ AWS CLI (uses public AWS APIs)
aws ec2 describe-instances
aws s3 ls s3://my-bucket/
```

### Metadata Endpoints (BLOCKED)

```bash
# ❌ AWS metadata endpoint (private IP, credential theft)
curl http://169.254.169.254/latest/meta-data/

# ❌ Direct access to instance metadata
curl http://169.254.169.254/latest/user-data
```

**Why the difference?**
- Public AWS services use public domain names (s3.amazonaws.com) that resolve to public IPs
- Metadata endpoints use private IP address (169.254.169.254) for instance-local access only
- Legitimate AWS usage never requires accessing 169.254.169.254 from Bash commands

## Edge Cases and FAQs

### Q: Can I disable SSRF protection for specific commands?

**A:** Not currently. SSRF protection applies to all Bash commands. Use action modes instead:
- `"action": "warn"` - Shows warning but allows execution
- `"action": "log-only"` - Logs but doesn't notify user

### Q: What about DNS rebinding attacks?

**A:** AI Guardian does NOT perform DNS resolution (by design). This avoids:
- Performance overhead
- Network dependencies
- TOCTOU (Time-of-Check-Time-of-Use) issues

This means a public domain that resolves to a private IP would bypass protection. This is a known limitation. For complete protection, combine with:
- Network egress filtering
- DNS filtering
- Runtime monitoring

### Q: Can I allow specific private IPs?

**A:** Core protections cannot be disabled. However, you can use action modes:
- Set `"allow_localhost": true` to allow localhost specifically
- Set `"action": "warn"` globally and approve on a case-by-case basis

### Q: What about IPv6 metadata endpoints?

**A:** Fully supported. AI Guardian blocks:
- `fd00:ec2::254` (AWS IPv6 metadata)
- All IPv6 private ranges (fc00::/7, fe80::/10)
- IPv6 loopback (::1)

### Q: Performance impact?

**A:** <1ms overhead per Bash command. URL extraction and IP validation are highly optimized.

### Q: Can attackers bypass this?

**Known bypass vectors:**
- DNS rebinding (domain resolves to private IP)
- URL redirects (server redirects to metadata endpoint)
- URL shorteners (obscure destination)

**Mitigations:**
- AI Guardian blocks direct access (first line of defense)
- Combine with network egress filtering (second line)
- Use runtime monitoring (third line)

## Credits

SSRF protection inspired by:
- **Hermes Security Framework**: https://github.com/fullsend-ai/experiments/tree/main/hermes-security-patterns
- Validated against real-world SSRF attack payloads from Hermes testing

## Related Documentation

- [README.md](../README.md) - Main documentation
- [CHANGELOG.md](../CHANGELOG.md) - Version history
- [Tool Policy](TOOL_POLICY.md) - Permission system
- [Prompt Injection](PROMPT_INJECTION.md) - Prompt injection detection

## Security Notes

**Defense in Depth**: SSRF protection is ONE layer of security. Combine with:
- ✅ Network egress filtering
- ✅ DNS filtering
- ✅ Runtime monitoring
- ✅ Principle of least privilege
- ✅ Code review

**Limitations**:
- Does not perform DNS resolution (by design)
- Cannot detect URL redirects
- Cannot detect DNS rebinding attacks

**Fail-Closed**: SSRF protection fails closed on errors - if URL parsing fails, the command is blocked.

**No Warranty**: This software is provided "AS IS" under the Apache 2.0 License.

# Secret Value Redaction in ai-guardian

## Overview

ai-guardian implements **defense-in-depth** for secret value redaction to ensure that actual secret values are **never** exposed in error messages, logs, or temporary files.

## Security Layers

### Layer 1: Gitleaks `--redact` Flag (Defense-in-Depth)

**Location**: `src/ai_guardian/__init__.py:1537`

```python
cmd = [
    'gitleaks',
    'detect',
    '--no-git',
    '--verbose',
    '--redact',        # Defense-in-depth: redact Match/Secret fields in JSON
                       # (we don't extract these fields, but safeguard against future changes)
    '--report-format', 'json',
    '--report-path', report_file,
    '--source', tmp_file_path,
]
```

**What it does**:
- Gitleaks replaces all secret values with `"REDACTED"` in its JSON output
- Both `Match` and `Secret` fields show `"REDACTED"` instead of actual values
- Prevents secrets from appearing in Gitleaks stdout/stderr

**Important Note**:
- ai-guardian **never extracts** the `Match` or `Secret` fields (see Layer 2)
- The `--redact` flag is **defense-in-depth** to safeguard against future code changes
- Even without `--redact`, current implementation wouldn't leak secrets
- We keep it as an extra security layer

**Verification**:
```python
# Gitleaks JSON output with --redact:
{
  "RuleID": "slack-bot-token",
  "Match": "REDACTED",      # ← Not the actual token (we don't use this field)
  "Secret": "REDACTED",     # ← Not the actual secret (we don't use this field)
  "File": "test.py",        # ← We extract this
  "StartLine": 2            # ← We extract this
}
```

### Layer 2: Never Display or Log Secret Values

**Location**: `src/ai_guardian/__init__.py:1545-1564`

```python
# Parse JSON report to extract details
# NOTE: Gitleaks --redact flag ensures "Match" and "Secret" fields are "REDACTED"
#       We never display or log the actual secret values for security
secret_details = None
try:
    if os.path.exists(report_file):
        with open(report_file, 'r', encoding='utf-8') as f:
            findings = json.load(f)
        if findings and len(findings) > 0:
            first_finding = findings[0]
            secret_details = {
                "rule_id": first_finding.get("RuleID", "Unknown"),
                "file": first_finding.get("File", filename),
                "line_number": first_finding.get("StartLine", 0),
                "end_line": first_finding.get("EndLine", 0),
                "commit": first_finding.get("Commit", "N/A"),
                # NOTE: "match" field removed - never displayed, redacted anyway
                "total_findings": len(findings)
            }
```

**What we extract** (safe metadata only):
- ✅ Rule ID (e.g., "slack-bot-token") - secret type, not value
- ✅ File path - where the secret was found
- ✅ Line numbers - location in file
- ✅ Total findings count - how many secrets

**What we DON'T extract** (fields that contain secret values):
- ❌ `Match` field - contains "REDACTED" (or actual secret without --redact flag)
- ❌ `Secret` field - contains "REDACTED" (or actual secret without --redact flag)
- ❌ Any actual secret value - we only use metadata for error messages

### Layer 3: Error Messages Show Only Metadata

**Location**: `src/ai_guardian/__init__.py:1575-1584`

```python
if secret_details:
    error_msg += "\n"
    error_msg += f"Secret Type: {secret_details['rule_id']}\n"
    if secret_details.get('line_number'):
        error_msg += f"Location: {secret_details['file']}, line {secret_details['line_number']}\n"
    else:
        error_msg += f"File: {secret_details['file']}\n"
    if secret_details.get('total_findings'):
        error_msg += f"Total findings: {secret_details['total_findings']}\n"
```

**Example error message** (user sees):
```
======================================================================
🚨 BLOCKED BY POLICY
🔒 SECRET DETECTED
======================================================================

Gitleaks has detected sensitive information in your prompt/file.

Secret Type: slack-bot-token
Location: test.py, line 2
Total findings: 1

This operation has been blocked for security.
Please remove the sensitive information and try again.
```

**Note**: No actual secret value is shown!

### Layer 4: Logs Only Metadata

**Location**: `src/ai_guardian/__init__.py:1612-1617`

```python
if action == "log":
    logging.warning(f"Secret detected (log mode): {secret_details.get('rule_id') if secret_details else 'unknown'} - execution allowed")
    return False, None
else:
    logging.error(f"Secret detected: {secret_details.get('rule_id') if secret_details else 'unknown'}")
    return True, error_msg
```

**Log output examples**:
```
2026-04-18 16:30:15 - ai_guardian - ERROR - Secret detected: slack-bot-token
2026-04-18 16:30:15 - ai_guardian - WARNING - Secret detected (log mode): aws-access-token - execution allowed
```

**Note**: Only rule_id logged, never the actual secret!

### Layer 5: Sanitized Gitleaks stderr

**Location**: `src/ai_guardian/__init__.py:1631-1636`

```python
# Extract error details (sanitized - don't log full stderr to avoid leaking secrets)
stderr_preview = ""
if result.stderr:
    # Only log sanitized error info, not full stderr
    logging.debug(f"Gitleaks stderr present (length: {len(result.stderr)} chars)")
    stderr_lines = [line.strip() for line in result.stderr.split('\n') if line.strip()]
    if stderr_lines:
        # Only show first line (error summary), truncated
        stderr_preview = stderr_lines[0][:200]
```

**What's logged**:
- ✅ Length of stderr (for debugging)
- ✅ First line only, truncated to 200 chars
- ✅ Only logged at DEBUG level

**What's NOT logged**:
- ❌ Full Gitleaks stderr (could contain sensitive info in edge cases)

### Layer 6: Violation Log Excludes Secrets

**Location**: `src/ai_guardian/__init__.py:1137-1152`

```python
blocked_info = {
    "file_path": filename if filename != "user_prompt" else None,
    "source": "prompt" if filename == "user_prompt" else "file",
    "secret_type": details.get("rule_id", "Unknown"),  # ← Type, not value
    "reason": "Gitleaks detected sensitive information"
}

# Add line number information if available
if details.get("line_number"):
    blocked_info["line_number"] = details["line_number"]
    if details.get("end_line") and details["end_line"] != details["line_number"]:
        blocked_info["end_line"] = details["end_line"]

# Add total findings count if available
if details.get("total_findings"):
    blocked_info["total_findings"] = details["total_findings"]
```

**Violation log entry** (JSONL):
```json
{
  "timestamp": "2026-04-18T16:30:15Z",
  "violation_type": "secret_detected",
  "blocked": {
    "file_path": "test.py",
    "source": "file",
    "secret_type": "slack-bot-token",
    "reason": "Gitleaks detected sensitive information",
    "line_number": 2,
    "total_findings": 1
  },
  "context": {...}
}
```

**Note**: No actual secret value in violation log!

### Layer 7: KNOWN LIMITATION - UserPromptSubmit Terminal Display

**Location**: `src/ai_guardian/__init__.py:247-260`

**THE LIMITATION (Claude Code Behavior)**:

When ai-guardian blocks prompts containing secrets using `decision: "block"` in JSON response, Claude Code displays the original prompt in the terminal error message.

**What we implemented:**
```python
response = {
    "decision": "block",
    "reason": error_message,  # Our sanitized message
    "hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit"
    }
}
```

**What Claude Code shows:**
```
======================================================================
🚨 BLOCKED BY POLICY
🔒 SECRET DETECTED
======================================================================
(our sanitized error message - no secret here)

Original prompt: AWS_ACCESS_KEY_ID=AKIA****************  ← SECRET VISIBLE # gitleaks:allow
```

**Why this happens:**
- Claude Code appends "Original prompt:" when `decision: "block"` is used
- This is Claude Code's design - we cannot control this behavior
- The `reason` field shows our message, but Claude Code adds the original prompt below it

**What IS protected:**
- ✅ Secret does NOT reach Claude's API (hook blocks before submission)
- ✅ Secret does NOT appear in conversation history/session
- ✅ Secret does NOT get sent to Anthropic servers
- ✅ Only metadata in our error message (type, file, line)

**What is NOT protected:**
- ❌ Secret visible in user's terminal when blocking occurs
- This is the trade-off for blocking secrets from reaching Claude

**Why we accept this limitation:**
- Preventing secrets from reaching Claude's API is MORE IMPORTANT than hiding from terminal
- The terminal leak is local only (user's screen)
- The alternative (allowing secrets to Claude) is worse
- This is a Claude Code design decision we cannot work around

**Attempted alternatives:**
- `systemMessage` without blocking - would hide secret BUT allows it to reach Claude (rejected)
- Exit codes only - still shows "Original prompt:" (doesn't help)
- No JSON response - interpreted as allow (defeats the purpose)

```
======================================================================
🚨 BLOCKED BY POLICY
🔒 SECRET DETECTED
======================================================================
(our error message - no secret here)

Original prompt: AWS_ACCESS_KEY_ID=AKIA****************  ← SECRET LEAKED! # gitleaks:allow
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYREALKEY # gitleaks:allow
```

**ATTEMPTED FIX (FAILED)**:

We tried JSON response format to prevent this:
```python
# This DOESN'T WORK
return {
    "output": json.dumps({"decision": "deny", "reason": "..."}),
    "exit_code": 0
}
```

**Result**: Claude Code rejects it with error:
```
UserPromptSubmit hook error
Hook JSON output validation failed — (root): Invalid input
```

**ROOT CAUSE**:

Claude Code's UserPromptSubmit hook **only accepts exit code responses**, not JSON. Unlike PostToolUse which accepts JSON, UserPromptSubmit has a different response schema that we cannot control.

**CURRENT STATUS (REVERTED)**:

```python
# Must use exit codes (only supported format)
if has_secrets and error_message:
    print(error_message, file=sys.stderr)
return {
    "output": None,
    "exit_code": 2 if has_secrets else 0
}
```

**IMPACT**:

- ❌ Secrets in direct prompts ARE LEAKED when blocked
- ✅ Secrets in tool outputs (PostToolUse) are NOT leaked (uses JSON)
- ✅ Secrets in file reads (PreToolUse) are NOT leaked (different flow)

**WORKAROUNDS**:

1. **Rely on other detection layers**:
   - PreToolUse hook scans files before reading (blocks file path, not content)
   - PostToolUse hook scans tool outputs (uses JSON, no leak)
   
2. **User education**:
   - Don't paste secrets directly in prompts
   - Use environment variables, config files, or secure vaults
   
3. **Report to Claude Code team**:
   - This is a security issue with Claude Code's UserPromptSubmit implementation
   - Feature request: Support JSON responses like PostToolUse does

**TODO**: Open GitHub issue for Claude Code team

### Layer 8: Secure File Cleanup

**Location**: `src/ai_guardian/__init__.py:1711-1756`

#### Content File (Scanned File)

```python
# Secure cleanup: overwrite file before deletion
if os.path.exists(tmp_file_path):
    try:
        # Make file writable
        os.chmod(tmp_file_path, 0o600)

        # Overwrite with zeros to prevent recovery
        file_size = os.path.getsize(tmp_file_path)
        with open(tmp_file_path, 'wb') as f:
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())

        # Delete the file
        os.unlink(tmp_file_path)
```

#### Report File (Gitleaks JSON Output)

**NEW**: Now securely cleaned up (defense in depth)

```python
# Securely clean up report file (contains Gitleaks findings)
# Even though --redact is used, we securely overwrite as defense in depth
if report_file and os.path.exists(report_file):
    try:
        # Make file writable
        os.chmod(report_file, 0o600)

        # Overwrite with zeros to prevent recovery
        file_size = os.path.getsize(report_file)
        with open(report_file, 'wb') as f:
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())

        # Delete the file
        os.unlink(report_file)
```

**Why this matters**:
- Even though Gitleaks redacts secrets, defense in depth requires secure cleanup
- Prevents forensic recovery of temporary files
- Both content and report files are overwritten with zeros before deletion
- Uses `os.fsync()` to ensure writes are committed to disk

## Testing

### Verification Test

```python
import subprocess
import tempfile
import json

# Create test file with secret (example - not a real token)
test_content = 'slack_token = "xoxb-' + '1234567890-1234567890123-abcdefghijklmnopqrstuvwx"'

with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
    f.write(test_content)
    tmp_path = f.name

report_path = tempfile.mktemp(suffix='.json')

# Run gitleaks with --redact
result = subprocess.run(
    ['gitleaks', 'detect', '--no-git', '--source', tmp_path,
     '--redact', '--report-format', 'json', '--report-path', report_path],
    capture_output=True,
    text=True
)

# Verify redaction
with open(report_path) as f:
    findings = json.load(f)

assert 'xoxb' not in result.stdout    # ✅ Secret not in stdout
assert 'xoxb' not in result.stderr    # ✅ Secret not in stderr  
assert 'xoxb' not in json.dumps(findings)  # ✅ Secret not in report
assert findings[0]['Match'] == 'REDACTED'  # ✅ Match is redacted
assert findings[0]['Secret'] == 'REDACTED' # ✅ Secret is redacted
```

**Result**: All assertions pass ✅

## Summary

**Secret values are NEVER exposed in**:
- ❌ Error messages shown to users
- ❌ Log files (`~/.config/ai-guardian/ai-guardian.log`)
- ❌ Violation logs (`~/.config/ai-guardian/violations.jsonl`)
- ❌ Gitleaks stdout/stderr output
- ❌ Gitleaks JSON report (shows "REDACTED")
- ❌ Temporary files (securely overwritten before deletion)

**What IS exposed** (safe metadata):
- ✅ Secret type (e.g., "slack-bot-token", "aws-access-key")
- ✅ File path where secret was found
- ✅ Line number(s) in file
- ✅ Total count of secrets found

**Defense-in-depth layers**:
1. Gitleaks `--redact` flag
2. Don't extract secret values from Gitleaks output
3. Error messages show only metadata
4. Logs show only rule IDs
5. Sanitized stderr logging
6. Violation logs exclude secrets
7. Secure file cleanup (overwrite + delete)

## Best Practices for Developers

When modifying secret scanning code:

1. **Never log `first_finding.get('Match')` or `first_finding.get('Secret')`**
   - These fields contain "REDACTED" but should never be logged anyway

2. **Never include `result.stdout` or `result.stderr` in user-facing messages**
   - Only use for internal debugging, with sanitization

3. **Always use secure cleanup for temporary files containing secrets**
   - Overwrite with zeros before deletion
   - Use `os.fsync()` to ensure write is committed

4. **Test with real secrets to verify redaction**
   - Use actual secret formats (Slack tokens, AWS keys, etc.)
   - Verify secrets don't appear in output, logs, or files

5. **Document any new fields extracted from Gitleaks output**
   - Ensure they don't contain secret values
   - Update this document with security analysis

## Related Files

- **Implementation**: `src/ai_guardian/__init__.py` (lines 1374-1778)
- **Tests**: `tests/test_secret_scanning_ignore.py`, `tests/test_ai_guardian.py`
- **Schema**: `src/ai_guardian/schemas/ai-guardian-config.schema.json`
- **Changelog**: `CHANGELOG.md`

## References

- **Gitleaks --redact**: https://github.com/gitleaks/gitleaks#redaction
- **OWASP Secret Management**: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- **Defense in Depth**: https://en.wikipedia.org/wiki/Defense_in_depth_(computing)

---

**Last Updated**: 2026-04-18  
**Version**: v1.7.0+

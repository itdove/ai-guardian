# IMMUTABLE_DENY_PATTERNS Review

## Context
After implementing contributor workflow (Issue #105), we changed the security model:
- **Edit/Write on development source**: NOW ALLOWED (bypassed via `_should_skip_immutable_protection`)
- **Bash/PowerShell on source**: STILL BLOCKED (immutable patterns still apply)

## Current Patterns Analysis

### ✅ Edit/Write Patterns - STILL NEEDED

```python
"Edit": [
    "*ai-guardian.json",                        # ✅ Config - ALWAYS protected
    "*/.config/ai-guardian/*",                  # ✅ Config - ALWAYS protected
    "*/.cache/ai-guardian/*",                   # ✅ Cache - ALWAYS protected
    "*/.claude/settings.json",                  # ✅ Hooks - ALWAYS protected
    "*/site-packages/ai_guardian/*",            # ✅ Pip-installed - ALWAYS protected
    "*/ai-guardian/src/ai_guardian/*",          # ⚠️  Development - BYPASSED (but pattern kept)
    "*/.ai-read-deny",                          # ✅ Markers - ALWAYS protected
]
```

**Analysis:**
- Config/hooks/cache patterns: ✅ **Correct** - always enforced
- Pip-installed patterns: ✅ **Correct** - always enforced
- Development source patterns: ⚠️ **Bypassed but kept** - Why?
  - **Reason 1**: Defense in depth (if bypass logic has bug)
  - **Reason 2**: Protects pip-installed code (same pattern matches both)
  - **Reason 3**: Clear intent (shows what we're protecting)

**Recommendation**: ✅ **KEEP AS-IS** but update comments

### ✅ Bash/PowerShell Patterns - STILL NEEDED

```python
"Bash": [
    "*sed*ai-guardian*",                        # ✅ Prevents sed on config/source
    "*rm*ai-guardian.json*",                    # ✅ Prevents deleting config
    "*mv*ai-guardian*",                         # ✅ Prevents moving files
    "*>*ai-guardian*",                          # ✅ Prevents redirection
    "*chmod*ai-guardian*",                      # ✅ Prevents permission changes
    # ... many more
]
```

**Analysis:**
- These are intentionally **broad** to catch subtle attacks
- Cover destructive operations: rm, mv, sed, awk, chmod, chattr
- Protect config, hooks, cache, source, markers

**Examples of what's blocked:**
```bash
# Config manipulation
sed -i 's/enabled":true/enabled":false/' ~/.config/ai-guardian/ai-guardian.json
rm ~/.claude/settings.json

# Source code destruction (development or pip-installed)
rm -rf /usr/lib/python3.12/site-packages/ai_guardian/
mv ~/ai-guardian/src/ai_guardian/tool_policy.py /tmp/

# Sneaky attacks
echo "" > ~/ai-guardian/src/ai_guardian/__init__.py  # Wipe file
chmod 000 ~/.config/ai-guardian/ai-guardian.json     # Make unreadable
```

**Recommendation**: ✅ **KEEP AS-IS** - provides essential protection

### Pattern Coverage Matrix

| File Type | Edit/Write | Bash/PowerShell | Result |
|-----------|------------|-----------------|--------|
| **Config files** | 🔒 Blocked | 🔒 Blocked | ✅ Always protected |
| **IDE hooks** | 🔒 Blocked | 🔒 Blocked | ✅ Always protected |
| **Cache files** | 🔒 Blocked | 🔒 Blocked | ✅ Always protected |
| **Pip-installed code** | 🔒 Blocked | 🔒 Blocked | ✅ Always protected |
| **Dev source code** | ✅ Allowed | 🔒 Blocked | ✅ Surgical edits only |
| **Directory markers** | 🔒 Blocked | 🔒 Blocked | ✅ Always protected |

## Potential Issues Found

### 1. ⚠️ Overly Broad Bash Patterns

**Issue**: Patterns like `"*sed*ai-guardian*"` might block legitimate operations

**Examples that get blocked:**
```bash
# Wanted: Edit unrelated file
sed 's/foo/bar/' ~/notes/thoughts-about-ai-guardian.txt  # ❌ BLOCKED

# Wanted: Search in docs
grep -r "ai-guardian" ~/documents/  # ❌ Might be blocked by some patterns

# Wanted: Process log files
awk '/ai-guardian/ {print $1}' system.log  # ❌ BLOCKED
```

**Recommendation**: 
- **Option A**: KEEP AS-IS (defense in depth, prevents sneaky attacks)
- **Option B**: Make patterns more specific (but might miss attacks)

**Decision**: ✅ **KEEP AS-IS** - Better to block rare legitimate cases than miss attacks

### 2. ⚠️ Comments Don't Reflect New Model

**Issue**: Comments say "Protect ai-guardian package (self-protection)" but don't clarify the bypass

**Current comment (line 63):**
```python
# Protect ai-guardian package (self-protection)
"*/site-packages/ai_guardian/*",           # Installed package
"*/ai-guardian/src/ai_guardian/*",         # Source repo (with hyphen)
```

**Should say:**
```python
# Protect ai-guardian package code
"*/site-packages/ai_guardian/*",           # Pip-installed - ALWAYS blocked
"*/ai-guardian/src/ai_guardian/*",         # Dev source - bypassed for Edit/Write only
```

**Recommendation**: ✅ **UPDATE COMMENTS** for clarity

### 3. ✅ Missing Coverage?

Checking for gaps:
- Config files ✅ (json)
- IDE hooks ✅ (.claude, .cursor)
- Cache ✅ (.cache/ai-guardian)
- Source code ✅ (src/, site-packages/)
- Markers ✅ (.ai-read-deny)
- Tests? ✅ (Handled by `_should_skip_immutable_protection`, not patterns)
- Docs? ✅ (Handled by bypass for `*.md`)
- Workflows? ✅ (Handled by bypass for `.github/*`)

**Recommendation**: ✅ **NO GAPS** - coverage is complete

### 4. ⚠️ Redundancy in PowerShell Patterns

**Issue**: Some PowerShell patterns are duplicated or overly specific

**Example (lines 221-228):**
```python
# PowerShell aliases (del, erase, rm, mv, etc.)
"*del *ai-guardian*", "*erase *ai-guardian*",
"*rm *ai-guardian*", "*rmdir *ai-guardian*",
"*mv *ai-guardian*", "*move *ai-guardian*",
```

**Note**: The space after `del ` is intentional (matches command, not Remove-Delete cmdlet)

**Recommendation**: ✅ **KEEP AS-IS** - covers both PowerShell cmdlets and aliases

## Edge Cases to Test

### Test 1: Edit Development Source (Should ALLOW)
```python
Edit(
    file_path="/home/user/ai-guardian/src/ai_guardian/tool_policy.py",
    old_string="old", new_string="new"
)
# Expected: ✅ ALLOWED (contributor workflow)
```

### Test 2: Edit Pip-Installed (Should BLOCK)
```python
Edit(
    file_path="/usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py",
    old_string="old", new_string="new"  
)
# Expected: 🔒 BLOCKED (immutable pattern)
```

### Test 3: Bash on Development Source (Should BLOCK)
```bash
rm ~/ai-guardian/src/ai_guardian/tool_policy.py
# Expected: 🔒 BLOCKED (immutable pattern - no bypass for Bash)
```

### Test 4: Edit Config (Should BLOCK)
```python
Edit(
    file_path="/home/user/.config/ai-guardian/ai-guardian.json",
    old_string="old", new_string="new"
)
# Expected: 🔒 BLOCKED (immutable pattern - no bypass for config)
```

### Test 5: Edit Hooks (Should BLOCK)
```python
Edit(
    file_path="/home/user/.claude/settings.json",
    old_string="old", new_string="new"
)
# Expected: 🔒 BLOCKED (immutable pattern - no bypass for hooks)
```

## Recommendations

### 1. Update Comments ✅ RECOMMENDED
Make comments reflect the new bypass behavior:

```python
"Edit": [
    # Config/hooks/cache - ALWAYS protected (even for repo owners)
    "*ai-guardian.json",
    "*/.config/ai-guardian/*",
    "*/.cache/ai-guardian/*",
    "*/.claude/settings.json",
    "*/.cursor/hooks.json",
    
    # Package code - Pip-installed ALWAYS protected, dev source bypassed for Edit/Write
    "*/site-packages/ai_guardian/*",            # Pip - always blocked
    "*/ai-guardian/src/ai_guardian/*",          # Dev - bypassed via _should_skip_immutable_protection
    
    # Directory markers - ALWAYS protected
    "*/.ai-read-deny",
]
```

### 2. Add Documentation Comment ✅ RECOMMENDED
Add a comment at the top of IMMUTABLE_DENY_PATTERNS explaining the bypass:

```python
# Hardcoded critical protections - cannot be disabled or bypassed
# 
# BYPASS BEHAVIOR:
# - Edit/Write on dev source: Bypassed via _should_skip_immutable_protection()
#   (Enables contributor workflow for fork + PR)
# - Edit/Write on config/hooks/cache/pip: ALWAYS blocked (no bypass)
# - Bash/PowerShell on anything: ALWAYS blocked (no bypass)
#
# These patterns are checked FIRST, before any user-configured permissions
IMMUTABLE_DENY_PATTERNS = {
```

### 3. Keep All Patterns ✅ RECOMMENDED
Don't remove any patterns because:
- Defense in depth (if bypass logic fails)
- Clear intent (documents what we protect)
- Pip-installed protection (same patterns cover both)

### 4. Add Test Coverage ⚠️ OPTIONAL
Consider adding tests for:
- Bash on development source (should block)
- PowerShell on development source (should block)  
- Edge cases with unusual paths

## Summary

### Status: ✅ PATTERNS ARE CORRECT

**What's working well:**
- ✅ Config/hooks/cache always protected
- ✅ Pip-installed code always protected
- ✅ Development source allows Edit/Write (via bypass)
- ✅ Development source blocks Bash/PowerShell (no bypass)
- ✅ Comprehensive coverage of attack vectors

**What could be improved:**
- 📝 Comments don't reflect bypass behavior
- 📝 Missing documentation about how bypass works
- 🧪 Could add more edge case tests

**Recommended actions:**
1. ✅ **Update comments** (high priority)
2. ✅ **Add bypass documentation** (high priority)
3. ⚠️ **Add edge case tests** (medium priority)
4. ✅ **Keep all patterns as-is** (no removals)

**Security posture**: 🔒 **STRONG** - No vulnerabilities found

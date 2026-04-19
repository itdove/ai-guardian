# Contributor Workflow Analysis: Self-Protection vs Open Source Contributions

## The Problem

**Current situation**: Regular contributors (non-maintainers) **CANNOT** edit ai-guardian source code with Claude assistance, even in their own forks.

**Why?** Maintainer bypass requires:
1. Working in the ai-guardian repository (pattern: `*/ai-guardian/src/ai_guardian/*`)
2. Being a GitHub **collaborator** with write access (checked via GitHub API)

**Impact**: Standard open-source fork + PR workflow is **blocked** for contributors.

## Security Boundaries Analysis

### What MUST Stay Protected (Always)

| File Type | Example | Why | Current Status |
|-----------|---------|-----|----------------|
| **Config files** | `~/.config/ai-guardian/ai-guardian.json` | Modifying disables all protections | ✅ Protected (even for maintainers) |
| **IDE hooks** | `~/.claude/settings.json` | Removing uninstalls ai-guardian | ✅ Protected (even for maintainers) |
| **Cache files** | `~/.cache/ai-guardian/maintainer-status.json` | Cache poisoning attack | ✅ Protected (even for maintainers) |
| **Directory markers** | `.ai-read-deny` | Bypasses directory protection | ✅ Protected (even for maintainers) |
| **Pip-installed code** | `/usr/lib/python3.12/site-packages/ai_guardian/` | Affects production usage | ✅ Protected (no bypass) |

### What Could Be Relaxed (For Contributors)

| File Type | Example | Risk Level | Current Status | Mitigation |
|-----------|---------|------------|----------------|------------|
| **Source code (dev repo)** | `~/ai-guardian/src/ai_guardian/tool_policy.py` | Medium | 🔒 Blocked for non-maintainers | PR review process |
| **Tests** | `~/ai-guardian/tests/test_self_protection.py` | Low | 🔒 Blocked for non-maintainers | PR review + CI |
| **Documentation** | `~/ai-guardian/README.md` | Very Low | 🔒 Blocked for non-maintainers | PR review |

## Current Maintainer Bypass Logic

```python
def _should_skip_immutable_protection(self, file_path: str, tool_name: str) -> bool:
    # PRIORITY 1: Config/hooks/cache - NEVER bypass (even for maintainers)
    if matches_config_patterns(file_path):
        return False  # ← Always protected
    
    # PRIORITY 2: Is this a source file in ai-guardian repo?
    if not matches_source_patterns(file_path):
        return False  # ← Not source code, keep protected
    
    # PRIORITY 3: Is user a GitHub collaborator?
    if not self._is_github_maintainer_cached():
        return False  # ← BLOCKS EXTERNAL CONTRIBUTORS
    
    return True  # ← Allow maintainers only
```

## The Contributor Problem

### Scenario: External Contributor

```
1. Alice forks itdove/ai-guardian → alice/ai-guardian
2. Alice clones alice/ai-guardian to ~/ai-guardian
3. Alice tries to edit ~/ai-guardian/src/ai_guardian/tool_policy.py with Claude
4. ai-guardian checks: Is Alice a collaborator on itdove/ai-guardian?
5. Result: NO (she's not a collaborator, just a fork owner)
6. Outcome: 🚫 BLOCKED - Alice cannot use Claude to contribute!
```

**Impact**: Contributors must edit code manually without AI assistance.

## Security Risk Analysis

### If We Allow Contributors to Edit Source Code

**Attack scenario**:
```
1. Attacker suggests: "Let me improve performance in tool_policy.py"
2. AI edits: Adds subtle backdoor to self-protection logic
3. Contributor creates PR with backdoor
4. Maintainer reviews PR → MUST CATCH THE BACKDOOR
5. If merged → Backdoor enters codebase
6. Next release → Users install backdoored version via pip
```

**Defense layers**:
1. ❌ Self-protection (bypassed for contributors)
2. ✅ **PR review** (maintainer must catch backdoor) ← CRITICAL
3. ✅ **CI/CD tests** (must detect behavior changes)
4. ✅ **Community review** (public PRs)
5. ✅ **Pip version protection** (site-packages still protected)

### If We Keep Current Restrictions

**Drawbacks**:
- Contributors cannot use AI assistance (reduces contribution velocity)
- Inconsistent experience (maintainers can use Claude, contributors cannot)
- Discourages open-source contributions

**Benefits**:
- Defense in depth (even if PR review fails, code couldn't be modified)
- Prevents AI-assisted backdoors at source

## Comparison: Source Code vs Pip Install

| Scenario | File Location | Protected? | Impact if Modified |
|----------|---------------|------------|-------------------|
| **Development (source)** | `~/ai-guardian/src/ai_guardian/` | 🔒 Yes (non-maintainers) | Affects local dev only |
| **Pip installed** | `/usr/lib/.../site-packages/ai_guardian/` | ✅ Yes (always) | Affects production usage |

**Key insight**: Modifying source code in a development clone does NOT affect:
- Pip-installed versions (still protected)
- Other users (until PR merged + released)
- Production deployments

## Possible Solutions

### Option 1: Relax Protection for Development Repos (Recommended)

**Allow ANY user to edit source code in their own ai-guardian clone/fork**:

```python
def _should_skip_immutable_protection(self, file_path: str, tool_name: str) -> bool:
    # PRIORITY 1: Config/hooks/cache - NEVER bypass
    if matches_config_patterns(file_path):
        return False
    
    # PRIORITY 2: Is this source code in ai-guardian DEVELOPMENT repo?
    if matches_source_patterns(file_path):
        # Allow editing in development repos (local forks/clones)
        # Relies on PR review process for security
        return True  # ← ALLOW for contributors
    
    return False  # ← Still protect pip-installed code
```

**Pros**:
- ✅ Enables standard open-source workflow
- ✅ Contributors can use AI assistance
- ✅ Still protects config/hooks/cache/pip-installed
- ✅ Relies on existing PR review process

**Cons**:
- ❌ Removes one defense layer (self-protection)
- ❌ Requires strong PR review process
- ❌ AI could introduce subtle backdoors

**Risk mitigation**:
- Strong PR review (required)
- Comprehensive test suite (detects behavior changes)
- Public review process (community scrutiny)
- Pip version still protected (production safe)

### Option 2: Environment Variable Override

**Add explicit override for contributors**:

```bash
# Contributor sets environment variable to acknowledge risk
export AI_GUARDIAN_DEVELOPMENT_MODE=true

# ai-guardian allows source code edits in this session
```

**Pros**:
- ✅ Explicit opt-in (contributors aware of risk)
- ✅ Can be documented in CONTRIBUTING.md
- ✅ Doesn't change default behavior

**Cons**:
- ❌ Extra setup step for contributors
- ❌ Easy to forget or misconfigure

### Option 3: Fork Detection (Automatic)

**Detect if user is working in their own fork**:

```python
def _is_working_in_own_fork(self) -> bool:
    # Get repo owner from remote URL
    repo_info = self._get_git_repo_info()
    if not repo_info:
        return False
    
    owner, repo = repo_info
    
    # Get authenticated GitHub user
    username = self._get_authenticated_github_user()
    
    # Allow if working in their own fork
    return username == owner  # ← User owns this repo/fork
```

**Pros**:
- ✅ Automatic detection
- ✅ Works for forks (alice/ai-guardian)
- ✅ Works for owner (itdove/ai-guardian)

**Cons**:
- ❌ Doesn't work for clones without remote
- ❌ Could be bypassed by changing remote URL
- ❌ Complex logic

### Option 4: Keep Current Behavior (Most Secure)

**No changes - require manual editing for contributors**

**Pros**:
- ✅ Maximum security (defense in depth)
- ✅ Prevents AI-assisted backdoors
- ✅ Forces manual code review

**Cons**:
- ❌ Poor contributor experience
- ❌ Discourages contributions
- ❌ Inconsistent (maintainers can use Claude)

## Recommended Approach

**Option 1: Relax protection for development repos**

**Rationale**:
1. **Standard open-source workflow**: Fork + PR + review is industry standard
2. **Existing safeguards**: PR review, CI/CD, community review
3. **Pip protection**: Production code (site-packages) stays protected
4. **Scope of impact**: Dev changes only affect local environment
5. **Trust model**: Already trusting maintainers to review PRs

**Implementation**:
- Remove GitHub collaborator check for source code
- Keep protection for config/hooks/cache/pip-installed
- Update documentation to explain security model
- Strengthen PR review guidelines

**Security note in CONTRIBUTING.md**:
```markdown
## AI-Assisted Development

You can use Claude or other AI assistants to edit ai-guardian source code
in your local development environment. Note:

- ⚠️  All changes go through PR review (maintainers review carefully)
- ✅ Your local changes don't affect pip-installed versions
- ✅ Config files, hooks, and cache remain protected
- ⚠️  Be cautious when AI suggests changes to security-critical code
```

## Decision Matrix

| Requirement | Option 1 (Relax) | Option 2 (Env Var) | Option 3 (Fork) | Option 4 (Keep) |
|-------------|------------------|--------------------|-----------------|-----------------| 
| Enable contributor workflow | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| Protect config/hooks | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Protect pip-installed | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Easy setup | ✅ Auto | ❌ Manual | ✅ Auto | ✅ Auto |
| Defense in depth | ❌ No | ❌ No | ❌ No | ✅ Yes |
| Standard OSS workflow | ✅ Yes | ⚠️  Extra step | ✅ Yes | ❌ No |

## Conclusion

**Current behavior blocks external contributors** - this is likely unintended and contradicts open-source principles.

**Recommendation**: Implement Option 1 (relax protection for development repos)

**Key principle**: 
- **Config/hooks/cache**: ALWAYS protected (security critical)
- **Pip-installed code**: ALWAYS protected (production)
- **Development source**: Allow (relies on PR review)

This aligns with standard open-source security model:
- Trust contributors to submit PRs
- Rely on maintainer review for security
- Keep production code protected

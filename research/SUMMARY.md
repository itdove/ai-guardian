# Phase 0 Research Summary: Multi-IDE Support

**Research Date:** 2026-03-27
**Status:** ✅ Complete
**Overall Finding:** Mixed approach needed - some config-only, some code changes

---

## Executive Summary

Research into extending ai-guardian support for GitHub Copilot, Aider, and additional VS Code AI assistants reveals a **mixed implementation approach**:

| IDE/Tool | Approach | Effort | Code Changes? |
|----------|----------|--------|---------------|
| **GitHub Copilot** | Format adapter | 1-2 weeks | ✅ Yes |
| **Aider** | Git hook wrapper | 1-3 days | ❌ No (docs only) |
| **VS Code (Copilot, Continue, Cline)** | Extension + MCP | 3-4 weeks | ✅ Yes (extension) |

**Key Insight:** The original hypothesis that GitHub Copilot might work with "configuration only" was **incorrect**. Code changes are required due to incompatible JSON formats.

---

## Current Support Status

### ✅ Already Supported (v1.1.0)

| IDE | Hook Type | Configuration Location | Status |
|-----|-----------|----------------------|--------|
| **Claude Code CLI** | Native hooks | `~/.claude/settings.json` | Full support |
| **VS Code Claude** | Claude Code hooks | `~/.claude/settings.json` | Full support |
| **Cursor** | Native hooks | `~/.cursor/hooks.json` | Full support |

**Coverage:** 3 IDEs fully supported

---

## Research Findings by IDE

### 1. GitHub Copilot

**Finding:** **CODE CHANGES REQUIRED**

**Why:**
- Incompatible JSON input format
- Different response format requirements
- Tool arguments as JSON string vs object
- Three-level permission system vs binary

**Input Format Differences:**
```json
// GitHub Copilot
{
  "timestamp": 1704614400000,
  "cwd": "/path/to/project",
  "toolName": "bash",
  "toolArgs": "{\"command\":\"npm test\"}"  // JSON string!
}

// Claude Code (current)
{
  "hook_event_name": "PreToolUse",
  "tool_use": {
    "name": "Bash",
    "input": {"command": "npm test"}  // Object
  }
}
```

**Response Format Differences:**
```json
// GitHub Copilot expects (JSON on stdout)
{
  "permissionDecision": "allow|deny|ask",
  "permissionDecisionReason": "..."
}

// Claude Code uses (exit code only)
Exit code: 0 (allow) or 2 (block)
```

**Implementation Required:**
1. Add `GITHUB_COPILOT` to `IDEType` enum
2. Update `detect_ide_type()` to recognize Copilot format
3. Update `format_response()` to output Copilot JSON
4. Update `extract_file_content_from_tool()` to parse `toolArgs` string
5. Update tool policy checker for `toolName` format

**Effort:** 1-2 weeks (Phase 1B from issue)

**Detailed Analysis:** See `research/github-copilot-format.md`

---

### 2. Aider

**Finding:** **DOCUMENTATION ONLY** (no code changes)

**Why:**
- Uses standard git pre-commit hooks
- Wrapper script reads staged files via `git show :file`
- Calls ai-guardian subprocess or gitleaks directly
- Already works with existing ai-guardian CLI

**Integration Method:**
```bash
#!/bin/bash
# .git/hooks/pre-commit

STAGED_FILES=$(git diff --cached --name-only)

for file in $STAGED_FILES; do
  git show ":$file" | gitleaks detect --no-git --stdin --redact
  if [ $? -eq 42 ]; then
    echo "❌ Secrets detected in $file"
    exit 1
  fi
done

exit 0
```

**Configuration:**
```yaml
# .aider.conf.yml
git-commit-verify: true
```

**Limitation:**
- ⚠️ Only works at commit time, not during AI generation
- This is a **last line of defense**, not real-time protection

**Implementation Required:**
1. Create `docs/AIDER.md` with setup instructions
2. Create `examples/aider/pre-commit-hook.sh`
3. Create `examples/aider/.aider.conf.yml`
4. Update README.md

**Effort:** 1-3 days (documentation only)

**Detailed Analysis:** See `research/aider-format.md`

---

### 3. VS Code (Other AI Assistants)

**Finding:** **VS Code Claude ALREADY WORKS** - Extension needed for others

**Already Supported:**
- ✅ VS Code Claude extension (uses Claude Code hooks)

**Needs Extension Support:**
- ⏭️ GitHub Copilot (in VS Code)
- ⏭️ Continue.dev
- ⏭️ Cline

**Why Extension Required:**
- Different integration model (Language Model Tool API)
- MCP (Model Context Protocol) for cross-assistant support
- Cannot use simple hook configuration

**Recommended Architecture:**
```
VS Code Extension
  ├─→ Language Model Tool (for GitHub Copilot)
  ├─→ MCP Server (for Continue.dev, Cline)
  └─→ Calls ai-guardian subprocess
```

**Implementation Required:**
1. Create TypeScript VS Code extension
2. Register Language Model Tool for Copilot
3. Implement MCP server wrapper
4. Package and publish to VS Code Marketplace

**Effort:** 3-4 weeks (Phase 3 from issue)

**Detailed Analysis:** See `research/vscode-format.md`

---

## Decision Matrix: Configuration vs Code Changes

| IDE/Tool | Configuration Only? | Code Changes? | Reason |
|----------|---------------------|---------------|--------|
| **GitHub Copilot** | ❌ No | ✅ Yes | Incompatible JSON format |
| **Aider** | ✅ Yes (docs) | ❌ No | Standard git hooks |
| **VS Code (others)** | ❌ No | ✅ Yes (extension) | Requires Extension API |

---

## Updated Implementation Plan

### Revised Priorities

**Phase 0: Research** ✅ **COMPLETE**
- ✅ GitHub Copilot format analysis
- ✅ Aider integration approach
- ✅ VS Code Extension API requirements

**Phase 1: GitHub Copilot Support (1-2 weeks)**
- Add Copilot format detection and parsing
- Implement Copilot response formatter
- Update tool policy checker
- Add tests for Copilot format
- Create docs/GITHUB_COPILOT.md

**Phase 2: Aider Documentation (1-3 days)**
- Create docs/AIDER.md
- Create examples/aider/ scripts
- Update README.md

**Phase 3: VS Code Extension (3-4 weeks)**
- Create vscode-ai-guardian extension
- Implement Language Model Tool
- Implement MCP server wrapper
- Publish to VS Code Marketplace

**Optional Phase 4: Plugin Architecture (2-3 weeks)**
- Only if we want to refactor for maintainability
- Extract format adapters to plugin system
- Not required for functionality

---

## Coverage Projection

| Phase | IDEs Supported | New Coverage |
|-------|----------------|--------------|
| **Current (v1.1.0)** | 3 | Claude Code, VS Code Claude, Cursor |
| **After Phase 1** | 4 | +GitHub Copilot |
| **After Phase 2** | 4 | +Aider (commit-time only) |
| **After Phase 3** | 7+ | +VS Code (Copilot, Continue, Cline) |

**Total Potential:** 7+ AI assistants protected

---

## Timeline Estimates

| Phase | Optimistic | Realistic | Conservative |
|-------|-----------|-----------|--------------|
| **Phase 1: GitHub Copilot** | 1 week | 1-2 weeks | 2-3 weeks |
| **Phase 2: Aider** | 1 day | 2-3 days | 1 week |
| **Phase 3: VS Code Extension** | 3 weeks | 3-4 weeks | 5-6 weeks |
| **Total (sequential)** | 4.2 weeks | 5-7 weeks | 8-10 weeks |

**Parallel Execution:**
- Phase 1 and Phase 2 can run in parallel
- Phase 3 depends on Phase 1 (shared code patterns)

**Realistic Timeline:** 5-7 weeks total

---

## Integration with Issue #3 (`ai-guardian setup` command)

Issue #3 proposes adding an `ai-guardian setup` command to automate hook configuration.

**Impact on Multi-IDE Support:**

**Immediate (for current IDEs):**
```bash
ai-guardian setup --ide claude      # Setup Claude Code
ai-guardian setup --ide cursor      # Setup Cursor
```

**After Phase 1 (GitHub Copilot):**
```bash
ai-guardian setup --ide copilot     # Setup GitHub Copilot hooks
```

**After Phase 2 (Aider):**
```bash
ai-guardian setup --ide aider       # Create git pre-commit hook
```

**After Phase 3 (VS Code Extension):**
- Extension handles setup automatically
- No manual configuration needed

**Recommendation:**
- Implement `ai-guardian setup` alongside Phase 1
- Simplifies Copilot hook configuration
- Reduces user friction

---

## Risk Assessment

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **GitHub Copilot format changes** | Medium | High | Version detection, backward compatibility |
| **VS Code Extension API changes** | Low | Medium | Follow VS Code stable API |
| **Performance issues (subprocess overhead)** | Medium | Medium | Caching, async execution |
| **Gitleaks compatibility** | Low | High | Pin Gitleaks version in docs |

### Project Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Scope creep** | High | Medium | Clear phase boundaries |
| **Testing complexity** | Medium | Medium | Automated tests, CI/CD |
| **Documentation debt** | Medium | Low | Write docs alongside code |

---

## Recommendations

### High Priority (Phase 1 & 2)

1. **Implement GitHub Copilot support**
   - Highest user demand
   - Moderate complexity
   - 1-2 week effort

2. **Document Aider integration**
   - Quick win (1-3 days)
   - No code changes
   - Useful for git-based workflows

### Medium Priority (Phase 3)

3. **Create VS Code extension**
   - Unlocks multiple assistants
   - Longer effort (3-4 weeks)
   - Can be separate release

### Low Priority (Optional)

4. **Plugin architecture refactor**
   - Only if maintainability becomes issue
   - Can defer until Phase 3 complete

---

## Success Criteria

**Phase 0 (Research):** ✅ Complete
- [x] Documented GitHub Copilot format requirements
- [x] Documented Aider integration approach
- [x] Documented VS Code extension requirements
- [x] Created decision matrix (config vs code)
- [x] Updated timeline and effort estimates

**Phase 1 (GitHub Copilot):**
- [ ] ai-guardian detects Copilot format
- [ ] Copilot hooks successfully block prompts with secrets
- [ ] Copilot hooks successfully block tools accessing denied directories
- [ ] All tests passing
- [ ] Documentation complete

**Phase 2 (Aider):**
- [ ] Git pre-commit hook example created
- [ ] Documentation complete
- [ ] Tested with real Aider installation
- [ ] README updated

**Phase 3 (VS Code Extension):**
- [ ] Extension published to VS Code Marketplace
- [ ] Works with GitHub Copilot in VS Code
- [ ] Works with Continue.dev
- [ ] Works with Cline
- [ ] Documentation complete

---

## Files Created in Phase 0

1. ✅ `research/github-copilot-format.md` (comprehensive)
2. ✅ `research/aider-format.md` (comprehensive)
3. ✅ `research/vscode-format.md` (comprehensive)
4. ✅ `research/SUMMARY.md` (this file)

---

## Next Steps

### Immediate (Post-Research)

1. **Update Issue #1:**
   - Document research findings
   - Update implementation plan
   - Revise timeline estimates
   - Clarify that configuration-only approach is NOT viable for Copilot

2. **Decide on Implementation Order:**
   - Option A: GitHub Copilot first (highest demand)
   - Option B: Aider first (quick win, documentation only)
   - Option C: Parallel (both simultaneously)

3. **Plan Phase 1 Implementation:**
   - Create detailed task breakdown
   - Set up development branch
   - Write failing tests first (TDD approach)

### Short-term (Phase 1)

4. **Implement GitHub Copilot Support:**
   - Add `IDEType.GITHUB_COPILOT` enum
   - Update detection logic
   - Update response formatting
   - Update tool extraction
   - Add comprehensive tests
   - Create documentation

5. **Integrate with Issue #3:**
   - Add Copilot detection to `ai-guardian setup`
   - Automate hook configuration

---

## Conclusion

**Key Findings:**
1. ❌ **Configuration-only approach does NOT work** for GitHub Copilot
2. ✅ **Aider integration is simple** - documentation only
3. ✅ **VS Code Claude already works** - extension needed for other assistants
4. ⏱️ **Realistic timeline: 5-7 weeks** for all three phases

**Recommended Path Forward:**
1. Implement GitHub Copilot support (1-2 weeks)
2. Document Aider integration (1-3 days)
3. Create VS Code extension (3-4 weeks)

**Total Coverage:** 7+ AI assistants protected (up from current 3)

---

**Research Completed:** 2026-03-27
**Research By:** Claude Sonnet 4.5 (via DevAIFlow session)
**Next Action:** Update issue #1 and begin Phase 1 implementation planning

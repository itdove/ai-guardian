# VS Code Extension API Research

**Research Date:** 2026-03-27
**Status:** ✅ Complete
**Finding:** **EXTENSION REQUIRED** for GitHub Copilot, Continue.dev, Cline support

---

## Important Clarification

**ai-guardian already supports VS Code Claude extension!** It uses the same hook format as Claude Code CLI.

This research is about extending support to **OTHER** VS Code AI assistants:
- ✅ **Already Works:** VS Code Claude extension (via Claude Code hooks)
- 🔍 **Needs Extension:** GitHub Copilot, Continue.dev, Cline

---

## Executive Summary

To support additional VS Code AI assistants (GitHub Copilot, Continue.dev, Cline), ai-guardian needs a VS Code extension that either:
1. Registers as a Language Model Tool (for Copilot)
2. Implements an MCP server (for Continue.dev, Cline)
3. Or both (recommended)

**Current Status:**
- ✅ VS Code Claude: Already supported (uses Claude Code hook format)
- ❌ GitHub Copilot: Needs VS Code extension
- ❌ Continue.dev: Needs MCP server or extension
- ❌ Cline: Needs MCP server or extension

**Effort:** 3-4 weeks for VS Code extension + MCP server

---

## 1. Current VS Code Support

### What Already Works

**VS Code Claude Extension:**
- Uses Claude Code's hook system
- Configuration in `~/.claude/settings.json`
- Same JSON format as Claude Code CLI
- Already fully supported by ai-guardian!

**Example configuration (already works):**
```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "ai-guardian",
            "statusMessage": "🛡️ Scanning prompt..."
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "ai-guardian",
            "statusMessage": "🛡️ Checking tool permissions..."
          }
        ]
      }
    ]
  }
}
```

### What Needs Extension Support

**Other VS Code AI Assistants:**
- GitHub Copilot - Native VS Code integration
- Continue.dev - Open-source AI code assistant
- Cline - Autonomous AI agent
- Any future VS Code AI tools

These require a different integration approach than hooks.

---

## 2. VS Code Language Model API

### Overview

The VS Code Language Model API provides extensions with direct access to AI models (GPT-4o, Claude 3.5 Sonnet, etc.) for creating AI-powered features.

**Three-step process:**
1. **Build the prompt** using `LanguageModelChatMessage`
2. **Select and query a model** via `selectChatModels()` and `sendRequest()`
3. **Process the streaming response**

**Supported models:**
- GPT-4o, GPT-4o-mini, O1
- Claude 3.5 Sonnet
- Requires user authentication/consent

---

## 3. Integration Approaches for New Assistants

### Option A: Language Model Tool API (Recommended for Copilot)

**Purpose:** Register tools that AI assistants can invoke automatically

**How it works:**
1. Define tool in `package.json`
2. Register via `vscode.lm.registerTool()`
3. AI invokes tool based on context

**Example:**
```typescript
// package.json
"contributes": {
  "languageModelTools": [{
    "name": "security_check",
    "displayName": "AI Guardian Security Check",
    "description": "Scan code for secrets and security issues",
    "modelDescription": "Check code for API keys, tokens, secrets, and security vulnerabilities",
    "inputSchema": {
      "type": "object",
      "properties": {
        "code": {"type": "string", "description": "Code to scan"}
      }
    }
  }]
}

// extension.ts
vscode.lm.registerTool('security_check', {
  invoke: async (input) => {
    // Call ai-guardian subprocess
    const result = await callAiGuardian(input.code);
    return new vscode.LanguageModelToolResult([
      new vscode.LanguageModelTextPart(
        result.hasSecrets ? "⚠️ Security issues found" : "✓ Code is clean"
      )
    ]);
  }
});
```

**Supported Assistants:**
- ✅ GitHub Copilot
- ✅ Any extension using Language Model API

---

### Option B: MCP (Model Context Protocol) Server

**Purpose:** Cross-platform tools accessible to multiple AI assistants

**How it works:**
1. Create MCP server wrapping ai-guardian
2. Configure in `.vscode/mcp.json` or `~/.config/ai-guardian/mcp.json`
3. Assistants invoke tools via MCP protocol

**Configuration:**
```json
{
  "servers": {
    "ai-guardian": {
      "command": "python",
      "args": ["-m", "ai_guardian.mcp_server"]
    }
  }
}
```

**Supported Assistants:**
- ✅ Continue.dev
- ✅ Cline
- ✅ GitHub Copilot (with MCP support)
- ✅ Works across VS Code, Claude Web, etc.

**Advantages:**
- Cross-platform (not VS Code specific)
- Single server serves multiple assistants
- Can be deployed remotely

---

### Option C: Hybrid Approach (Recommended)

Implement both Language Model Tool and MCP server:

```
┌────────────────────────────────────────┐
│   VS Code Extension                     │
│  ┌──────────────────────────────────┐  │
│  │  Language Model Tool (Copilot)   │  │
│  │           +                      │  │
│  │  MCP Server (Continue, Cline)    │  │
│  └──────────────┬───────────────────┘  │
│                 ▼                       │
│  ┌──────────────────────────────────┐  │
│  │  ai-guardian subprocess          │  │
│  │  - Secret scanning               │  │
│  │  - Policy enforcement            │  │
│  │  - Directory blocking            │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
```

**Coverage:**
- GitHub Copilot → Language Model Tool
- Continue.dev → MCP Server
- Cline → MCP Server
- VS Code Claude → Already works (hooks)

---

## 4. Calling ai-guardian from VS Code Extension

### Subprocess Execution (Recommended for MVP)

```typescript
import { spawn } from 'child_process';

async function callAiGuardian(content: string): Promise<{allowed: boolean, error?: string}> {
  return new Promise((resolve, reject) => {
    const process = spawn('ai-guardian', []);
    let output = '';
    let errorOutput = '';

    process.stdout.on('data', (data) => {
      output += data.toString();
    });

    process.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    process.on('close', (code) => {
      resolve({
        allowed: code === 0,
        error: code === 2 ? errorOutput : undefined
      });
    });

    // Send hook data to stdin
    const hookData = {
      hook_event_name: "UserPromptSubmit",
      prompt: content
    };
    process.stdin.write(JSON.stringify(hookData));
    process.stdin.end();
  });
}
```

**Advantages:**
- ✅ Works with existing ai-guardian CLI
- ✅ No code changes to ai-guardian required
- ✅ Simple integration

**Disadvantages:**
- ⚠️ Process startup overhead (50-200ms)
- ⚠️ Requires ai-guardian installed

### Performance Optimization

**Caching strategy:**
```typescript
class AiGuardianCache {
  private cache = new Map<string, {result: boolean, timestamp: number}>();
  private cacheTTL = 300_000; // 5 minutes

  async checkWithCache(content: string): Promise<boolean> {
    const hash = hashContent(content);
    const cached = this.cache.get(hash);

    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return cached.result;
    }

    const result = await callAiGuardian(content);
    this.cache.set(hash, {result: result.allowed, timestamp: Date.now()});
    return result.allowed;
  }
}
```

---

## 5. AI Assistants in VS Code

### Compatibility Matrix

| Assistant | Type | Hook Support | MCP Support | ai-guardian Support |
|-----------|------|--------------|-------------|---------------------|
| **VS Code Claude** | Extension | ✅ Native hooks | ✅ MCP | ✅ Already works |
| **GitHub Copilot** | Built-in | ✅ Hooks (.github) | ✅ MCP | ⏭️ Needs extension |
| **Continue.dev** | Extension | ✅ Config | ✅ MCP | ⏭️ Needs MCP server |
| **Cline** | Extension | ⚠️ Limited | ✅ MCP | ⏭️ Needs MCP server |
| **Cursor** | Separate IDE | ✅ Hooks | ⚠️ Partial | ✅ Already works |

### Coverage Projection

**Current (v1.1.0):**
- ✅ Claude Code CLI
- ✅ VS Code Claude
- ✅ Cursor

**After VS Code Extension:**
- ✅ GitHub Copilot
- ✅ Continue.dev
- ✅ Cline
- ✅ Future MCP-compatible assistants

**Total:** 6+ AI assistants protected

---

## 6. Extension Implementation Plan

### Phase 1: Basic Extension (2 weeks)

**Tasks:**
1. Create VS Code extension project
2. Implement Language Model Tool registration
3. Add subprocess call to ai-guardian
4. Basic configuration UI
5. Package and test

**Deliverables:**
- `vscode-ai-guardian/` extension directory
- Working Language Model Tool for Copilot
- VS Code Marketplace package

### Phase 2: MCP Server (1-2 weeks)

**Tasks:**
1. Create MCP server wrapper (`ai_guardian/mcp_server.py`)
2. Implement MCP protocol for tools
3. Add to extension as optional server
4. Document MCP configuration

**Deliverables:**
- MCP server implementation
- Works with Continue.dev, Cline
- Cross-platform support

### Phase 3: Polish and Publish (1 week)

**Tasks:**
1. Add telemetry/logging
2. Comprehensive testing
3. Documentation and tutorials
4. Publish to VS Code Marketplace

**Deliverables:**
- Published extension
- `docs/VSCODE.md` guide
- Demo video/screenshots

---

## 7. File Structure

```
vscode-ai-guardian/
├── package.json              # Extension manifest
├── src/
│   ├── extension.ts          # Main extension code
│   ├── aiGuardian.ts         # ai-guardian subprocess wrapper
│   ├── mcpServer.ts          # MCP server implementation (optional)
│   └── cache.ts              # Result caching
├── docs/
│   └── README.md             # Extension documentation
└── tests/
    └── extension.test.ts     # Extension tests

ai-guardian/
├── src/ai_guardian/
│   └── mcp_server.py         # MCP server (optional Phase 2)
└── docs/
    └── VSCODE.md             # VS Code integration guide
```

---

## 8. Configuration

### Extension Settings

```json
{
  "aiGuardian.enabled": true,
  "aiGuardian.scanPrompts": true,
  "aiGuardian.scanFiles": true,
  "aiGuardian.cacheResults": true,
  "aiGuardian.cacheTTL": 300,
  "aiGuardian.mcpServerEnabled": false,
  "aiGuardian.mcpServerPort": 3000
}
```

### User Experience

**When Copilot tries to use code with secrets:**
```
GitHub Copilot is calling security_check...
⚠️ Security Check: Secrets detected in code
- API key found: ghp_****
- Private key found: [RSA PRIVATE KEY HEADER DETECTED]

Recommendation: Remove secrets before proceeding
```

---

## 9. Testing Strategy

### Unit Tests
- Subprocess execution
- JSON parsing
- Error handling
- Cache behavior

### Integration Tests
- Test with mock ai-guardian responses
- Test Language Model Tool invocation
- Test MCP server communication

### Manual Tests
- Install in VS Code
- Test with GitHub Copilot
- Test with Continue.dev
- Test with Cline

---

## 10. Implementation Estimate

**Total Effort:** 3-4 weeks

| Phase | Tasks | Effort |
|-------|-------|--------|
| **Phase 1: Extension** | Project setup, Language Model Tool, subprocess integration | 2 weeks |
| **Phase 2: MCP Server** | MCP protocol, server wrapper, integration | 1-2 weeks |
| **Phase 3: Polish** | Testing, docs, marketplace publish | 1 week |

**Files to Create:**
1. `vscode-ai-guardian/` - Extension project (new)
2. `src/ai_guardian/mcp_server.py` - MCP server (new, optional)
3. `docs/VSCODE.md` - Integration guide (new)

**Files to Update:**
1. `README.md` - Add VS Code extension section
2. `CHANGELOG.md` - Document extension release

---

## 11. Alternative: Configuration-Only Approach

**For Continue.dev and Cline only:**

Users can manually configure MCP server without extension:

```json
// .vscode/mcp.json
{
  "servers": {
    "ai-guardian": {
      "command": "ai-guardian",
      "args": ["--mcp-server"]
    }
  }
}
```

**Limitations:**
- Doesn't work for GitHub Copilot (requires Language Model Tool)
- Less discoverable
- No UI for configuration
- Requires manual setup

---

## 12. Conclusion

### Key Findings

**Current Support:**
- ✅ VS Code Claude: Already works (uses Claude Code hooks)
- ✅ Cursor: Already works (dedicated hook format)

**Needs Extension:**
- ⏭️ GitHub Copilot: Language Model Tool required
- ⏭️ Continue.dev: MCP server recommended
- ⏭️ Cline: MCP server recommended

**Recommended Path:**
1. Create VS Code extension with Language Model Tool (GitHub Copilot)
2. Add MCP server wrapper (Continue.dev, Cline)
3. Publish to VS Code Marketplace

**Effort:** 3-4 weeks total

---

## 13. Next Steps

1. ✅ Document findings (this file)
2. ⏭️ Update implementation plan in issue #1
3. ⏭️ Prioritize: GitHub Copilot (code changes) vs VS Code extension
4. ⏭️ Decide: MCP server in Phase 1 or Phase 2

---

## 14. Sources

- [Language Model API - VS Code Extension API](https://code.visualstudio.com/api/extension-guides/ai/language-model)
- [Language Model Tool API - VS Code](https://code.visualstudio.com/api/extension-guides/ai/tools)
- [MCP Developer Guide - VS Code](https://code.visualstudio.com/api/extension-guides/ai/mcp)
- [AI Extensibility Overview - VS Code](https://code.visualstudio.com/api/extension-guides/ai/ai-extensibility-overview)
- [Continue.dev Extension](https://marketplace.visualstudio.com/items?itemName=Continue.continue)
- [Cline Extension](https://marketplace.visualstudio.com/items?itemName=saoudrizwan.claude-dev)
- [VS Code Extension API Reference](https://code.visualstudio.com/api/references/vscode-api)
- ai-guardian README.md (current support matrix)

---

**Last Updated:** 2026-03-27
**Confidence Level:** High - Based on VS Code Extension API and ai-guardian analysis

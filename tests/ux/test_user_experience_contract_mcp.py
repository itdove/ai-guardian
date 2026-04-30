"""
User Experience Contract Tests for MCP Security Features

These tests document and verify the expected user experience when ai-guardian
protects against MCP tool threats. They serve as a "contract" that defines
what users should see in Claude Code when MCP security protections trigger.

Issue #226: Document UX for MCP security features (permissions, secrets, SSRF,
prompt injection, and clean operations).

IMPORTANT: These tests use explicit configuration dicts and mocks to ensure
test isolation. They do NOT rely on the user's ~/.config/ai-guardian/ai-guardian.json
file, ensuring consistent behavior in CI/CD and across different environments.
"""

import json
from io import StringIO
from unittest import TestCase
from unittest.mock import patch

import pytest

import ai_guardian
from tests.fixtures.mock_mcp_server import create_hook_data, create_tool_response
from tests.fixtures import attack_constants


class MCPUserExperienceContractTests(TestCase):
    """
    Tests documenting the user experience contract for MCP security protections.

    These tests verify what users SHOULD see when ai-guardian is configured
    in Claude Code's PreToolUse and PostToolUse hooks to protect MCP operations.
    """

    def test_user_experience_mcp_tool_blocked(self):
        """
        USER EXPERIENCE: MCP tool blocked → DENIED immediately, no prompt shown.

        Scenario:
        1. Claude Code permission: "Ask before using MCP tools" (user wants review)
        2. User asks Claude: "Create a NotebookLM notebook"
        3. Claude tries to call mcp__notebooklm-mcp__notebook_create
        4. ai-guardian PreToolUse hook runs
        5. Tool is NOT in allowlist

        Expected User Experience:
        ❌ Claude Code does NOT show permission prompt
        ❌ Operation is BLOCKED immediately
        🛡️ User sees error: "TOOL ACCESS DENIED: Tool not in allow list"

        This is CORRECT behavior - unauthorized MCP tools should be blocked,
        regardless of user permission settings, to prevent malicious tool usage.
        """
        # Configure: MCP tools require explicit allow
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "mcp__notebooklm-mcp__*",
                        "mode": "allow",
                        "patterns": [
                            "mcp__notebooklm-mcp__notebook_list",
                            "mcp__notebooklm-mcp__notebook_get"
                        ]
                    }
                ]
            }
        }

        from ai_guardian.tool_policy import ToolPolicyChecker
        policy_checker = ToolPolicyChecker(config=config)

        # Claude Code invokes PreToolUse hook
        hook_data = create_hook_data(
            tool_name=attack_constants.MCP_TOOL_NOTEBOOKLM_CREATE,
            tool_input={"title": "My Research Notes"},
            hook_event="PreToolUse"
        )

        # ai-guardian checks tool permission
        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)

        # Verify ai-guardian's response
        assert not allowed, "Tool not in allowlist should be denied"
        assert error_msg is not None, "Must include error message"
        assert "not in allow list" in error_msg.lower() or "denied" in error_msg.lower(), \
            f"Error should explain tool is not allowed: {error_msg}"

        # USER SEES: Error message in Claude Code
        # USER DOES NOT SEE: Permission prompt (operation blocked before prompt)
        # OPERATION: Denied, notebook not created, tool not executed

    @patch('ai_guardian._load_secret_scanning_config')
    @patch('ai_guardian._load_secret_redaction_config')
    @patch('ai_guardian._load_pattern_server_config')
    def test_user_experience_secret_in_mcp_output(self, mock_pattern_config, mock_redaction_config, mock_scan_config):
        """
        USER EXPERIENCE: Secret in MCP output → Currently NOT scanned by default.

        Scenario:
        1. User asks Claude: "Query my notebook about API keys"
        2. Claude calls mcp__notebooklm-mcp__notebook_query
        3. Tool executes and returns response containing Slack token
        4. ai-guardian PostToolUse hook runs
        5. MCP tool output currently NOT scanned for secrets

        Current Behavior (as of this test):
        ⚠️ MCP tool responses are NOT extracted/scanned by default
        ✅ PostToolUse returns exit 0 with empty response
        ❌ Secret passes through to AI (not ideal)

        Expected Future Behavior:
        🛡️ Secret should be REDACTED from output
        ⚠️ User should see warning: "Redacted secrets from tool output"
        ✅ AI should receive redacted version (secrets removed)

        Note: This test documents current behavior. MCP tool response extraction
        needs to be implemented in extract_tool_result() function to enable
        secret scanning for MCP outputs.

        Reference: tests/unit/test_posttooluse_mcp.py::test_mcp_response_with_secret_allowed_by_default
        """
        # Configure mocks to avoid loading user's config file
        mock_pattern_config.return_value = None
        mock_redaction_config.return_value = ({"enabled": True, "action": "warn"}, None)
        mock_scan_config.return_value = ({"enabled": True, "ignore_files": [], "ignore_tools": []}, None)

        # Simulate MCP tool response containing secret
        tool_output = f"""
        Here are the findings from your notebook:
        - API endpoint: https://api.slack.com/v1
        - Auth token: {attack_constants.SECRET_SLACK_TOKEN}
        - Status: active
        """

        # Claude Code invokes PostToolUse hook after tool execution
        hook_data = create_tool_response(
            tool_name=attack_constants.MCP_TOOL_NOTEBOOKLM_QUERY,
            output={"answer": tool_output, "status": "success"}
        )

        with patch('sys.stdin', StringIO(json.dumps(hook_data))):
            result = ai_guardian.process_hook_input()

        # Verify ai-guardian's current response (empty because MCP not scanned)
        assert result['exit_code'] == 0, "PostToolUse always returns exit 0"

        response = json.loads(result['output'])

        # CURRENT BEHAVIOR: Empty response because MCP outputs not scanned
        # If extract_tool_result() doesn't handle this MCP tool specifically,
        # it returns None and scanning is skipped
        assert response == {}, \
            "Current behavior: MCP tool outputs not scanned, returns empty response"

        # USER SEES: No warning (current behavior)
        # AI RECEIVES: Original output with secret (current behavior - not ideal)
        # OPERATION: Already executed on MCP server
        #
        # FUTURE IMPROVEMENT: Implement MCP output extraction in extract_tool_result()
        # to enable secret scanning and redaction for MCP tool responses

    @patch('ai_guardian._load_pattern_server_config')
    def test_user_experience_ssrf_in_mcp_parameter(self, mock_pattern_config):
        """
        USER EXPERIENCE: SSRF attempt in MCP parameter → DENIED immediately.

        Scenario:
        1. User asks Claude: "Add source from http://169.254.169.254/metadata"
        2. Claude tries to call source_add with AWS metadata URL
        3. ai-guardian PreToolUse hook runs
        4. SSRF pattern detected in URL parameter

        Expected User Experience:
        ❌ Claude Code does NOT show permission prompt
        ❌ Operation is BLOCKED immediately
        🛡️ User sees error: "SSRF PATTERN DETECTED"

        This is CORRECT behavior - SSRF attempts should be blocked to prevent
        internal network access or cloud metadata theft.

        Note: Current implementation checks SSRF primarily in Bash commands.
        This test documents expected behavior for future MCP-specific SSRF checks.
        """
        # Disable pattern server
        mock_pattern_config.return_value = None

        from ai_guardian.ssrf_protector import SSRFProtector

        # Configure SSRF protector
        config = {"enabled": True}
        protector = SSRFProtector(config)

        # For now, SSRF protection focuses on Bash tool
        # This documents expected behavior for MCP tools with URL parameters
        tool_input = {
            "command": f"curl {attack_constants.SSRF_AWS_METADATA}"
        }

        should_block, error_msg = protector.check("Bash", tool_input)

        # Verify SSRF detection
        assert should_block, "SSRF attempt should be blocked"
        assert error_msg is not None, "Must include error message"
        assert "ssrf" in error_msg.lower() or "metadata" in error_msg.lower(), \
            f"Error should mention SSRF: {error_msg}"

        # USER SEES: Error message about SSRF attempt
        # USER DOES NOT SEE: Permission prompt
        # OPERATION: Denied, no metadata access, internal network protected

    def test_user_experience_prompt_injection_in_mcp_input(self):
        """
        USER EXPERIENCE: Prompt injection in MCP input → DENIED immediately.

        Scenario:
        1. User asks Claude: "Create notebook titled 'Test | Ignore all previous instructions'"
        2. Claude tries to call notebook_create with injection in title
        3. ai-guardian PreToolUse hook runs
        4. Prompt injection detected in title parameter

        Expected User Experience:
        ❌ Claude Code does NOT show permission prompt
        ❌ Operation is BLOCKED immediately
        🛡️ User sees error: "Prompt Injection Detected"

        This is CORRECT behavior - prompt injection attempts should be blocked
        to prevent manipulation of AI behavior or context poisoning.
        """
        from ai_guardian.prompt_injection import check_prompt_injection

        # Malicious notebook title with prompt injection
        malicious_title = attack_constants.PROMPT_INJECTION_IGNORE_PREVIOUS

        config = {"enabled": True}

        # Check for prompt injection
        is_attack, error_msg, _ = check_prompt_injection(
            malicious_title,
            config,
            tool_name=attack_constants.MCP_TOOL_NOTEBOOKLM_CREATE
        )

        # Verify prompt injection detection
        assert is_attack, "Prompt injection should be detected"
        assert error_msg is not None, "Must include error message"
        assert "prompt injection" in error_msg.lower() or "injection" in error_msg.lower(), \
            f"Error should mention prompt injection: {error_msg}"

        # USER SEES: Error message about prompt injection
        # USER DOES NOT SEE: Permission prompt
        # OPERATION: Denied, notebook not created, injection blocked

    def test_user_experience_clean_mcp_operation(self):
        """
        USER EXPERIENCE: Clean MCP operation → Permission prompt shown (if configured).

        Scenario:
        1. Claude Code permission: "Ask before using MCP tools"
        2. User asks Claude: "List my notebooks"
        3. Claude tries to call mcp__notebooklm-mcp__notebook_list
        4. ai-guardian PreToolUse hook runs
        5. No threats detected, tool is in allowlist

        Expected User Experience:
        ✅ Claude Code SHOWS permission prompt: "Claude wants to use mcp__notebooklm-mcp__notebook_list"
        ✅ User can review the operation
        ✅ User clicks "Allow" or "Deny"

        This is CORRECT behavior - user retains control over MCP operations
        when no security threats are detected.

        This follows the same principle as issue #224 fix - ai-guardian
        returns empty response (no auto-approve), allowing Claude Code's
        normal permission system to work.
        """
        # Configure: Allow notebook_list tool
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "mcp__notebooklm-mcp__*",
                        "mode": "allow",
                        "patterns": [
                            "mcp__notebooklm-mcp__notebook_list",
                            "mcp__notebooklm-mcp__notebook_get"
                        ]
                    }
                ]
            }
        }

        from ai_guardian.tool_policy import ToolPolicyChecker
        policy_checker = ToolPolicyChecker(config=config)

        # Claude Code invokes PreToolUse hook
        hook_data = create_hook_data(
            tool_name="mcp__notebooklm-mcp__notebook_list",
            tool_input={},
            hook_event="PreToolUse"
        )

        # ai-guardian checks tool (clean operation)
        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)

        # Verify ai-guardian allows operation (returns empty response)
        assert allowed, f"Clean allowed tool should pass: {error_msg}"
        assert error_msg is None, "No error for clean operation"

        # IMPORTANT: ai-guardian does NOT auto-approve
        # It returns empty response, allowing Claude Code to show permission prompt

        # USER SEES: Claude Code permission prompt (because ai-guardian didn't auto-approve)
        # PROMPT SHOWS: "Claude wants to use mcp__notebooklm-mcp__notebook_list"
        # USER CHOOSES: Allow or Deny
        # OPERATION: Proceeds only if user approves

    @patch('ai_guardian._load_pattern_server_config')
    def test_user_experience_comparison_threat_vs_clean_mcp(self, mock_pattern_config):
        """
        USER EXPERIENCE COMPARISON: Threat vs Clean MCP operations.

        This test demonstrates the difference in user experience between
        MCP operations with threats (denied) vs clean operations (prompt shown).

        Scenario A: MCP tool with prompt injection
        ===========================================
        1. User asks: "Create notebook with injection attack"
        2. ai-guardian: DENIES immediately
        3. User sees: Error message "Prompt injection detected"
        4. User does NOT see: Permission prompt
        5. Result: Notebook NOT created (attack blocked)

        Scenario B: Clean MCP tool operation
        ====================================
        1. User asks: "List my notebooks"
        2. ai-guardian: Returns empty response (no auto-approve)
        3. User sees: Permission prompt "Claude wants to use notebook_list"
        4. User clicks: "Allow"
        5. Result: Notebooks listed (user gave explicit consent)

        This is the CORRECT behavior for MCP security.
        """
        # Disable pattern server
        mock_pattern_config.return_value = None

        from ai_guardian.prompt_injection import check_prompt_injection
        from ai_guardian.tool_policy import ToolPolicyChecker

        # Scenario A: MCP operation with prompt injection
        malicious_title = attack_constants.PROMPT_INJECTION_IGNORE_PREVIOUS

        config_pi = {"enabled": True}
        is_attack, error_msg, _ = check_prompt_injection(
            malicious_title,
            config_pi,
            tool_name=attack_constants.MCP_TOOL_NOTEBOOKLM_CREATE
        )

        # Scenario A verification: Immediate denial
        assert is_attack, "Prompt injection should be detected"
        assert error_msg is not None, "Must have error message for attack"
        assert "injection" in error_msg.lower(), \
            f"Error should mention injection: {error_msg}"

        # Scenario B: Clean MCP operation
        config_tool = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "mcp__notebooklm-mcp__*",
                        "mode": "allow",
                        "patterns": ["mcp__notebooklm-mcp__notebook_list"]
                    }
                ]
            }
        }

        policy_checker = ToolPolicyChecker(config=config_tool)

        hook_data = create_hook_data(
            tool_name="mcp__notebooklm-mcp__notebook_list",
            tool_input={},
            hook_event="PreToolUse"
        )

        allowed, error_msg, _ = policy_checker.check_tool_allowed(hook_data)

        # Scenario B verification: Allowed, no auto-approve
        assert allowed, f"Clean operation should be allowed: {error_msg}"
        assert error_msg is None, "No error for clean operation"

        # SUMMARY: Different user experiences
        # MCP with Threat: User sees error, operation blocked immediately
        # Clean MCP: User sees prompt, chooses to allow/deny

    def test_user_experience_documentation_mcp(self):
        """
        Documentation test: What users should expect for MCP security.

        This test always passes but documents the expected behavior
        for users configuring ai-guardian in Claude Code with MCP servers.

        Configuration:
        ==============
        ~/.claude/settings.json:
        {
          "PreToolUse": [
            {
              "matcher": "*",
              "hooks": [
                {
                  "command": "ai-guardian",
                  "statusMessage": "🛡️ AI Guardian checking..."
                }
              ]
            }
          ],
          "PostToolUse": [
            {
              "matcher": "*",
              "hooks": [
                {
                  "command": "ai-guardian",
                  "statusMessage": "🛡️ AI Guardian scanning output..."
                }
              ]
            }
          ]
        }

        Expected User Experience for MCP Tools:
        ========================================

        1. MCP TOOL BLOCKED (not in allowlist):
           ❌ BLOCKED immediately (PreToolUse)
           🛡️ Error shown: "TOOL ACCESS DENIED: Tool not in allow list"
           ⚠️ No permission prompt (security override)

        2. PROMPT INJECTION IN MCP INPUT:
           ❌ BLOCKED immediately (PreToolUse)
           🛡️ Error shown: "Prompt Injection Detected"
           ⚠️ No permission prompt (security override)

        3. SECRET IN MCP OUTPUT:
           ⚠️ CURRENT: MCP outputs NOT scanned by default (limitation)
           ⚠️ Secret passes through to AI (not ideal)
           🔧 FUTURE: Should redact secrets and show warning
           📝 Note: Requires MCP output extraction implementation

        4. SSRF IN MCP PARAMETER:
           ❌ BLOCKED immediately (PreToolUse)
           🛡️ Error shown: "SSRF PATTERN DETECTED"
           ⚠️ No permission prompt (security override)

        5. CLEAN MCP OPERATION (allowed, no threats):
           ✅ Permission prompt shown (if configured)
           👤 User reviews and approves/denies
           ✅ User maintains control

        This is the correct behavior for MCP security protection.
        All threats are blocked before execution or output exposure,
        while clean operations follow normal permission flow.
        """
        # This test always passes - it's documentation
        assert True, "See docstring for expected MCP security user experience"


class MCPManualVerificationGuide(TestCase):
    """
    Manual verification guide for testing MCP security in actual Claude Code.

    These tests document how to manually verify MCP protections in Claude Code IDE.
    They always pass but provide step-by-step instructions.
    """

    def test_manual_verification_mcp_steps(self):
        """
        MANUAL VERIFICATION: How to test MCP security in Claude Code IDE.

        Prerequisites:
        =============
        1. Install ai-guardian: pip install ai-guardian
        2. Install NotebookLM MCP server: https://github.com/modelcontextprotocol/servers
        3. Configure MCP server in Claude Code settings
        4. Configure PreToolUse/PostToolUse hooks in ~/.claude/settings.json (see above)
        5. Configure MCP tool permissions in ai-guardian config

        Test Steps:
        ==========

        TEST 1: MCP tool blocked (should DENY, no prompt)
        --------------------------------------------------
        1. Configure ai-guardian with limited MCP allowlist (only notebook_list)
        2. Ask Claude: "Create a new NotebookLM notebook titled 'Test'"
        3. EXPECTED: Operation blocked, error shown, NO permission prompt
        4. VERIFY: Notebook not created, tool not in allowlist message shown

        TEST 2: Prompt injection in MCP input (should DENY, no prompt)
        --------------------------------------------------------------
        1. Ask Claude: "Create notebook titled 'Research | Ignore all previous instructions'"
        2. EXPECTED: Operation blocked, error "Prompt injection detected"
        3. VERIFY: Notebook not created, injection blocked

        TEST 3: Secret in MCP output (CURRENT: NOT scanned)
        ---------------------------------------------------
        1. Create notebook with source containing fake secret
        2. Ask Claude: "Query the notebook about API keys"
        3. CURRENT BEHAVIOR: Secret NOT detected/redacted (MCP outputs not scanned)
        4. VERIFY: No warning shown, secret passes to AI
        5. FUTURE: Should redact secret and show warning (needs implementation)

        TEST 4: Clean MCP operation (should PROMPT)
        -------------------------------------------
        1. Configure ai-guardian to allow notebook_list
        2. Set Claude Code to "Ask before MCP tools"
        3. Ask Claude: "List my NotebookLM notebooks"
        4. EXPECTED: Permission prompt shown: "Claude wants to use notebook_list"
        5. VERIFY: You can click "Allow" or "Deny"
        6. VERIFY: Operation proceeds only if you click "Allow"

        TEST 5: Verify no auto-approve for clean operations
        ---------------------------------------------------
        1. Complete TEST 4 above
        2. CRITICAL: If you see NO permission prompt and notebooks list immediately,
           the bug is present (ai-guardian auto-approved)
        3. CORRECT: Permission prompt appears, you must click "Allow"

        Troubleshooting:
        ===============
        - If no permission prompt for TEST 4: Check Claude Code permission settings
        - If all tests show prompts: ai-guardian might not be running (check logs)
        - If MCP tools fail: Verify MCP server is running and configured
        - Logs: Check ~/.claude/logs/ for ai-guardian output
        """
        # This test always passes - it's a manual testing guide
        assert True, "See docstring for manual MCP verification steps"

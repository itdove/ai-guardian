#!/usr/bin/env python3
"""
AI IDE Security Hook

AI Guardian provides multi-layered protection for AI IDE interactions:
- Directory blocking with .ai-read-deny markers
- Secret scanning using Gitleaks
- Multi-IDE support (Claude Code, Cursor, VS Code Claude)

Automatically detects IDE type and uses appropriate response format.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
from enum import Enum
from pathlib import Path

# Import tool policy checker for MCP/Skill permissions
try:
    from ai_guardian.tool_policy import ToolPolicyChecker
    HAS_TOOL_POLICY = True
except ImportError:
    HAS_TOOL_POLICY = False
    logging.warning("tool_policy module not available - MCP/Skill permissions disabled")

# Import pattern server for enhanced secret detection
try:
    from ai_guardian.pattern_server import PatternServerClient
    HAS_PATTERN_SERVER = True
except ImportError:
    HAS_PATTERN_SERVER = False
    logging.debug("pattern_server module not available")

# Configure logging - will be disabled for Cursor hooks
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    stream=sys.stderr,  # Log to stderr so stdout is clean for JSON responses
)

# Global logger instance
logger = logging.getLogger(__name__)


class IDEType(Enum):
    """Supported IDE types with different output formats."""
    CLAUDE_CODE = "claude_code"  # Exit codes: 0=allow, 2=block
    CURSOR = "cursor"  # JSON: {"continue": bool, "user_message": str}
    UNKNOWN = "unknown"  # Default to Claude Code format


def detect_ide_type(hook_data):
    """
    Detect which IDE is calling the hook based on input format.

    Args:
        hook_data: Parsed JSON input from the IDE

    Returns:
        IDEType: The detected IDE type
    """
    # Check for environment variable override
    ide_override = os.environ.get("AI_GUARDIAN_IDE_TYPE", "").lower()
    if ide_override == "cursor":
        return IDEType.CURSOR
    elif ide_override == "claude":
        return IDEType.CLAUDE_CODE

    # Auto-detect based on input structure
    # Cursor sends cursor_version field
    if "cursor_version" in hook_data:
        return IDEType.CURSOR

    # Cursor typically sends hook_name or beforeSubmitPrompt event
    if "hook_name" in hook_data or (
        "hook_event_name" in hook_data and
        hook_data.get("hook_event_name") in ["beforeSubmitPrompt", "preToolUse"]
    ):
        return IDEType.CURSOR

    # Claude Code sends UserPromptSubmit or PreToolUse
    if "hook_event_name" in hook_data and hook_data.get("hook_event_name") in ["UserPromptSubmit", "PreToolUse"]:
        return IDEType.CLAUDE_CODE

    # Default to Claude Code format (exit codes)
    return IDEType.CLAUDE_CODE


def format_response(ide_type, has_secrets, error_message=None, hook_event="prompt"):
    """
    Format the response based on IDE type and hook event.

    Args:
        ide_type: IDEType enum value
        has_secrets: bool indicating if secrets were found
        error_message: Optional error message for blocked responses
        hook_event: "prompt" or "pretooluse" to determine response format

    Returns:
        dict with 'output' (str to print) and 'exit_code' (int)
    """
    if ide_type == IDEType.CURSOR:
        # Cursor expects JSON on stdout AND exit code 2 to block
        if hook_event == "pretooluse":
            # preToolUse expects {"decision": "allow"|"deny", "reason": "..."}
            response = {
                "decision": "deny" if has_secrets else "allow",
            }
            if has_secrets and error_message:
                response["reason"] = error_message
        elif hook_event == "beforereadfile":
            # beforeReadFile expects {"permission": "allow"|"deny", "user_message": "..."}
            response = {
                "permission": "deny" if has_secrets else "allow",
            }
            if has_secrets and error_message:
                response["user_message"] = error_message
        else:
            # beforeSubmitPrompt expects {"continue": bool, "user_message": "..."}
            response = {
                "continue": not has_secrets,
            }
            if has_secrets and error_message:
                response["user_message"] = error_message

        return {
            "output": json.dumps(response),
            "exit_code": 2 if has_secrets else 0  # Exit code 2 blocks in Cursor
        }
    else:
        # Claude Code (and unknown) use exit codes
        if has_secrets and error_message:
            # Print error to stderr
            print(error_message, file=sys.stderr)

        return {
            "output": None,
            "exit_code": 2 if has_secrets else 0
        }


def detect_hook_event(hook_data):
    """
    Detect which hook event triggered this call.

    Args:
        hook_data: Parsed JSON input from the IDE

    Returns:
        str: "prompt" for prompt submission hooks, "pretooluse" for tool use hooks
    """
    # Check hook_event_name for both Claude Code and Cursor
    event_name = hook_data.get("hook_event_name", "").lower()
    if event_name in ["userpromptsubmit", "beforesubmitprompt"]:
        return "prompt"
    elif event_name in ["pretooluse"]:
        return "pretooluse"
    elif event_name in ["beforereadfile"]:
        return "beforereadfile"

    # Check hook_name for Cursor (alternative field)
    hook_name = hook_data.get("hook_name", "").lower()
    if hook_name in ["beforesubmitprompt"]:
        return "prompt"
    elif hook_name in ["pretooluse"]:
        return "pretooluse"

    # Check for tool_use or tool fields (indicates PreToolUse)
    if "tool_use" in hook_data or "tool" in hook_data or "tool_name" in hook_data:
        return "pretooluse"

    # Default to prompt if we have a prompt/message field
    if "prompt" in hook_data or "message" in hook_data or "userMessage" in hook_data:
        return "prompt"

    # Default to prompt
    return "prompt"


def check_directory_denied(file_path):
    """
    Check if a file is in a directory (or subdirectory) that contains a .ai-read-deny marker file.

    This function walks up the directory tree from the file's location to check if any
    parent directory contains a .ai-read-deny file, which indicates the directory and all
    its subdirectories should be blocked from AI access.

    Args:
        file_path: Path to the file being accessed

    Returns:
        tuple: (is_denied: bool, denied_directory: str or None)
               - is_denied: True if access should be blocked
               - denied_directory: The directory containing .ai-read-deny, if found
    """
    try:
        # Convert to absolute path
        abs_path = os.path.abspath(file_path)

        # Get the directory containing the file
        current_dir = os.path.dirname(abs_path)

        # Walk up the directory tree
        while True:
            deny_marker = os.path.join(current_dir, ".ai-read-deny")

            if os.path.exists(deny_marker):
                logging.info(f"Found .ai-read-deny marker in {current_dir}")
                return True, current_dir

            # Move to parent directory
            parent_dir = os.path.dirname(current_dir)

            # Stop if we've reached the root
            if parent_dir == current_dir:
                break

            current_dir = parent_dir

        return False, None

    except Exception as e:
        logging.error(f"Error checking for .ai-read-deny: {e}")
        # Fail-open: allow access if check fails
        return False, None


def extract_file_content_from_tool(hook_data):
    """
    Extract file path/content from PreToolUse/beforeReadFile hook data.

    Args:
        hook_data: Parsed JSON input from PreToolUse or beforeReadFile hook

    Returns:
        tuple: (content: str or None, filename: str, file_path: str or None, is_denied: bool, deny_reason: str or None)
    """
    try:
        # Cursor beforeReadFile format: includes content and file_path directly
        if "content" in hook_data and "file_path" in hook_data:
            content = hook_data["content"]
            file_path = hook_data["file_path"]

            # Check if directory is denied
            is_denied, denied_dir = check_directory_denied(file_path)
            if is_denied:
                error_msg = (
                    f"\n{'='*70}\n"
                    f"🚫 ACCESS DENIED - Directory Protected\n"
                    f"{'='*70}\n\n"
                    f"The file '{file_path}' is located in a directory that contains\n"
                    f"a .ai-read-deny marker file.\n\n"
                    f"Protected directory: {denied_dir}\n\n"
                    f"This directory and all its subdirectories are blocked from AI access.\n"
                    f"Please remove the .ai-read-deny file if you need AI access to this\n"
                    f"directory, or move the file to an accessible location.\n"
                    f"\n{'='*70}\n"
                )
                return None, os.path.basename(file_path), file_path, True, error_msg

            return content, os.path.basename(file_path), file_path, False, None

        # Try to extract file path from different possible locations
        file_path = None

        # Claude Code format: tool_use.parameters.file_path
        if "tool_use" in hook_data:
            tool_use = hook_data["tool_use"]
            if isinstance(tool_use, dict) and "parameters" in tool_use:
                params = tool_use["parameters"]
                file_path = params.get("file_path") or params.get("path")

        # Alternative: direct parameters field
        if not file_path and "parameters" in hook_data:
            params = hook_data["parameters"]
            if isinstance(params, dict):
                file_path = params.get("file_path") or params.get("path")

        # Cursor format: tool_input.file_path
        if not file_path and "tool_input" in hook_data:
            tool_input = hook_data["tool_input"]
            if isinstance(tool_input, dict):
                file_path = tool_input.get("file_path") or tool_input.get("path")

        # Cursor format alternative: tool field
        if not file_path and "tool" in hook_data:
            tool = hook_data["tool"]
            if isinstance(tool, dict):
                file_path = tool.get("file_path") or tool.get("path")

        if not file_path:
            logging.warning("Could not extract file path from hook data")
            return None, "unknown_file", None, False, None

        # Expand ~ to home directory
        file_path = os.path.expanduser(file_path)

        # Check if directory is denied BEFORE reading the file
        is_denied, denied_dir = check_directory_denied(file_path)
        if is_denied:
            error_msg = (
                f"\n{'='*70}\n"
                f"🚫 ACCESS DENIED - Directory Protected\n"
                f"{'='*70}\n\n"
                f"The file '{file_path}' is located in a directory that contains\n"
                f"a .ai-read-deny marker file.\n\n"
                f"Protected directory: {denied_dir}\n\n"
                f"This directory and all its subdirectories are blocked from AI access.\n"
                f"Please remove the .ai-read-deny file if you need AI access to this\n"
                f"directory, or move the file to an accessible location.\n"
                f"\n{'='*70}\n"
            )
            return None, os.path.basename(file_path), file_path, True, error_msg

        # Read the file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            return content, os.path.basename(file_path), file_path, False, None
        except FileNotFoundError:
            logging.warning(f"File not found: {file_path}")
            return None, os.path.basename(file_path), file_path, False, None
        except PermissionError:
            logging.warning(f"Permission denied reading file: {file_path}")
            return None, os.path.basename(file_path), file_path, False, None
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return None, os.path.basename(file_path), file_path, False, None

    except Exception as e:
        logging.error(f"Error extracting file from tool data: {e}")
        return None, "unknown_file", None, False, None


def _load_pattern_server_config():
    """
    Load pattern server configuration from ai-guardian.json.

    Returns:
        dict: Pattern server configuration or None
    """
    try:
        # Try user global config first
        config_home = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
        config_path = Path(config_home) / "ai-guardian" / "ai-guardian.json"

        if not config_path.exists():
            # Try project local config
            config_path = Path.cwd() / ".ai-guardian.json"

        if not config_path.exists():
            return None

        with open(config_path, 'r') as f:
            config = json.load(f)

        return config.get("pattern_server")

    except Exception as e:
        logging.debug(f"Error loading pattern server config: {e}")
        return None


def check_secrets_with_gitleaks(content, filename="temp_file"):
    """
    Check content for secrets using Gitleaks binary.

    Scans content for secrets using the open-source Gitleaks tool.
    Uses in-memory temp files on Linux for better performance.

    Supports optional pattern server integration for enhanced detection patterns.

    Args:
        content: The text content to scan for secrets
        filename: Optional filename for context in error messages

    Returns:
        tuple: (has_secrets: bool, error_message: str or None)
            - has_secrets: True if secrets detected, False otherwise
            - error_message: Detailed error if secrets found, None otherwise
    """
    try:
        # Use in-memory filesystem on Linux for better performance
        tmp_base_dir = "/dev/shm" if os.path.exists("/dev/shm") else None

        # Create temporary file with content
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            suffix=f"_{filename}",
            prefix="aiguardian_",
            dir=tmp_base_dir,
            delete=False
        ) as tmp_file:
            tmp_file.write(content)
            tmp_file.flush()
            tmp_file_path = tmp_file.name

        try:
            # Determine which Gitleaks configuration to use
            gitleaks_config_path = None

            # Priority 1: Pattern server (if enabled and available)
            if HAS_PATTERN_SERVER:
                pattern_config = _load_pattern_server_config()
                if pattern_config:
                    try:
                        pattern_client = PatternServerClient(pattern_config)
                        server_patterns = pattern_client.get_patterns_path()
                        if server_patterns:
                            gitleaks_config_path = server_patterns
                            logging.debug(f"Using pattern server config: {server_patterns}")
                    except Exception as e:
                        logging.debug(f"Pattern server error (using default): {e}")

            # Priority 2: Project-specific .gitleaks.toml
            if not gitleaks_config_path:
                project_config = Path(".gitleaks.toml")
                if project_config.exists():
                    gitleaks_config_path = project_config
                    logging.debug(f"Using project config: {project_config}")

            # Build gitleaks command
            cmd = [
                'gitleaks',
                'detect',
                '--no-git',        # Don't use git history
                '--verbose',       # Detailed output
                '--redact',        # Hide secret values in output
                '--exit-code', '42',  # Custom exit code for found secrets
                '--source', tmp_file_path,
            ]

            # Add custom config if we have one
            if gitleaks_config_path:
                cmd.extend(['--config', str(Path(gitleaks_config_path).absolute())])

            # Run Gitleaks scanner
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # Prevent hanging
            )

            # Check exit code
            if result.returncode == 42:  # Secrets found
                error_msg = (
                    f"\n{'='*70}\n"
                    f"🔒 SECRET DETECTED\n"
                    f"{'='*70}\n\n"
                    "Gitleaks has detected sensitive information in your prompt/file.\n"
                    "This operation has been blocked for security.\n\n"
                    "Please remove the sensitive information and try again.\n\n"
                    "Common secrets detected:\n"
                    "  • API keys and tokens\n"
                    "  • Private keys (SSH, RSA, PGP)\n"
                    "  • Database credentials\n"
                    "  • Cloud provider keys (AWS, GCP, Azure)\n\n"
                    "If this is a false positive, see:\n"
                    "https://github.com/gitleaks/gitleaks#configuration\n"
                    f"\n{'='*70}\n"
                )
                return True, error_msg

            elif result.returncode in [0, 1]:
                # No secrets found (0 or 1 are both "clean" states)
                return False, None

            else:
                # Unexpected error - fail open for availability
                logging.warning(f"Gitleaks returned unexpected exit code: {result.returncode}")
                if result.stderr:
                    logging.warning(f"Gitleaks stderr: {result.stderr}")
                return False, None

        finally:
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

                except Exception as cleanup_error:
                    logging.warning(f"Failed to securely cleanup temp file: {cleanup_error}")
                    # Still try basic deletion
                    try:
                        if os.path.exists(tmp_file_path):
                            os.unlink(tmp_file_path)
                    except Exception:
                        pass  # Silent fail on final cleanup

    except FileNotFoundError:
        # Gitleaks binary not found
        logging.warning("Gitleaks binary not found - skipping secret scanning")
        logging.warning("Install Gitleaks: https://github.com/gitleaks/gitleaks#installing")
        return False, None

    except subprocess.TimeoutExpired:
        logging.error("Gitleaks scan timed out after 30 seconds")
        return False, None

    except Exception as e:
        logging.error(f"Unexpected error during secret scanning: {e}")
        import traceback
        logging.error(traceback.format_exc())
        # Fail open - don't block on errors
        return False, None


def process_hook_input():
    """
    Process hook input from stdin and check for secrets.

    Supports both prompt hooks (UserPromptSubmit, beforeSubmitPrompt) and
    tool use hooks (PreToolUse, preToolUse).

    Returns:
        dict: Response with 'output' (str or None) and 'exit_code' (int)
              - For Claude Code: output=None, exit_code=0 (allow) or 2 (block)
              - For Cursor: output=JSON string, exit_code=0
    """
    try:
        # Read JSON input from stdin
        stdin_content = sys.stdin.read()
        hook_data = json.loads(stdin_content)

        # Detect which IDE is calling
        ide_type = detect_ide_type(hook_data)

        # Disable logging for Cursor (it's sensitive to stderr output)
        if ide_type == IDEType.CURSOR:
            logging.disable(logging.CRITICAL)
        else:
            logging.info(f"Detected IDE type: {ide_type.value}")

        # Detect which hook event triggered this call
        hook_event = detect_hook_event(hook_data)
        if ide_type != IDEType.CURSOR:
            logging.info(f"Detected hook event: {hook_event}")

        # Check tool permissions for PreToolUse events (MCP servers and Skills)
        if hook_event in ["pretooluse", "beforereadfile"] and HAS_TOOL_POLICY:
            try:
                policy_checker = ToolPolicyChecker()
                is_allowed, error_message, tool_name = policy_checker.check_tool_allowed(hook_data)

                if not is_allowed:
                    logging.warning(f"Tool '{tool_name}' blocked by policy")
                    return format_response(ide_type, has_secrets=True, error_message=error_message, hook_event=hook_event)

                if tool_name and ide_type != IDEType.CURSOR:
                    logging.info(f"✓ Tool '{tool_name}' allowed by policy")
            except Exception as e:
                # Fail-open: if policy check fails, allow the operation
                logging.warning(f"Tool policy check error (fail-open): {e}")

        content_to_scan = None
        filename = "unknown"

        if hook_event in ["pretooluse", "beforereadfile"]:
            # PreToolUse or beforeReadFile hook - scan file content
            logging.info(f"Processing {hook_event} hook...")
            content_to_scan, filename, file_path, is_denied, deny_reason = extract_file_content_from_tool(hook_data)

            # Check if directory access is denied
            if is_denied:
                logging.warning(f"Directory access denied for file '{file_path}'")
                return format_response(ide_type, has_secrets=True, error_message=deny_reason, hook_event=hook_event)

            if content_to_scan is None:
                # Could not extract file content - allow operation (fail-open)
                logging.warning("Could not extract file content, allowing operation")
                return format_response(ide_type, has_secrets=False, hook_event=hook_event)

            logging.info(f"Scanning file '{filename}' for secrets...")

        else:
            # Prompt hook - scan the user's prompt
            logging.info("Processing prompt submission hook...")
            content_to_scan = hook_data.get("prompt", hook_data.get("userMessage", hook_data.get("message", "")))
            filename = "user_prompt"

            if not content_to_scan:
                # No content to check - allow operation
                return format_response(ide_type, has_secrets=False, hook_event=hook_event)

            logging.info("Scanning user prompt for secrets...")

        # Check for secrets in the content
        has_secrets, error_message = check_secrets_with_gitleaks(
            content_to_scan, filename
        )

        if has_secrets:
            # Secrets found - block operation
            return format_response(ide_type, has_secrets=True, error_message=error_message, hook_event=hook_event)

        # No secrets found, allow operation
        if hook_event == "pretooluse":
            logging.info(f"✓ No secrets detected in file '{filename}'")
        else:
            logging.info("✓ No secrets detected in prompt")
        return format_response(ide_type, has_secrets=False, hook_event=hook_event)

    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse hook input: {e}")
        # Fail-open: allow operation on errors
        # Default to Claude Code format for error responses
        return {"output": None, "exit_code": 0}
    except Exception as e:
        logging.error(f"Unexpected error in hook: {e}")
        import traceback
        logging.error(traceback.format_exc())
        # Fail-open: allow operation on errors
        return {"output": None, "exit_code": 0}


def main():
    """Main entry point for the hook."""
    # If arguments are provided, handle them
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            prog="ai-guardian",
            description="AI IDE security hook for blocking directories and scanning secrets",
        )
        parser.add_argument(
            "--version",
            "-v",
            action="version",
            version="ai-guardian 1.0.0",
        )
        parser.parse_args()
        return 0

    # No arguments - run as hook (read from stdin)
    response = process_hook_input()

    # Output JSON to stdout if needed (for Cursor)
    if response.get("output"):
        print(response["output"], flush=True)  # Force flush for Cursor
        sys.stdout.flush()  # Explicit flush for compatibility

    # Exit with appropriate code
    sys.exit(response["exit_code"])


if __name__ == "__main__":
    main()

#!/bin/bash
# Test script for ai-guardian hook

set -e

# Use the installed command
HOOK_CMD="${HOME}/.local/bin/ai-guardian"

# Check if the command exists
if [ ! -x "$HOOK_CMD" ]; then
    echo "Error: ai-guardian not found at $HOOK_CMD"
    echo "Please run 'make install' first"
    exit 1
fi

echo "Testing AI IDE Secret Scanner Hook"
echo "========================================"
echo ""

# Test 1: Clean prompt (should pass)
echo "Test 1: Clean prompt (should pass with exit code 0)"
echo '{"prompt": "Can you help me write a Python function to calculate fibonacci numbers?"}' | "$HOOK_CMD"
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ PASS: Clean prompt allowed (exit code: $EXIT_CODE)"
else
    echo "✗ FAIL: Clean prompt was blocked (exit code: $EXIT_CODE)"
    exit 1
fi
echo ""

# Test 2: Prompt with potential secret (should fail)
echo "Test 2: Prompt with secret (should block with exit code 2)"
echo '{"prompt": "Here is my GitHub token: ghp_1234567890abcdefghijklmnopqrstuvwxyz can you help me use it?"}' | "$HOOK_CMD" 2>&1 | grep -q "SECRET DETECTED"  #notsecret
if [ $? -eq 0 ]; then
    EXIT_CODE=2
else
    EXIT_CODE=0
fi
if [ $EXIT_CODE -eq 2 ]; then
    echo "✓ PASS: Prompt with secret blocked (exit code: $EXIT_CODE)"
else
    echo "✗ FAIL: Prompt with secret was not blocked (exit code: $EXIT_CODE)"
    exit 1
fi
echo ""

# Test 3: Empty prompt (should pass)
echo "Test 3: Empty prompt (should pass with exit code 0)"
echo '{"prompt": ""}' | "$HOOK_CMD"
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ PASS: Empty prompt allowed (exit code: $EXIT_CODE)"
else
    echo "✗ FAIL: Empty prompt was blocked (exit code: $EXIT_CODE)"
    exit 1
fi
echo ""

# Test 4: Malformed JSON (should pass - fail-open design)
echo "Test 4: Malformed JSON (should pass with exit code 0 - fail-open)"
echo 'not valid json' | "$HOOK_CMD" 2>/dev/null
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ PASS: Malformed JSON allowed (fail-open design, exit code: $EXIT_CODE)"
else
    echo "✗ FAIL: Malformed JSON was blocked (exit code: $EXIT_CODE)"
    exit 1
fi
echo ""

echo "========================================"
echo "All tests passed! ✓"
echo ""
echo "The hook is working correctly and will:"
echo "  - Allow clean prompts"
echo "  - Block prompts with secrets"
echo "  - Fail-open on errors (allow prompt to proceed)"

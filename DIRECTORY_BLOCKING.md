# Directory Blocking with .ai-read-deny

## Overview

In addition to blocking files that contain secrets, ai-guardian now supports blocking AI access to entire directories using a `.ai-read-deny` marker file.

## How It Works

When the AI attempts to read a file, ai-guardian checks if the file is located in a directory (or any parent directory) that contains a `.ai-read-deny` marker file. If found, access to the file is blocked.

### Directory Tree Walk

The check walks up the directory tree from the file's location to the root, looking for `.ai-read-deny` in each parent directory. This means:

- A `.ai-read-deny` file blocks access to all files in that directory
- It also blocks access to all files in subdirectories (recursively)
- Multiple levels of nesting are supported

## Usage

### Blocking a Directory

To block AI access to a directory and all its subdirectories:

```bash
# Navigate to the directory you want to protect
cd /path/to/sensitive/directory

# Create the marker file
touch .ai-read-deny
```

### Example Directory Structure

```
my-project/
├── public/
│   ├── index.html          # ✓ Accessible
│   └── script.js           # ✓ Accessible
├── secrets/
│   ├── .ai-read-deny       # 🚫 Marker file
│   ├── api_keys.txt        # 🚫 Blocked
│   ├── credentials.json    # 🚫 Blocked
│   └── internal/
│       ├── passwords.txt   # 🚫 Blocked (recursive)
│       └── tokens.env      # 🚫 Blocked (recursive)
└── src/
    ├── app.py              # ✓ Accessible
    └── utils.py            # ✓ Accessible
```

### What Gets Blocked

When AI tries to read a file in a blocked directory:

1. The file content is NOT sent to the AI
2. A clear error message is shown to the user
3. The error message indicates which directory contains the `.ai-read-deny` marker

### Error Message Example

```
======================================================================
🚫 ACCESS DENIED - Directory Protected
======================================================================

The file '/path/to/secrets/api_keys.txt' is located in a directory that contains
a .ai-read-deny marker file.

Protected directory: /path/to/secrets

This directory and all its subdirectories are blocked from AI access.
Please remove the .ai-read-deny file if you need AI access to this
directory, or move the file to an accessible location.

======================================================================
```

## Use Cases

### 1. Protecting Credential Directories

```bash
# Block access to all credential files
cd ~/.aws
touch .ai-read-deny

cd ~/.ssh
touch .ai-read-deny

cd ~/my-project/config/secrets
touch .ai-read-deny
```

### 2. Protecting Proprietary Code

```bash
# Block access to proprietary algorithms
cd ~/my-project/proprietary
touch .ai-read-deny
```

### 3. Protecting Customer Data

```bash
# Block access to customer data directories
cd ~/my-project/data/customers
touch .ai-read-deny
```

### 4. Protecting Third-Party Dependencies

```bash
# Block access to node_modules or vendor directories
cd ~/my-project/node_modules
touch .ai-read-deny

cd ~/my-project/vendor
touch .ai-read-deny
```

## Removing Protection

To remove directory protection:

```bash
# Navigate to the protected directory
cd /path/to/protected/directory

# Remove the marker file
rm .ai-read-deny
```

## Testing

Run the test suite to verify directory blocking works correctly:

```bash
cd ai-guardian
python3 test_directory_blocking.py
```

Expected output:
```
Testing directory blocking feature...
======================================================================
✓ Test 1 PASSED: Allowed file is accessible
✓ Test 2 PASSED: File in denied directory is blocked
✓ Test 3 PASSED: Nested file in denied directory is blocked
======================================================================
✅ All tests PASSED!
```

## Implementation Details

### Function: `check_directory_denied(file_path)`

**Location:** `ai-guardian/src/ai_guardian/__init__.py`

**Purpose:** Check if a file is in a directory (or subdirectory) that contains a `.ai-read-deny` marker file.

**Algorithm:**
1. Convert file path to absolute path
2. Get the directory containing the file
3. Walk up the directory tree to the root
4. At each level, check if `.ai-read-deny` exists
5. Return `(True, directory_path)` if found, `(False, None)` otherwise

**Fail-Safe Design:** If the check encounters an error, it fails open (allows access) to prevent breaking normal workflows.

### Integration Points

The directory blocking check is integrated into the file reading hooks:

1. **PreToolUse Hook** (Claude Code)
2. **beforeReadFile Hook** (Cursor)

The check happens BEFORE:
- Reading the file content
- Scanning for secrets

This ensures maximum protection with minimal performance impact.

## Comparison with Secret Scanning

| Feature | Secret Scanning | Directory Blocking |
|---------|----------------|-------------------|
| **Trigger** | Content-based | Location-based |
| **Granularity** | Per-file | Per-directory (recursive) |
| **Detection** | Scans file content | Checks for marker file |
| **Use Case** | Prevent specific secrets | Protect entire directories |
| **Performance** | Slower (content scan) | Faster (file check only) |

Both features work together to provide comprehensive protection:
1. Directory blocking prevents reading files in protected directories
2. Secret scanning catches secrets that slip through in allowed files

## Best Practices

1. **Use `.gitignore` patterns** - Consider adding `.ai-read-deny` to your `.gitignore` if you don't want to commit these markers

2. **Document protected directories** - Keep a README or documentation noting which directories are protected and why

3. **Review periodically** - Regularly review which directories are protected to ensure the protection is still needed

4. **Combine with secret scanning** - Use both directory blocking and secret scanning for defense in depth

5. **Test after adding markers** - After adding `.ai-read-deny` files, test that AI access is properly blocked

## Troubleshooting

### AI can still access files after adding .ai-read-deny

1. Verify the marker file is in the correct directory:
   ```bash
   ls -la /path/to/directory/.ai-read-deny
   ```

2. Check that the file path is correct (use absolute paths)

3. Restart your AI IDE to ensure hooks are reloaded

### Need to temporarily allow access

Instead of deleting the marker file, you can:

1. Move the marker file temporarily:
   ```bash
   mv .ai-read-deny .ai-read-deny.disabled
   ```

2. Restore when done:
   ```bash
   mv .ai-read-deny.disabled .ai-read-deny
   ```

## Future Enhancements

Potential future improvements:

- Support for patterns in `.ai-read-deny` (allow/deny specific file types)
- Global configuration for protected directories
- Integration with `.gitignore` patterns
- Whitelisting specific files within denied directories

# Unicode-Based Attack Detection

AI Guardian detects Unicode-based attacks that bypass traditional pattern matching through invisible characters, visual deception, and character substitution.

## Overview

Unicode attacks exploit special characters to:
- **Hide malicious commands** using invisible characters
- **Reverse text visually** while keeping malicious code intact
- **Bypass allowlists** by substituting look-alike characters
- **Encode hidden data** in deprecated tag characters

These attacks are particularly effective against AI assistants and code analysis tools that rely on visual pattern matching.

## Attack Types Detected

### 1. Zero-Width Characters (Invisible Characters)

**What they are:** Unicode characters that are invisible to humans but visible to computers. They break pattern matching by inserting invisible separators into commands.

**Characters detected (9 types):**
- `U+200B` Zero-width space (​)
- `U+200C` Zero-width non-joiner (‌)
- `U+200D` Zero-width joiner (‍)
- `U+FEFF` Zero-width no-break space / BOM (﻿)
- `U+2060` Word joiner (⁠)
- `U+2061` Function application (⁡)
- `U+2062` Invisible times (⁢)
- `U+2063` Invisible separator (⁣)
- `U+2064` Invisible plus (⁤)

**Example Attack:**
```
# Visually looks like: curl http://safe-domain.com
# Actually contains: cur​l http://evil.com (zero-width space after 'cur')
```

**Why it's dangerous:**
- Breaks regex patterns: `curl` doesn't match `cur​l`
- Invisible to human reviewers
- Can hide entire commands or URLs
- Bypasses most security filters

**Detection:** AI Guardian scans for any occurrence of these characters and reports their Unicode code points and positions.

---

### 2. Bidirectional Override Characters (Text Reversal)

**What they are:** Unicode control characters that reverse the visual display order of text without changing the actual character sequence.

**Characters detected (2 types):**
- `U+202E` Right-to-left override (‮)
- `U+202D` Left-to-right override (‭)

**Example Attack:**
```python
# Visually appears as: access_token = "safe_value"
# Actually executed as: access_token = "eulav_liam_ot_dnes"
access_token = "‮send_to_mail_value‬" # notsecret
```

**Real-world scenario:**
```bash
# Looks like: echo "Installing dependencies..."
# Actually runs: echo "...seicnedneped gnitalsni"‮
echo "‮Installing dependencies..."
```

**Why it's dangerous:**
- Visual deception - code looks safe but executes maliciously
- Hard to detect in code reviews
- Can hide sensitive data exfiltration
- Bypasses visual inspection

**Detection:** AI Guardian flags any occurrence of bidi override characters and shows both visual and actual character order.

---

### 3. Tag Characters (Hidden Data Encoding)

**What they are:** Deprecated Unicode tag characters (U+E0000 - U+E007F) originally designed for language tagging. Now used to encode hidden data.

**Why they're dangerous:**
- Invisible to most text editors
- Can encode entire hidden messages
- Deprecated but still supported
- Used for steganography attacks

**Example Attack:**
```
# Looks like: print("Hello World")
# Contains hidden tag characters encoding: "EXFIL_KEY=abc123"
```

**Detection:** AI Guardian scans the entire Unicode tag character range and reports any occurrences.

---

### 4. Homoglyphs (Look-Alike Characters)

**What they are:** Characters from different alphabets (Cyrillic, Greek, Mathematical, Cherokee, Coptic) that look identical to Latin characters but have different Unicode code points.

**80+ homoglyph pairs detected** including:

#### Cyrillic → Latin (Most Common)
| Cyrillic | Latin | Unicode Points |
|----------|-------|----------------|
| а | a | U+0430 → U+0061 |
| е | e | U+0435 → U+0065 |
| о | o | U+043E → U+006F |
| р | p | U+0440 → U+0070 |
| с | c | U+0441 → U+0063 |
| х | x | U+0445 → U+0078 |

#### Greek → Latin
| Greek | Latin | Unicode Points |
|-------|-------|----------------|
| α | a | U+03B1 → U+0061 |
| ε | e | U+03B5 → U+0065 |
| ο | o | U+03BF → U+006F |
| ν | v | U+03BD → U+0076 |
| ρ | p | U+03C1 → U+0070 |

#### Mathematical Alphanumeric → Latin
| Mathematical | Latin | Usage |
|-------------|-------|-------|
| 𝐚 | a | Bold mathematical |
| 𝐛 | b | Bold mathematical |
| 𝐜 | c | Bold mathematical |

#### Fullwidth Latin → ASCII
| Fullwidth | ASCII | Usage |
|-----------|-------|-------|
| Ａ | A | East Asian text |
| ａ | a | East Asian text |

#### Cherokee/Coptic → Latin
| Cherokee/Coptic | Latin | Notes |
|----------------|-------|-------|
| Ꭺ | A | Cherokee script |
| Ⲟ | O | Coptic script |

**Example Attacks:**

1. **Domain Spoofing:**
```python
# Looks like: https://google.com
# Actually: https://gооgle.com (Cyrillic 'о' instead of Latin 'o')
url = "https://gооgle.com"
```

2. **Function Name Bypass:**
```python
# Looks like: def execute_command():
# Actually: def ехecute_command(): (Cyrillic 'е' and 'х')
def ехecute_command():
    os.system("malicious")
```

3. **Variable Substitution:**
```python
# Looks like: API_KEY = "safe"
# Actually: АPI_KEY = "malicious" (Cyrillic 'А')
АPI_KEY = "exfiltrate_to_attacker"
```

**Why it's dangerous:**
- Bypasses allowlists and security filters
- Visual indistinguishable from legitimate code
- Can spoof trusted domains and function names
- Hard to detect without specialized tools
- Effective against human reviewers

**Detection:** AI Guardian:
1. Scans for 80+ homoglyph character pairs
2. Reports the homoglyph character, its Latin equivalent, and Unicode code points
3. Shows the visual appearance vs. actual encoding
4. Flags mixed-script usage (e.g., Latin + Cyrillic in same identifier)

---

## Configuration

Unicode attack detection is enabled by default and configured under `prompt_injection.unicode_detection` in your config file.

### Basic Configuration

```json
{
  "prompt_injection": {
    "unicode_detection": {
      "enabled": true,
      "action": "warn",
      "detect_zero_width": true,
      "detect_bidi_override": true,
      "detect_tag_chars": true,
      "detect_homoglyphs": true,
      "strict_mode": false
    }
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable Unicode attack detection |
| `action` | string | `"warn"` | Action to take: `"block"`, `"warn"`, or `"log-only"` |
| `detect_zero_width` | boolean | `true` | Detect zero-width invisible characters |
| `detect_bidi_override` | boolean | `true` | Detect bidirectional override characters |
| `detect_tag_chars` | boolean | `true` | Detect Unicode tag characters |
| `detect_homoglyphs` | boolean | `true` | Detect look-alike character substitution |
| `strict_mode` | boolean | `false` | Strict mode: fail on ANY Unicode anomaly |

### Action Modes

**Block Mode** (`"block"`):
- **Blocks execution** when Unicode attacks are detected
- Use for production environments with high security requirements
- Prevents potentially malicious code from running

**Warn Mode** (`"warn"`, default):
- **Displays warning** but allows execution
- Use for development environments
- Shows detection details without blocking work

**Log-only Mode** (`"log-only"`):
- **Logs detection** silently without user notification
- Use for monitoring and analysis
- Minimal disruption to workflow

### Strict Mode

When `strict_mode: true`:
- **Any Unicode anomaly triggers detection** (not just known attack patterns)
- Detects unusual character combinations
- Higher false positive rate but maximum security
- Recommended for sensitive environments

Example:
```json
{
  "prompt_injection": {
    "unicode_detection": {
      "enabled": true,
      "action": "block",
      "strict_mode": true
    }
  }
}
```

---

## Detection Examples

### Zero-Width Character Detection

**Input:**
```
cur​l http://metadata.google.internal
```

**Detection Output:**
```
⚠️  Unicode Attack Detected: Zero-width characters found

Detected Characters:
  • U+200B (Zero-width space) at position 3

Visual: curl http://metadata.google.internal
Actual: cur​l http://metadata.google.internal
        ^
        Hidden zero-width space
```

---

### Bidirectional Override Detection

**Input:**
```python
password = "‮toor"
```

**Detection Output:**
```
⚠️  Unicode Attack Detected: Bidirectional override characters found

Detected Characters:
  • U+202E (Right-to-left override) at position 12

Visual Display: password = "root"
Actual Value:   password = "‮toor"

WARNING: Visual display is reversed!
```

---

### Homoglyph Detection

**Input:**
```python
def ехecute_command():
    pass
```

**Detection Output:**
```
⚠️  Unicode Attack Detected: Homoglyph characters found

Detected Homoglyphs:
  • Position 4: 'е' (U+0435 Cyrillic) looks like 'e' (U+0065 Latin)
  • Position 5: 'х' (U+0445 Cyrillic) looks like 'x' (U+0078 Latin)

Visual:  execute_command
Actual:  ехecute_command
         ^^
         Cyrillic characters

This could be used to:
  • Bypass function name allowlists
  • Spoof trusted function names
  • Hide malicious code in plain sight
```

---

## Attack Scenarios

### Scenario 1: Metadata Endpoint Bypass

**Attack:**
```bash
# Attacker inserts zero-width space to bypass SSRF filters
cur​l http://169.254.169.254/latest/meta-data/
```

**How it works:**
- SSRF filter looks for `curl` command
- Zero-width space breaks the pattern: `cur​l` ≠ `curl`
- Filter doesn't match, attack succeeds

**AI Guardian Detection:**
```
🚨 BLOCKED: Zero-width character detected at position 3
Pattern: cur​l → curl (with hidden U+200B)
Threat: SSRF bypass via invisible character injection
```

---

### Scenario 2: Visual Deception in Code Review

**Attack:**
```python
# Visually appears to assign safe value
api_key = "‮yek_tnegilam_ot_dnes"
```

**How it works:**
- Right-to-left override reverses visual display
- Developer sees: `api_key = "send_to_malignant_key"`
- Code actually assigns: `api_key = "‮yek_tnegilam_ot_dnes"`
- Passes code review but executes malicious value

**AI Guardian Detection:**
```
🚨 BLOCKED: Bidirectional override detected
Visual: "send_to_malignant_key"
Actual: "‮yek_tnegilam_ot_dnes"
WARNING: Text direction is reversed!
```

---

### Scenario 3: Allowlist Bypass via Homoglyphs

**Attack:**
```python
# Allowlist permits: google.com, github.com
# Attacker uses Cyrillic 'о' instead of Latin 'o'
url = "https://gооgle.com"  # Actually: g[o-cyrillic][o-cyrillic]gle.com
```

**How it works:**
- Security allowlist checks for exact string `google.com`
- Attacker uses `gооgle.com` (Cyrillic о = U+043E)
- String comparison fails: `gооgle.com` ≠ `google.com`
- Attacker redirects to malicious site that looks like Google

**AI Guardian Detection:**
```
🚨 BLOCKED: Homoglyph attack detected
Domain: gооgle.com
  • Position 2: 'о' (U+043E Cyrillic) → 'o' (U+006F Latin)
  • Position 3: 'о' (U+043E Cyrillic) → 'o' (U+006F Latin)

This domain LOOKS like google.com but is actually different!
Potential phishing or allowlist bypass attack.
```

---

## Integration with Other Protections

Unicode attack detection works in conjunction with other AI Guardian protections:

### + SSRF Protection
```
Zero-width chars bypass SSRF filters → Unicode detection catches them
```

### + Prompt Injection Detection
```
Homoglyphs bypass jailbreak filters → Unicode detection flags substitution
```

### + Secret Redaction
```
Bidi override hides exfiltration URLs → Unicode detection reveals them
```

---

## Performance Impact

Unicode attack detection is **highly optimized**:

- **Zero-width detection:** O(n) single pass, ~0.1ms per 1000 chars
- **Bidi override:** O(n) single pass, ~0.1ms per 1000 chars
- **Tag characters:** O(n) single pass, ~0.1ms per 1000 chars
- **Homoglyph detection:** O(n) hash table lookup, ~0.3ms per 1000 chars

**Total overhead:** <1ms for typical prompts (< 5000 characters)

---

## False Positives

### Legitimate Use Cases

Some legitimate text contains Unicode characters that may trigger detection:

1. **International Text:**
   - Cyrillic/Greek names in comments
   - Mathematical formulas with Greek letters
   - East Asian fullwidth characters

2. **Formatted Text:**
   - Bidirectional text (Arabic, Hebrew)
   - Right-to-left languages in strings

3. **Special Formatting:**
   - Zero-width joiners in Indic scripts
   - Emoji sequences with zero-width joiners

### Reducing False Positives

**Use `action: "warn"` instead of `"block"`:**
```json
{
  "unicode_detection": {
    "action": "warn"
  }
}
```

**Disable specific detectors:**
```json
{
  "unicode_detection": {
    "detect_homoglyphs": true,
    "detect_zero_width": true,
    "detect_bidi_override": false  // Allow RTL text
  }
}
```

**Context-aware detection:**
AI Guardian automatically reduces false positives by:
- Checking for RTL script context before flagging bidi chars
- Allowing zero-width joiners in Indic/Arabic text
- Distinguishing intentional Greek math symbols from homoglyph attacks

---

## Best Practices

### For Developers

1. **Enable in development:** Catch attacks early in code review
2. **Use warn mode:** Don't block legitimate international text
3. **Review detections:** Investigate all Unicode warnings
4. **Educate team:** Make sure team understands Unicode risks

### For Security Teams

1. **Enable in production:** Block mode for critical systems
2. **Monitor logs:** Track Unicode attack attempts
3. **Combine with allowlists:** Don't rely on Unicode detection alone
4. **Regular updates:** Keep homoglyph database current

### For Code Reviewers

1. **Check Unicode warnings:** Don't ignore them
2. **Verify character encoding:** Use tools to inspect actual bytes
3. **Test both visual and encoded:** Copy-paste tests may miss attacks
4. **Question unusual scripts:** Why is there Cyrillic in English code?

---

## Research Background

Unicode attack detection in AI Guardian is based on:

- **Hermes Security Patterns** - Real-world attack patterns from security research
- **Tirith CLI** - 80+ homoglyph pairs from production security tools
- **Unicode Security Considerations** (TR #36) - Official Unicode consortium guidance
- **OWASP** - Unicode security best practices

---

## Technical Details

### Character Detection Algorithm

```
1. Scan input text character by character
2. For each character:
   a. Check if code point in zero-width range
   b. Check if code point is bidi override
   c. Check if code point in tag char range (U+E0000 - U+E007F)
   d. Check if character in homoglyph mapping table
3. Record position, Unicode code point, and type
4. Return all detections with context
```

### Homoglyph Detection Algorithm

```
1. Build hash table of 80+ homoglyph pairs
2. For each character in input:
   a. Check if character in homoglyph table
   b. If found, record Latin equivalent and position
3. Detect mixed-script usage (Latin + Cyrillic in same word)
4. Return all homoglyph substitutions
```

---

## See Also

- [SSRF Protection](SSRF_PROTECTION.md) - Network-based attack prevention
- [Secret Redaction](SECRET_REDACTION.md) - Credential protection
- [Credential Exfiltration](CREDENTIAL_EXFILTRATION.md) - Config file scanning
- [Configuration Guide](../CONFIGURATION.md) - Full configuration reference

---

## Version History

- **v1.4.0** - Initial Unicode attack detection (zero-width, bidi, homoglyphs)
- **v1.5.0** - Added tag character detection and strict mode
- **v1.6.0** - Enhanced homoglyph database (80+ pairs), context-aware detection

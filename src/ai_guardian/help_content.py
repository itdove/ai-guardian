"""Centralized help content for all AI Guardian scanner pages.

Used by both the TUI HelpModal and the web console help panel.
"""

_GITHUB_DOCS = "https://github.com/itdove/ai-guardian/blob/main/docs"

SCANNER_HELP = {
    "secret_scanning": {
        "title": "Secret Scanning",
        "summary": (
            "Scans AI tool inputs and outputs for leaked API keys, tokens, passwords, "
            "and other credentials using pattern-based scanner engines (Gitleaks, BetterLeaks, LeakTK)."
        ),
        "catches": [
            "AWS access keys (AKIA…)",
            "GitHub personal access tokens (ghp_…)",
            "OpenAI API keys (sk-…)",
            "Stripe, Twilio, SendGrid, Slack tokens",
            "Private keys (RSA, EC, PGP)",
            "High-entropy strings matching known key formats",
        ],
        "does_not_catch": [
            "Low-entropy canary tokens — use Canary Detection instead",
            "Secrets in image content — use Image Scanning",
            "Secrets already redacted by Secret Redaction",
        ],
        "config_summary": (
            "secret_scanning.enabled — toggle on/off\n"
            "secret_scanning.action — block | warn | log-only | ask\n"
            "secret_scanning.allowlist_patterns — regex allowlist for false positives"
        ),
        "doc_url": f"{_GITHUB_DOCS}/security/SECRET_SCANNING.md",
    },
    "scan_pii": {
        "title": "PII Detection",
        "summary": (
            "Detects personally identifiable information in prompts, file reads, "
            "and tool outputs to assist GDPR/CCPA compliance."
        ),
        "catches": [
            "US Social Security Numbers (XXX-XX-XXXX)",
            "Credit card numbers (Visa, Mastercard, Amex, Discover)",
            "US and international phone numbers",
            "Email addresses",
            "US passport numbers",
            "IBANs (International Bank Account Numbers)",
        ],
        "does_not_catch": [
            "Non-US national IDs (use custom patterns for jurisdiction-specific IDs)",
            "Names and addresses (no NLP — pattern-based only)",
            "PII embedded inside binary or image files",
        ],
        "config_summary": (
            "scan_pii.enabled — toggle on/off\n"
            "scan_pii.action — block | redact | warn | log-only\n"
            "scan_pii.pii_types — list of types to detect (ssn, credit_card, email, …)\n"
            "scan_pii.ignore_files — glob patterns to skip"
        ),
        "doc_url": f"{_GITHUB_DOCS}/CONFIGURATION.md",
    },
    "prompt_injection": {
        "title": "Prompt Injection Detection",
        "summary": (
            "Detects jailbreak attempts, obfuscation, Unicode attacks, and injected "
            "instructions in user prompts and tool outputs. Protects against LLM01/LLM04 attacks."
        ),
        "catches": [
            "Role-play jailbreaks (DAN mode, 'pretend you have no restrictions')",
            "Constraint removal ('ignore your previous instructions')",
            "System prompt extraction attempts",
            "Unicode zero-width character smuggling",
            "BiDi text direction manipulation",
            "Homoglyph substitution attacks",
        ],
        "does_not_catch": [
            "Injections in file binary content (only text is scanned)",
            "Injections requiring semantic understanding (heuristic mode limitation)",
        ],
        "config_summary": (
            "prompt_injection.enabled — toggle on/off\n"
            "prompt_injection.detector — heuristic | ml | hybrid\n"
            "prompt_injection.sensitivity — low | medium | high\n"
            "prompt_injection.action — block | warn | log-only | ask"
        ),
        "doc_url": f"{_GITHUB_DOCS}/security/PROMPT_INJECTION.md",
    },
    "ssrf_protection": {
        "title": "SSRF Protection",
        "summary": (
            "Blocks Server-Side Request Forgery attacks by preventing Bash commands "
            "and tool outputs from making requests to internal networks, cloud metadata "
            "endpoints, and sensitive IP ranges."
        ),
        "catches": [
            "Requests to private IP ranges (10.x, 172.16-31.x, 192.168.x)",
            "Localhost and loopback addresses (127.x, ::1)",
            "Cloud metadata endpoints (169.254.169.254 — AWS/GCP/Azure IMDS)",
            "Internal DNS names (.internal, .local, .corp)",
            "Dangerous URL schemes (file://, gopher://, dict://)",
        ],
        "does_not_catch": [
            "SSRF via DNS rebinding (IP checked at scan time, not resolution time)",
            "Requests in encrypted payloads",
            "SSRF in non-Bash tools (only Bash commands are checked by default)",
        ],
        "config_summary": (
            "ssrf_protection.enabled — toggle on/off\n"
            "ssrf_protection.action — block | warn | log-only\n"
            "ssrf_protection.allowed_domains — regex allowlist for trusted internal hosts"
        ),
        "doc_url": f"{_GITHUB_DOCS}/CONFIGURATION.md",
    },
    "context_poisoning": {
        "title": "Context Poisoning Detection",
        "summary": (
            "Detects attempts to inject persistent malicious instructions into conversation "
            "context (LLM03). Looks for phrases that try to permanently alter the AI's behavior."
        ),
        "catches": [
            "Persistent instruction injection ('from now on, always…')",
            "System prompt hijacking attempts",
            "Persistent + dangerous action combos (exfil, ignore rules)",
        ],
        "does_not_catch": [
            "Single-turn jailbreaks — use Prompt Injection Detection for those",
            "Context poisoning in binary file content",
        ],
        "config_summary": (
            "context_poisoning.enabled — toggle on/off\n"
            "context_poisoning.sensitivity — low | medium | high\n"
            "context_poisoning.action — block | warn | log-only"
        ),
        "doc_url": f"{_GITHUB_DOCS}/security/CONTEXT_POISONING.md",
    },
    "supply_chain": {
        "title": "Supply Chain Scanning",
        "summary": (
            "Detects malicious patterns in agent hook configurations, MCP server "
            "command definitions, and plugin/extension files."
        ),
        "catches": [
            "Hook commands that make network requests on trigger",
            "MCP server configs that auto-install packages (npx -y)",
            "Plugin files that access system credentials",
            "Unpinned or suspicious package references in agent configs",
        ],
        "does_not_catch": [
            "Runtime behavior of installed packages — only static config scanning",
            "Malicious packages uploaded to npm/PyPI (use dependency scanning for that)",
        ],
        "config_summary": (
            "supply_chain.enabled — toggle on/off\n"
            "supply_chain.action — block | warn | log-only\n"
            "supply_chain.allowlist_paths — paths to skip"
        ),
        "doc_url": None,
    },
    "config_file_scanning": {
        "title": "Config File Scanner",
        "summary": (
            "Detects attempts to read or exfiltrate sensitive configuration files "
            "via AI tool outputs. Catches when CLAUDE.md, .env, SSH keys, etc. "
            "appear in file reads or network requests."
        ),
        "catches": [
            "CLAUDE.md, .cursorrules, .github/copilot-* agent instructions",
            ".env, .env.local, .env.production credential files",
            "SSH private keys (~/.ssh/id_rsa, id_ed25519, etc.)",
            "Cloud credentials (~/.aws/credentials, ~/.config/gcloud/)",
            "Database connection strings and API key files",
        ],
        "does_not_catch": [
            "Config file access that doesn't match the protected patterns",
            "Config files in explicitly allowed paths (add to ignore_files)",
        ],
        "config_summary": (
            "config_file_scanning.enabled — toggle on/off\n"
            "config_file_scanning.action — block | warn | log-only\n"
            "config_file_scanning.additional_protected_files — extra files to protect\n"
            "config_file_scanning.ignore_files — glob patterns to skip"
        ),
        "doc_url": f"{_GITHUB_DOCS}/CONFIGURATION.md",
    },
    "code_scanning": {
        "title": "Code Security Scanning (Bandit)",
        "summary": (
            "Scans Python code written by the AI for common security vulnerabilities "
            "using Bandit: eval/exec usage, shell injection, weak crypto, SQL injection, "
            "hardcoded credentials, and more."
        ),
        "catches": [
            "eval() and exec() with user input (B307, B102)",
            "subprocess with shell=True (B602, B603)",
            "Weak crypto: MD5, SHA1 for passwords (B303, B324)",
            "SQL string formatting / injection risk (B608)",
            "assert statements in production code (B101)",
            "Hardcoded passwords and default key sizes (B105, B107)",
        ],
        "does_not_catch": [
            "Security issues in non-Python languages",
            "Logic errors and business logic flaws",
            "Runtime-only vulnerabilities (e.g., race conditions)",
        ],
        "config_summary": (
            "code_scanning.enabled — toggle on/off\n"
            "code_scanning.action — block | warn | log-only\n"
            "code_scanning.severity — LOW | MEDIUM | HIGH (minimum level to flag)\n"
            "code_scanning.confidence — LOW | MEDIUM | HIGH"
        ),
        "doc_url": None,
    },
    "offensive_language": {
        "title": "Offensive Language Scanner",
        "summary": (
            "Detects profanity, slurs, and non-inclusive terminology in code comments, "
            "variable names, and generated text. Disabled by default — context-dependent."
        ),
        "catches": [
            "Profanity — explicit swear words",
            "Slurs — racial, ethnic, gender, ableist slurs",
            "Non-inclusive language — master/slave, blacklist/whitelist, dummy (optional)",
        ],
        "does_not_catch": [
            "Context-aware usage (e.g., a legitimate use of 'master branch' if enabled)",
            "Offensive language in non-text file formats",
        ],
        "config_summary": (
            "scan_offensive.enabled — toggle on/off\n"
            "scan_offensive.categories — [profanity, slurs, inclusive_language]\n"
            "scan_offensive.action — block | warn | log-only\n"
            "scan_offensive.ignore_files — glob patterns to skip"
        ),
        "doc_url": None,
    },
    "canary_detection": {
        "title": "Canary Token Detection",
        "summary": (
            "Detects user-registered tripwire values in AI output. Plant a secret value "
            "in a sensitive file, register it here — if the AI ever outputs that value, "
            "data exfiltration is caught before it leaves."
        ),
        "catches": [
            "Any user-registered exact string (value=) — case-sensitive match",
            "Any user-registered regex pattern (pattern=) — e.g. CANARY_[A-Z0-9]{8}",
            "Low-entropy strings that secret scanners would miss",
        ],
        "does_not_catch": [
            "Tokens not registered in the config",
            "Encoded variants of canary values (base64, hex) unless registered as regex",
        ],
        "config_summary": (
            "canary_detection.enabled — toggle on/off (disabled by default)\n"
            "canary_detection.action — block | warn | log-only\n"
            "canary_detection.tokens — list of {value: '...'} or {pattern: '...'} entries"
        ),
        "doc_url": None,
    },
    "exfil_detection": {
        "title": "Exfiltration Behavior Detection",
        "summary": (
            "Detects bash command patterns that indicate credential theft: curl/wget "
            "uploading token variables, base64 encoding of secret files, SSH key "
            "piped to network tools, and cloud credential exfiltration."
        ),
        "catches": [
            "curl/wget with $TOKEN, $API_KEY, $SECRET env vars (credential_theft)",
            "env|nc, printenv|socat, $() subshell variable dumps (env_collection)",
            "cat ~/.ssh/id_rsa | curl ... (key_file_exfil)",
            "base64 ~/.aws/credentials (base64_encoding)",
            "curl 169.254.169.254/... — IMDS metadata theft (cloud_credential_exfil)",
            ".netrc, .npmrc, keychain extraction (secret_collection)",
        ],
        "does_not_catch": [
            "Exfiltration via non-bash tools (Python, Node.js scripts)",
            "Exfiltration using allowed patterns (add to allowlist_patterns)",
        ],
        "config_summary": (
            "exfil_detection.enabled — toggle on/off\n"
            "exfil_detection.action — block | warn | log-only\n"
            "exfil_detection.allowlist_patterns — regex patterns for legitimate commands"
        ),
        "doc_url": None,
    },
    "global_settings": {
        "title": "Global Settings",
        "summary": (
            "Master control panel for all AI Guardian security features. "
            "Toggle features on/off, set actions, and configure fail-open vs fail-closed behavior."
        ),
        "catches": [
            "All active scanners and their current status",
            "on_scan_error — what happens when a scanner itself crashes",
        ],
        "does_not_catch": [],
        "config_summary": (
            "on_scan_error:\n"
            "  allow (default) — fail-open: log warning, let operation through\n"
            "  block           — fail-closed: block operation if any scanner fails\n\n"
            "Security tradeoff:\n"
            "  'block' is safer but a scanner bug = blocked workflow.\n"
            "  Recommend: 'allow' for dev, 'block' for production/compliance environments.\n"
            "  Applies to ALL scanners: secret, PII, prompt injection, Bandit, canary, etc."
        ),
        "doc_url": f"{_GITHUB_DOCS}/CONFIGURATION.md",
    },
    "secret_redaction": {
        "title": "Secret Redaction",
        "summary": (
            "Automatically replaces detected secrets with placeholder values before "
            "they reach the AI model. Complements secret scanning — scanning blocks, "
            "redaction masks and allows through."
        ),
        "catches": [
            "All patterns matched by the configured secret scanner engines",
            "Redacts in tool output before the AI model sees the content",
        ],
        "does_not_catch": [
            "Secrets that the scanner engines don't detect",
            "Secrets in user prompts (redaction is PostToolUse only by default)",
        ],
        "config_summary": (
            "secret_redaction.enabled — toggle on/off\n"
            "secret_redaction.action — warn | log-only\n"
            "secret_redaction.preserve_format — mask with same character count\n"
            "secret_redaction.log_redactions — log each redaction for audit"
        ),
        "doc_url": f"{_GITHUB_DOCS}/security/SECRET_SCANNING.md",
    },
    "tool_permissions": {
        "title": "Tool Permissions",
        "summary": (
            "Controls which Claude Code tools, skills (slash commands), and MCP server "
            "tools are allowed or denied. Uses ordered allow/deny rules with glob matching."
        ),
        "catches": [
            "Unauthorized tool invocations not in any allow rule",
            "Explicitly denied tools in deny rules",
            "MCP server tool calls not in the allowlist",
        ],
        "does_not_catch": [
            "Tools allowed by a broader rule — be specific with deny rules",
        ],
        "config_summary": (
            "permissions.enabled — toggle enforcement on/off\n"
            "permissions.rules[] — ordered list of {pattern, action, scope} entries\n"
            "permissions.default_action — allow | deny (default: allow)"
        ),
        "doc_url": f"{_GITHUB_DOCS}/TOOL_POLICY.md",
    },
}

# Maps TUI panel IDs to doc URLs (only panels with dedicated docs)
PANEL_DOC_URLS: dict = {
    k: v["doc_url"]
    for k, v in {
        "panel-secrets": SCANNER_HELP["secret_scanning"],
        "panel-secret-redaction": SCANNER_HELP["secret_redaction"],
        "panel-scan-pii": SCANNER_HELP["scan_pii"],
        "panel-pi-detection": SCANNER_HELP["prompt_injection"],
        "panel-pi-jailbreak": SCANNER_HELP["prompt_injection"],
        "panel-pi-patterns": SCANNER_HELP["prompt_injection"],
        "panel-pi-unicode": SCANNER_HELP["prompt_injection"],
        "panel-ssrf": SCANNER_HELP["ssrf_protection"],
        "panel-context-poisoning": SCANNER_HELP["context_poisoning"],
        "panel-config-scanner": SCANNER_HELP["config_file_scanning"],
        "panel-global-settings": SCANNER_HELP["global_settings"],
        "panel-skills": SCANNER_HELP["tool_permissions"],
        "panel-mcp": SCANNER_HELP["tool_permissions"],
    }.items()
    if v["doc_url"]
}

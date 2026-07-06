---
name: Pattern Enhancement
about: Propose new detection patterns from security research (any scanner)
title: '[Pattern] '
labels: 'security, pattern-enhancement'
assignees: ''
---

## 📚 Source Information

**Source Name**: <!-- e.g., Hermes Security Patterns, OWASP LLM Top 10, Gitleaks community config, TruffleHog detectors, Research Paper -->

**Source URL**: <!-- Direct link to the research/pattern -->

**Date Accessed**: <!-- YYYY-MM-DD -->

**Source License**: <!-- e.g., MIT, Apache-2.0, Academic Fair Use, Public Domain -->
<!-- For GitHub repos: curl -s https://api.github.com/repos/OWNER/REPO | jq -r '.license.spdx_id' -->

**Scanner**: <!-- prompt_injection / context_poisoning / secrets / ssrf / config_scanner / other -->

**Pattern Category**: <!-- e.g., Jailbreak, Obfuscation, Unicode Attack, Credential Format, Metadata Endpoint, Config Path -->

---

## ✅ Evaluation Checklist

Before proposing this pattern, verify:

- [ ] **Applies to AI IDEs** - This pattern affects tools like Claude Code, not just LLM chat interfaces
- [ ] **Not Duplicate** - Checked existing patterns in the relevant scanner file — this is genuinely new
- [ ] **Low False Positives** - Detection regex/logic won't block legitimate code or documentation
- [ ] **Reproducible** - I can provide concrete examples that demonstrate the attack
- [ ] **License Compatible** - Source uses permissive open source license (MIT/Apache-2.0/BSD/CC0/ISC) or academic fair use applies
  - ✅ Acceptable: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, CC0-1.0, ISC, Unlicense, Public Domain, Academic Papers (cite properly)
  - ❌ Unacceptable: GPL-2.0, GPL-3.0, AGPL-3.0, proprietary, "All Rights Reserved", unclear licensing

---

## 🎯 Pattern Details

### Attack / Credential Pattern

<!-- Describe the attack technique or credential format in plain English -->

**Example Attack / Match String**:
```
<!-- Provide at least one concrete example of the malicious pattern or credential format -->


```

**Example Safe String** (should NOT trigger):
```
<!-- Provide at least one example of similar but legitimate content -->


```

### Detection Logic

**Proposed Regex** (if applicable):
```regex
<!-- e.g., r'(?i)(ignore|disregard).{0,20}(previous|above|prior).{0,20}(instructions?|rules?|prompts?)' -->
<!-- or for secrets: r'(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}' -->


```

**Alternative Detection Method** (if regex not suitable):
<!-- Describe alternative detection logic (e.g., Unicode normalization, entropy check, AST analysis) -->


**Rationale**:
<!-- Why this detection pattern works and why it has low false positives -->


### Test Cases

**Attack / Match Scenarios** (should be detected):
1. `<!-- Example 1 -->`
2. `<!-- Example 2 -->`
3. `<!-- Example 3 -->`

**Safe Scenarios** (should NOT be detected):
1. `<!-- Example 1 -->`
2. `<!-- Example 2 -->`
3. `<!-- Example 3 -->`

---

## 🔍 Research Context

**Why This Matters**:
<!-- Explain the security impact - what can an attacker achieve, or what credential is exposed? -->


**Real-World Examples** (if available):
<!-- Links to CVEs, incident reports, documented exploits, or credential leak incidents -->


**Related Patterns** (if any):
<!-- Link to related issues or existing patterns that this builds upon -->


---

## 💡 Implementation Recommendation

**Severity**: <!-- Low / Medium / High / Critical -->

**Suggested Implementation File**:
- [ ] `src/ai_guardian/prompt_injection.py` — add to `JAILBREAK_PATTERNS` / `OBFUSCATION_PATTERNS` / `UNICODE_ATTACK_PATTERNS` / new category
- [ ] `src/ai_guardian/context_poisoning.py` — detection patterns
- [ ] `src/ai_guardian/patterns/data/secrets.toml` — new secret rule
- [ ] `src/ai_guardian/ssrf_protector.py` — blocked IP ranges / domains / redirect paths
- [ ] `src/ai_guardian/config_scanner.py` — new config file path/pattern
- [ ] Requires new detector class (specify below)

**Additional Notes**:
<!-- Any implementation considerations, edge cases, or performance concerns -->


---

## 📋 Acceptance Criteria

- [ ] Pattern detection implemented in the correct scanner file
- [ ] Test cases added for attack/match scenarios (should detect)
- [ ] Test cases added for safe scenarios (should NOT detect)
- [ ] Documentation updated (CHANGELOG.md, scanner docs if new category)
- [ ] No regression in existing tests
- [ ] False positive rate verified (<1% on sample legitimate code/content)

---

**References**:
<!-- Add any additional links, papers, or resources -->

---
name: Pattern Enhancement
about: Propose new prompt injection detection patterns from security research
title: '[Pattern] '
labels: 'security, pattern-enhancement'
assignees: ''
---

## 📚 Source Information

**Source Name**: <!-- e.g., Hermes Security Patterns, OWASP LLM Top 10, Research Paper -->

**Source URL**: <!-- Direct link to the research/pattern -->

**Date Accessed**: <!-- YYYY-MM-DD -->

**Source License**: <!-- e.g., MIT, Apache-2.0, Academic Fair Use, Public Domain -->
<!-- For GitHub repos: curl -s https://api.github.com/repos/OWNER/REPO | jq -r '.license.spdx_id' -->

**Pattern Category**: <!-- e.g., Jailbreak, Obfuscation, Context Manipulation, Unicode Attack -->

---

## ✅ Evaluation Checklist

Before proposing this pattern, verify:

- [ ] **Applies to AI IDEs** - This pattern affects tools like Claude Code, not just LLM chat interfaces
- [ ] **Not Duplicate** - Checked existing patterns in `src/ai_guardian/prompt_injection.py` - this is genuinely new
- [ ] **Low False Positives** - Detection regex/logic won't block legitimate code or documentation
- [ ] **Reproducible** - I can provide concrete examples that demonstrate the attack
- [ ] **License Compatible** - Source uses permissive open source license (MIT/Apache-2.0/BSD/CC0/ISC) or academic fair use applies
  - ✅ Acceptable: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, CC0-1.0, ISC, Unlicense, Public Domain, Academic Papers (cite properly)
  - ❌ Unacceptable: GPL-2.0, GPL-3.0, AGPL-3.0, proprietary, "All Rights Reserved", unclear licensing

---

## 🎯 Pattern Details

### Attack Pattern

<!-- Describe the attack technique in plain English -->

**Example Attack String**:
```
<!-- Provide at least one concrete example of the malicious pattern -->


```

**Example Safe String** (should NOT trigger):
```
<!-- Provide at least one example of similar but legitimate content -->


```

### Detection Logic

**Proposed Regex** (if applicable):
```regex
<!-- e.g., r'(?i)(ignore|disregard).{0,20}(previous|above|prior).{0,20}(instructions?|rules?|prompts?)' -->


```

**Alternative Detection Method** (if regex not suitable):
<!-- Describe alternative detection logic (e.g., Unicode normalization, AST analysis, etc.) -->


**Rationale**:
<!-- Why this detection pattern works and why it has low false positives -->


### Test Cases

**Attack Scenarios** (should be detected):
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
<!-- Explain the security impact - what can an attacker achieve with this pattern? -->


**Real-World Examples** (if available):
<!-- Links to CVEs, incident reports, or documented exploits -->


**Related Patterns** (if any):
<!-- Link to related issues or existing patterns that this builds upon -->


---

## 💡 Implementation Recommendation

**Severity**: <!-- Low / Medium / High / Critical -->

**Suggested Implementation**:
- [ ] Add to `JAILBREAK_PATTERNS` in `prompt_injection.py`
- [ ] Add to `OBFUSCATION_PATTERNS` in `prompt_injection.py`
- [ ] Add to `UNICODE_ATTACK_PATTERNS` in `prompt_injection.py`
- [ ] Create new pattern category (specify below)
- [ ] Requires custom detector class (specify below)

**Additional Notes**:
<!-- Any implementation considerations, edge cases, or performance concerns -->


---

## 📋 Acceptance Criteria

- [ ] Pattern detection implemented in code
- [ ] Test cases added for attack scenarios (should detect)
- [ ] Test cases added for safe scenarios (should NOT detect)
- [ ] Documentation updated (if new category)
- [ ] No regression in existing tests
- [ ] False positive rate verified (<1% on sample legitimate code)

---

**References**:
<!-- Add any additional links, papers, or resources -->

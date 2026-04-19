# Multi-Engine Support GitHub Issue

## ✅ Issue Created

**Issue**: [#91 - Multi-Engine Support for Secret Scanning](https://github.com/itdove/ai-guardian/issues/91)  
**Created**: 2026-04-18  
**Status**: Open  
**Milestone**: v2.0.0  
**Labels**: enhancement

## Issue Details

## Issue Content Preview

The full issue content is in `docs/MULTI_ENGINE_SUPPORT.md`.

**Summary**: Add support for multiple secret scanning engines beyond Gitleaks (TruffleHog, detect-secrets, Secretlint, etc.)

**Key Points**:
- Currently hardcoded to Gitleaks only
- Add `secret_scanning.engines` configuration
- Implement abstract `SecretScanner` base class
- Support multiple execution strategies (first-match, all-engines, consensus)
- Maintain backward compatibility

**Timeline**: Planned for v2.0.0 across 3 phases

## Related Code Changes

The following files have been updated to reference this future feature:

- `src/ai_guardian/__init__.py` - TODO comments added at lines 1386 and 1516
- `src/ai_guardian/schemas/ai-guardian-config.schema.json` - Reserved `engines` field documented
- `CHANGELOG.md` - Reserved field documented in Unreleased section
- `README.md` - Note added in Requirements section

## After Creating Issue

1. Update TODO comments in code to include issue number:
   ```python
   # TODO: Multi-engine support (#XXX) - Currently hardcoded to Gitleaks only.
   ```

2. Update `docs/MULTI_ENGINE_SUPPORT.md` header with issue link:
   ```markdown
   # Multi-Engine Support for Secret Scanning (#XXX)
   ```

3. Reference issue in CHANGELOG:
   ```markdown
   - See `docs/MULTI_ENGINE_SUPPORT.md` for planned implementation (#XXX)
   ```

"""Shared utilities for hook event handlers."""

import ai_guardian.hook_processing as _hp


def _format_response(adapter, **kwargs):
    """Call adapter.format_response() with [ai-guardian] prefix on warning_message.

    Replaces the backward-compat wrapper in response_format.py for internal
    use, ensuring the correct adapter instance (from detect_adapter) is used
    instead of re-resolving via IDEType enum.
    """
    wm = kwargs.get("warning_message")
    if wm and not wm.lstrip().startswith("[ai-guardian]"):
        kwargs["warning_message"] = f"[ai-guardian] {wm}"
    return adapter.format_response(**kwargs)


# --- Shared _hp delegation wrappers ---
# Tests mock these functions on hook_processing; the _hp delegation ensures
# mocks propagate into hook_events modules. These wrappers were previously
# duplicated across content_pipeline.py, post_tool_use.py, and scanners.py.


def _load_secret_scanning_config():
    return _hp._load_secret_scanning_config()


def _load_pii_config():
    return _hp._load_pii_config()


def _get_on_scan_error_action():
    return _hp._get_on_scan_error_action()


def _extract_pii_matched_text(pii_redactions, content):
    return _hp._extract_pii_matched_text(pii_redactions, content)


def _pii_redactions_to_findings(pii_redactions, content, error_msg=""):
    return _hp._pii_redactions_to_findings(pii_redactions, content, error_msg)


def _extract_file_path_from_pii_warning(pii_warning):
    return _hp._extract_file_path_from_pii_warning(pii_warning)


def check_secrets_with_gitleaks(*args, **kwargs):
    return _hp.check_secrets_with_gitleaks(*args, **kwargs)

"""Shared utilities for hook event handlers."""


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


def _extract_pii_matched_text(pii_redactions, content):
    from ai_guardian.hook_processing import _extract_pii_matched_text as _fn

    return _fn(pii_redactions, content)


def _pii_redactions_to_findings(pii_redactions, content, error_msg=""):
    from ai_guardian.hook_processing import _pii_redactions_to_findings as _fn

    return _fn(pii_redactions, content, error_msg)


def _extract_file_path_from_pii_warning(pii_warning):
    from ai_guardian.hook_processing import _extract_file_path_from_pii_warning as _fn

    return _fn(pii_warning)

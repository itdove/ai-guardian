"""Client-side UTC → local-timezone display for timestamps."""

from nicegui import ui

# JavaScript that converts all elements with class 'utc-timestamp' to local
# time using the browser's Intl.DateTimeFormat API.  Called once after the
# page content is rendered (via ui.timer).
_CONVERT_JS = """
document.querySelectorAll('.utc-timestamp').forEach(el => {
    const utc = el.getAttribute('data-utc');
    if (!utc) return;
    try {
        const d = new Date(utc.endsWith('Z') ? utc : utc + 'Z');
        if (isNaN(d.getTime())) return;
        el.textContent = d.toLocaleString(undefined, {
            year:   'numeric',
            month:  '2-digit',
            day:    '2-digit',
            hour:   '2-digit',
            minute: '2-digit',
            second: '2-digit',
        });
    } catch (_) {}
});
"""


def local_time_label(utc_iso: str) -> ui.html:
    """Render a timestamp that the browser converts to local time.

    Server-side renders the truncated UTC string as a fallback;
    client-side JS replaces it with the locale-formatted local time.
    """
    fallback = utc_iso[:19] if utc_iso else ""
    return ui.html(
        f'<span class="utc-timestamp text-xs text-grey-6" '
        f'data-utc="{utc_iso}">{fallback}</span>'
    )


def inject_local_time_js() -> None:
    """Run the conversion script on the client.

    Call this **once** per page, after all violation cards have been
    rendered (e.g. at the end of load_violations).
    """
    ui.run_javascript(_CONVERT_JS)

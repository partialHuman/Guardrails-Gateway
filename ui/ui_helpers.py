"""
Pure helpers for the Streamlit UI (no Streamlit import, so they are unit-tested).

The UI holds the gateway API key and calls the gateway on behalf of whoever
opens the page. Anyone who can reach the UI port therefore gets authenticated
access to the gateway, so the UI must not show its form until the visitor has
been authorised (see ``evaluate_gate``).
"""

from __future__ import annotations

import secrets

GATE_OPEN = "open"                  # nothing to protect: show the form
GATE_LOGIN = "login"                # ask for the UI password first
GATE_LOCKED = "locked"              # key present but UI unprotected: refuse
GATE_OPEN_WARN = "open_warn"        # explicitly allowed anonymous: show a warning


def normalize_api_url(raw: str) -> tuple[str, str]:
    """Return ``(base_url, analyze_url)``.

    Accepts both ``http://api:8000`` and ``http://api:8000/analyze`` so a
    mis-set API_URL can never produce ``.../analyze/analyze``.
    """
    base = raw.strip().rstrip("/")

    if base.endswith("/analyze"):
        base = base[: -len("/analyze")]

    return base, f"{base}/analyze"


def evaluate_gate(api_key: str, ui_password: str, allow_anonymous: bool) -> str:
    """Decide how the UI may be used.

    * No gateway key configured -> the UI protects nothing: ``open``.
    * Key configured and a UI password set -> visitors must log in.
    * Key configured, no password, anonymous explicitly allowed -> ``open_warn``.
    * Key configured, no password, anonymous NOT allowed -> ``locked``
      (the safe default: the UI will not lend the key to strangers).
    """
    if not api_key:
        return GATE_OPEN

    if ui_password:
        return GATE_LOGIN

    if allow_anonymous:
        return GATE_OPEN_WARN

    return GATE_LOCKED


def password_matches(provided: str, expected: str) -> bool:
    """Constant-time password comparison that never raises on odd input."""
    if not provided or not expected:
        return False

    return secrets.compare_digest(
        provided.encode("utf-8", "surrogatepass"),
        expected.encode("utf-8", "surrogatepass"),
    )


def describe_http_error(status_code: int, retry_after: str | None = None) -> str:
    """Friendly message for a failed gateway call.

    Deliberately contains no URL, hostname, header or traceback, so an
    unauthenticated visitor learns nothing about the internal deployment.
    """
    if status_code == 401:
        return "Authentication failed (401). Check GUARDRAILS_API_KEY on the UI service."

    if status_code == 413:
        return "The request was too large (413). Shorten the prompt or documents."

    if status_code == 422:
        return "The gateway rejected the input (422). Check the field lengths and characters."

    if status_code == 429:
        wait = f" Try again in about {retry_after} seconds." if retry_after else ""
        return f"Too many requests (429).{wait}"

    if 500 <= status_code < 600:
        return f"The gateway reported a server error ({status_code})."

    return f"The gateway returned an unexpected status ({status_code})."


def format_reason_line(reason: dict) -> str:
    """One plain-text line for a detection reason.

    Rendered with ``st.text`` (NOT Markdown): the evidence contains text the
    user submitted, which must never be interpreted as links or images.
    """
    tag = reason.get("tag", "")
    rule = reason.get("rule", "")
    source = reason.get("source", "prompt")
    evidence = reason.get("evidence", "")

    return f"\u2022 {tag} ({rule} in {source}) \u2192 {evidence}"

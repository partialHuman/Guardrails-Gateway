"""
Logging configuration for SentraGuard Lite.

Only logs metadata (request_id, decision, risk score, rule ids, etc.)
Never logs prompts or document contents to avoid leaking
sensitive information.
"""

from __future__ import annotations

import logging
import sys


def sanitize_for_log(value: object, max_length: int = 200) -> str:
    """
    Render an attacker-controlled value (path, header, id) safely for a log line.

    Control characters (ESC, VT, FF, NEL, U+2028, ...) and all non-ASCII
    characters are escaped, so a request cannot inject terminal escape
    sequences or fake-looking log lines, and the value is truncated so it
    cannot flood the log.
    """

    text = ascii(str(value))[1:-1]

    if len(text) > max_length:
        text = text[:max_length] + "...[truncated]"

    return text


def configure_logger() -> logging.Logger:
    """
    Configure and return the application logger.

    Returns:
        Configured logger instance.
    """

    logger = logging.getLogger("sentraguard")

    # Prevent duplicate handlers during reload
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)

    logger.propagate = False

    return logger


logger = configure_logger()

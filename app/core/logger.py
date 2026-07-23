"""
Logging configuration for SentraGuard Lite.

Only logs metadata (request_id, decision, risk score, etc.)
Never logs prompts or document contents to avoid leaking
sensitive information.
"""

from __future__ import annotations

import logging
import sys


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
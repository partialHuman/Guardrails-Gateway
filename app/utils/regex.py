"""
Common regular expressions used across the project.
"""

EMAIL_REGEX = (
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

PHONE_REGEX = (
    r"\+?\d[\d\s\-]{8,14}\d"
)
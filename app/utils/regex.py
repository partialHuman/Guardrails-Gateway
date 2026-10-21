"""
Regular expressions shared across the project (PII candidates).

These only find *candidates*. app/core/detectors.py applies checksum /
sanity validation before anything is reported.
"""

# Emails are found by locating each "@" and expanding outwards (see
# detectors._find_emails). A single regex with an unbounded local part
# rescans every run of word characters from every start position, which
# is quadratic and lets a 50 000-character input stall a worker.
EMAIL_LOCAL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-"
)

EMAIL_LOCAL_MAX = 64  # RFC 5321 limit for the part before "@"

EMAIL_DOMAIN_REGEX = (
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

# 13-19 digits, optionally grouped with single spaces or dashes.
# Validated with Luhn + a card-issuer prefix check.
CARD_REGEX = (
    r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"
)

# 12 digits (first digit 2-9), optionally grouped 4-4-4.
# Validated with the Verhoeff checksum.
AADHAAR_REGEX = (
    r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"
)

# International: "+" followed by digits and common separators.
# The candidate is trimmed to at most 15 digits (E.164) afterwards.
PHONE_INTL_REGEX = (
    r"(?<![\w+])\+\d[\d\s().-]{6,24}\d"
)

# Indian mobile numbers (6-9 followed by 9 digits), optional +91 / 91 / 0
# prefix, optional "98765 43210" grouping.
PHONE_IN_REGEX = (
    r"(?<!\d)(?:(?:\+?91|091|0)[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"
)

# North-American style: separators are REQUIRED before the last group so
# bare 10-digit ids (orders, timestamps, ISBN fragments) do not match.
PHONE_NANP_REGEX = (
    r"(?<![\d-])\(?[2-9]\d{2}\)?[\s.-]?\d{3}[\s.-]\d{4}(?!\d)"
)

# Base64-looking tokens (standard or URL-safe alphabet).
BASE64_REGEX = (
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])"
)

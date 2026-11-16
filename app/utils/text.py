"""
Text normalisation helpers.

Detectors must not be fooled by cosmetic tricks such as zero-width
characters, non-breaking spaces, full-width letters, Cyrillic look-alikes
or "leetspeak". Three views of the same text are used:

* canonical  - NFKC-normalised, invisible format characters removed.
               This is the text that redaction is applied to.
* match view - canonical + look-alike letters folded to ASCII.
* leet view  - match view + digits/symbols folded to letters
               (only used for injection phrases, never for PII, because
               it would destroy digits).

Every fold below is strictly 1 character -> 1 character, so a match
position in a folded view is also the correct position in the canonical
text. That is what lets the sanitizer redact the right span.
"""

from __future__ import annotations

import unicodedata


class NormalizationLimitExceeded(ValueError):
    """Raised when normalized text length exceeds safe limits."""

    def __init__(self, length: int, limit: int) -> None:
        super().__init__(
            f"Normalized text length ({length}) exceeds safe limit ({limit})"
        )
        self.length = length
        self.limit = limit

# Look-alike letters that NFKC does not unify (Cyrillic / Greek -> Latin).
_CONFUSABLES = {
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ѕ": "S", "Ј": "J",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

_LEET = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s",
}
_LEET_TABLE = str.maketrans(_LEET)


def canonicalize(text: str, max_chars: int | None = None) -> str:
    """
    NFKC-normalise and strip invisible "format" characters (category Cf):
    zero-width spaces/joiners, soft hyphens, BOM, bidi controls and the
    Unicode "tag" block sometimes used to smuggle hidden instructions.
    NFKC also turns non-breaking and other exotic spaces into plain spaces.

    If `max_chars` is provided and the normalized text exceeds this limit,
    raises NormalizationLimitExceeded to protect downstream regexes and
    sanitizers from excessive CPU/memory consumption.
    """

    norm = unicodedata.normalize("NFKC", text)
    if max_chars is not None and len(norm) > max_chars:
        raise NormalizationLimitExceeded(len(norm), max_chars)

    return "".join(ch for ch in norm if unicodedata.category(ch) != "Cf")


def fold_confusables(canonical: str) -> str:
    """Fold common Cyrillic/Greek look-alikes to Latin (length preserving)."""

    return canonical.translate(_CONFUSABLE_TABLE)


def fold_leet(folded: str) -> str:
    """Fold leetspeak digits/symbols to letters (length preserving)."""

    return folded.translate(_LEET_TABLE)

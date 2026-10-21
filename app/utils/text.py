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


def canonicalize(text: str) -> str:
    """
    NFKC-normalise and strip invisible "format" characters (category Cf):
    zero-width spaces/joiners, soft hyphens, BOM, bidi controls and the
    Unicode "tag" block sometimes used to smuggle hidden instructions.
    NFKC also turns non-breaking and other exotic spaces into plain spaces.
    """

    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def fold_confusables(canonical: str) -> str:
    """Fold common Cyrillic/Greek look-alikes to Latin (length preserving)."""

    return canonical.translate(_CONFUSABLE_TABLE)


def fold_leet(folded: str) -> str:
    """Fold leetspeak digits/symbols to letters (length preserving)."""

    return folded.translate(_LEET_TABLE)

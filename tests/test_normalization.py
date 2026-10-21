import pytest

from app.utils.text import canonicalize, fold_confusables, fold_leet


def test_zero_width_characters_are_removed():
    assert canonicalize("Ign\u200bore") == "Ignore"


def test_tag_block_characters_are_removed():
    # Invisible "tag" characters can smuggle hidden text.
    assert canonicalize("hi\U000E0041\U000E0042") == "hi"


def test_non_breaking_space_becomes_space():
    assert canonicalize("a\u00a0b") == "a b"


def test_fullwidth_letters_are_normalised():
    assert canonicalize("\uff29gnore") == "Ignore"


@pytest.mark.parametrize("text", ["Ignore previous", "naïve café", "a\nb\tc"])
def test_plain_text_is_unchanged(text):
    assert canonicalize(text) == text


def test_confusable_fold_preserves_length():
    text = "Ignоre prеvious"  # Cyrillic o and e
    assert len(fold_confusables(text)) == len(text)
    assert fold_confusables(text) == "Ignore previous"


def test_leet_fold_preserves_length():
    text = "1gn0re $y$t3m"
    assert len(fold_leet(text)) == len(text)
    assert fold_leet(text) == "ignore system"

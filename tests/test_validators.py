import pytest

from app.utils.validators import (
    luhn_valid,
    verhoeff_check_digit,
    verhoeff_valid,
)


@pytest.mark.parametrize("number", [
    "4111 1111 1111 1111",
    "5500-0000-0000-0004",
    "378282246310005",
])
def test_luhn_valid(number):
    assert luhn_valid(number)


@pytest.mark.parametrize("number", [
    "4111 1111 1111 1112",
    "1234567890123",
    "123",
])
def test_luhn_invalid(number):
    assert not luhn_valid(number)


def test_verhoeff_reference_example():
    # Well-known reference: payload 236 has check digit 3.
    assert verhoeff_check_digit("236") == 3
    assert verhoeff_valid("2363")
    assert not verhoeff_valid("2364")


def test_verhoeff_round_trip():
    payload = "23456789012"
    assert verhoeff_valid(payload + str(verhoeff_check_digit(payload)))

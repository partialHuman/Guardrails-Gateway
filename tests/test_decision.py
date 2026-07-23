from app.core.analyzer import decide
from app.schemas import Decision


def test_allow():

    assert decide(0) == Decision.ALLOW


def test_transform():

    assert decide(50) == Decision.TRANSFORM


def test_block():

    assert decide(90) == Decision.BLOCK
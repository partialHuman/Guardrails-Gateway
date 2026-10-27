"""SG-010: middleware order is explicit, documented, and verified."""

from app import main

EXPECTED_OUTERMOST_FIRST = [
    "assign_request_id",
    "add_security_headers",
    "enforce_authentication",
    "enforce_rate_limit",
    "enforce_request_body_size",
]


def _names(middleware):
    return [entry.kwargs["dispatch"].__name__ for entry in middleware]


def test_declared_order():
    assert _names(main.MIDDLEWARE) == EXPECTED_OUTERMOST_FIRST


def test_application_installs_exactly_the_declared_order():
    # Starlette keeps user middleware outermost-first.
    assert _names(main.app.user_middleware) == EXPECTED_OUTERMOST_FIRST


def test_authentication_is_outside_the_rate_limiter():
    order = _names(main.app.user_middleware)

    assert order.index("enforce_authentication") < order.index("enforce_rate_limit")


def test_response_decorators_wrap_every_rejecting_layer():
    order = _names(main.app.user_middleware)

    for rejecting in (
        "enforce_authentication",
        "enforce_rate_limit",
        "enforce_request_body_size",
    ):
        assert order.index("assign_request_id") < order.index(rejecting)
        assert order.index("add_security_headers") < order.index(rejecting)

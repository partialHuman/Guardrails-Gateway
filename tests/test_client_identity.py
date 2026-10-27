"""SG-005: CIDR trusted proxies, IPv6 handling, hostile forwarded headers, bounded memory."""

import sys
from unittest.mock import MagicMock

import pytest

from app.core.rate_limiter import (
    OVERFLOW_CLIENT_ID,
    InMemoryRateLimiter,
    RedisRateLimiter,
    client_ip_from_request,
    create_rate_limiter,
    rate_limit_key,
)


def resolve(peer, xff, trusted):
    return client_ip_from_request(peer, xff, trusted_proxies=frozenset(trusted))


# --- trusted proxies: CIDR ---------------------------------------------------


def test_cidr_network_marks_every_member_as_trusted():
    # Docker/Kubernetes proxy addresses change on every restart, so they
    # must be configurable as a network.
    assert resolve("10.0.0.5", "203.0.113.9", {"10.0.0.0/24"}) == "203.0.113.9"
    assert resolve("10.0.0.200", "203.0.113.9", {"10.0.0.0/24"}) == "203.0.113.9"


def test_peer_outside_the_network_is_not_trusted():
    assert resolve("10.0.1.5", "203.0.113.9", {"10.0.0.0/24"}) == "10.0.1.5"


def test_ipv6_cidr_network():
    assert resolve("fd00::5", "2001:db8::1", {"fd00::/8"}) == "2001:db8::1"


def test_ipv4_and_ipv6_networks_never_match_each_other():
    assert resolve("::1", "203.0.113.9", {"0.0.0.0/0"}) == "::1"


def test_ipv4_mapped_ipv6_peer_matches_an_ipv4_network():
    assert resolve("::ffff:10.0.0.5", "203.0.113.9", {"10.0.0.0/24"}) == "203.0.113.9"


def test_cidr_entries_in_the_forwarded_chain_are_skipped():
    chain = "203.0.113.9, 10.0.0.7"

    assert resolve("10.0.0.5", chain, {"10.0.0.0/24"}) == "203.0.113.9"


def test_every_hop_trusted_falls_back_to_the_peer():
    assert resolve("10.0.0.5", "10.0.0.7, 10.0.0.8", {"10.0.0.0/24"}) == "10.0.0.5"


# --- forwarded header hygiene --------------------------------------------------


@pytest.mark.parametrize(
    "xff, expected",
    [
        ("203.0.113.9:5555", "203.0.113.9"),
        ("[2001:db8::7]:443", "2001:db8::7"),
        ("  203.0.113.9  ", "203.0.113.9"),
        ("::ffff:203.0.113.9", "203.0.113.9"),
    ],
)
def test_forwarded_addresses_are_normalised(xff, expected):
    assert resolve("10.0.0.1", xff, {"10.0.0.1"}) == expected


@pytest.mark.parametrize(
    "xff",
    [
        "203.0.113.9, not-an-ip",
        "203.0.113.9, <script>alert(1)</script>",
        "x" * 10_000,
        "999.1.1.1",
        "[unclosed",
    ],
)
def test_malformed_forwarded_header_is_ignored_and_never_becomes_an_identity(xff):
    # A trusted proxy always appends a valid address, so anything else means
    # the header was forged: use the TCP peer instead.
    assert resolve("10.0.0.1", xff, {"10.0.0.1"}) == "10.0.0.1"


def test_empty_list_elements_are_harmless_formatting():
    # An empty element is never an identity; it is simply skipped.
    assert resolve("10.0.0.1", "203.0.113.9, ", {"10.0.0.1"}) == "203.0.113.9"
    assert resolve("10.0.0.1", ",203.0.113.9,,", {"10.0.0.1"}) == "203.0.113.9"


def test_forwarded_header_is_ignored_without_trusted_proxies():
    assert resolve("198.51.100.4", "203.0.113.9", set()) == "198.51.100.4"


def test_untrusted_peer_cannot_spoof_the_forwarded_header():
    assert resolve("198.51.100.4", "203.0.113.9", {"10.0.0.1"}) == "198.51.100.4"


def test_missing_peer_uses_the_shared_unknown_bucket():
    assert client_ip_from_request(None, None) == "unknown"


# --- rate-limit keys -------------------------------------------------------------


def test_ipv4_key_is_the_address():
    assert rate_limit_key("203.0.113.9") == "203.0.113.9"
    assert rate_limit_key("203.0.113.9:8080") == "203.0.113.9"


def test_ipv6_addresses_in_one_slash_64_share_a_key():
    # One subscriber owns a whole /64; rotating addresses inside it must not
    # buy a fresh quota.
    first = rate_limit_key("2001:db8:1:2::1")
    second = rate_limit_key("2001:db8:1:2:ffff:ffff:ffff:ffff")

    assert first == second == "2001:db8:1:2::/64"


def test_different_slash_64_networks_get_different_keys():
    assert rate_limit_key("2001:db8:1:2::1") != rate_limit_key("2001:db8:1:3::1")


def test_ipv6_spellings_collapse_to_one_key():
    assert rate_limit_key("::1") == rate_limit_key("0:0:0:0:0:0:0:1")


def test_ipv4_mapped_ipv6_uses_the_ipv4_key():
    assert rate_limit_key("::ffff:203.0.113.9") == "203.0.113.9"


def test_non_ip_identities_pass_through_truncated():
    assert rate_limit_key("unknown") == "unknown"
    assert rate_limit_key("testclient") == "testclient"
    assert len(rate_limit_key("x" * 1000)) == 128


# --- bounded memory ---------------------------------------------------------------


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_client_table_is_bounded_with_a_shared_overflow_bucket():
    clock = FakeClock()
    limiter = InMemoryRateLimiter(1, 60, clock=clock, max_clients=3)

    for client_id in ("a", "b", "c"):
        assert limiter.allow(client_id) == (True, 0.0)

    # Table is full of live clients: newcomers share ONE overflow quota.
    assert limiter.allow("d") == (True, 0.0)
    assert limiter.allow("e")[0] is False
    assert limiter.allow("f")[0] is False

    assert len(limiter._requests) == 4  # a, b, c + the overflow bucket
    assert OVERFLOW_CLIENT_ID in limiter._requests


def test_memory_stays_bounded_under_address_rotation():
    clock = FakeClock()
    limiter = InMemoryRateLimiter(5, 60, clock=clock, max_clients=100)

    for i in range(10_000):
        limiter.allow(f"198.51.{i // 256}.{i % 256}")

    assert len(limiter._requests) <= 101


def test_stale_clients_are_evicted_to_make_room():
    clock = FakeClock()
    limiter = InMemoryRateLimiter(1, 60, clock=clock, max_clients=2)

    limiter.allow("a")
    limiter.allow("b")

    clock.now += 61  # both entries leave the window

    assert limiter.allow("c") == (True, 0.0)
    assert OVERFLOW_CLIENT_ID not in limiter._requests


def test_existing_clients_keep_their_own_quota_when_the_table_is_full():
    clock = FakeClock()
    limiter = InMemoryRateLimiter(2, 60, clock=clock, max_clients=2)

    limiter.allow("a")
    limiter.allow("b")
    limiter.allow("overflow-1")

    assert limiter.allow("a") == (True, 0.0)
    assert limiter.allow("a")[0] is False


def test_max_clients_must_be_positive():
    with pytest.raises(ValueError):
        InMemoryRateLimiter(1, 60, max_clients=0)


# --- factory / redis wiring ----------------------------------------------------------


def test_memory_limiter_is_not_blocking_but_redis_is():
    assert InMemoryRateLimiter(1, 60).blocking is False
    assert RedisRateLimiter(client=MagicMock(), max_requests=1, window_seconds=60).blocking is True


def test_redis_client_is_created_with_connect_and_read_timeouts(monkeypatch):
    fake_redis = MagicMock()
    monkeypatch.setitem(sys.modules, "redis", fake_redis)

    create_rate_limiter(
        backend="redis",
        redis_url="redis://localhost:6379/0",
        redis_timeout=0.4,
    )

    fake_redis.from_url.assert_called_once_with(
        "redis://localhost:6379/0",
        socket_timeout=0.4,
        socket_connect_timeout=0.4,
    )


def test_redis_key_prefix_is_configurable():
    limiter = create_rate_limiter(
        backend="redis",
        redis_client=MagicMock(),
        prefix="guardrails:auth_failure:",
    )

    assert limiter.prefix == "guardrails:auth_failure:"


def test_factory_passes_max_clients_to_the_memory_limiter():
    limiter = create_rate_limiter(backend="memory", max_clients=7)

    assert limiter.max_clients == 7


def test_unparseable_trusted_entry_never_matches_and_does_not_break_valid_ones():
    # Config validation rejects bad entries at startup, but callers that
    # build the set themselves must still fail safe: the bad entry trusts
    # nothing, and the valid entry next to it keeps working.
    trusted = {"not-an-ip", "10.0.0.0/24"}

    assert resolve("10.0.0.5", "203.0.113.9", trusted) == "203.0.113.9"
    assert resolve("198.51.100.4", "203.0.113.9", {"not-an-ip"}) == "198.51.100.4"

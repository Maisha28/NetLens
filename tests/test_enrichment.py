"""
Tests for enrichment.enrichment.resolve_org(): offline IP -> organisation
name lookup that feeds the flow table's Organisation column.
"""

import ipaddress

from enrichment.enrichment import _longest_prefix_match, resolve_org


def test_known_public_ip_resolves_to_org():
    assert resolve_org("8.8.8.4") == "Google"


def test_private_ip_resolves_to_local_network():
    assert resolve_org("192.168.1.42") == "Local Network"


def test_loopback_resolves_to_loopback():
    assert resolve_org("127.0.0.1") == "Loopback"


def test_broadcast_resolves_to_broadcast():
    assert resolve_org("255.255.255.255") == "Broadcast"


def test_link_local_resolves_to_apipa():
    assert resolve_org("169.254.1.1") == "Link-Local (APIPA)"


def test_multicast_resolves_to_multicast():
    assert resolve_org("224.0.0.251") == "Multicast"


def test_unmatched_ip_resolves_to_unknown():
    assert resolve_org("203.0.113.7") == "Unknown"


def test_unparsable_input_does_not_raise():
    assert resolve_org("not-an-ip") == "Unknown"


def test_nested_range_prefers_more_specific_match():
    # Two entries where one range sits inside another - the longer
    # prefix (more specific) one must win, regardless of list order.
    ranges = sorted(
        [
            (ipaddress.ip_network("10.0.0.0/8"), "Broad"),
            (ipaddress.ip_network("10.1.0.0/16"), "Specific"),
        ],
        key=lambda pair: pair[0].prefixlen,
        reverse=True,
    )
    assert _longest_prefix_match(ipaddress.ip_address("10.1.2.3"), ranges) == "Specific"
    assert _longest_prefix_match(ipaddress.ip_address("10.2.2.3"), ranges) == "Broad"

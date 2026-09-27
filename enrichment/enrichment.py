"""
IP -> organisation enrichment. Fully offline: special-case RFC 1918 /
link-local / loopback / multicast / broadcast buckets are checked first,
then a hand-curated longest-prefix-match lookup table, falling back to
"Unknown" for anything else. resolve_org() never raises - it's called on
every flow-table refresh and must not be able to break that loop.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import List, Optional, Tuple

from enrichment.ip_ranges import ORG_RANGES, SPECIAL_CASES


def _longest_prefix_match(
    addr: ipaddress.IPv4Address,
    ranges: List[Tuple[ipaddress.IPv4Network, str]],
) -> Optional[str]:
    """
    ranges must already be sorted longest-prefix-first (see ip_ranges.py) -
    this just returns the label of the first network that contains addr.
    """
    for network, label in ranges:
        if addr in network:
            return label
    return None


@lru_cache(maxsize=4096)
def resolve_org(ip: str) -> str:
    """
    Resolve a dotted-quad IPv4 address to a human-readable label.

    Never raises - an unparsable or unmatched address falls back to
    "Unknown" rather than breaking the display/detection loop that
    calls this on every refresh.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "Unknown"

    special = _longest_prefix_match(addr, SPECIAL_CASES)
    if special is not None:
        return special

    org = _longest_prefix_match(addr, ORG_RANGES)
    if org is not None:
        return org

    return "Unknown"

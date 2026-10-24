"""
Offline IP -> organisation lookup data for enrichment.resolve_org().

Two separate tables:
  SPECIAL_CASES - RFC 1918 / link-local / loopback / multicast / broadcast
                  buckets, checked first, before any lookup table match.
  ORG_RANGES    - a hand-curated set of public CIDR ranges for a handful
                  of large, commonly-seen operators. Accuracy at the
                  /16-/12 level is enough for a demo; this is not meant
                  to be a full ASN database.
"""

from __future__ import annotations

import ipaddress
from typing import List, Tuple

SPECIAL_CASES: List[Tuple[ipaddress.IPv4Network, str]] = [
    (ipaddress.ip_network("10.0.0.0/8"), "Local Network"),
    (ipaddress.ip_network("172.16.0.0/12"), "Local Network"),
    (ipaddress.ip_network("192.168.0.0/16"), "Local Network"),
    (ipaddress.ip_network("169.254.0.0/16"), "Link-Local (APIPA)"),
    (ipaddress.ip_network("127.0.0.0/8"), "Loopback"),
    (ipaddress.ip_network("224.0.0.0/4"), "Multicast"),
    (ipaddress.ip_network("255.255.255.255/32"), "Broadcast"),
]

_RAW_ORG_RANGES = [
    ("8.8.8.0/24", "Google"),
    ("142.250.0.0/15", "Google"),
    ("172.217.0.0/16", "Google"),
    ("1.1.1.0/24", "Cloudflare"),
    ("104.16.0.0/12", "Cloudflare"),
    ("157.240.0.0/16", "Meta / Facebook"),
    ("31.13.24.0/21", "Meta / Facebook"),
    ("13.32.0.0/15", "Amazon / AWS"),
    ("52.0.0.0/8", "Amazon / AWS"),
    ("13.64.0.0/11", "Microsoft / Azure"),
    ("20.0.0.0/8", "Microsoft / Azure"),
    ("23.32.0.0/11", "Akamai"),
    ("17.0.0.0/8", "Apple"),
]

# Sorted longest-prefix-first once at import time so resolve_org() can
# just walk the list and return the first match.
ORG_RANGES: List[Tuple[ipaddress.IPv4Network, str]] = sorted(
    ((ipaddress.ip_network(cidr), org) for cidr, org in _RAW_ORG_RANGES),
    key=lambda pair: pair[0].prefixlen,
    reverse=True,
)

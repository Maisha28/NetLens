"""
Detection rules compare live per-interval stats against BaselineTracker
history and emit Alerts - evidence, not a verdict: every Alert carries the
numbers that caused it rather than a claim it can't prove.

Three rules, matching the SRS (REQ-25..REQ-27):

  check_bandwidth_hog() - a host's bytes this interval are far above its own
                          established baseline.
  check_port_scan()     - a host touched far more distinct destination ports
                          this interval than its baseline and the threshold.
  ArpWatcher            - one IP address claimed by a second MAC address.

All three reuse the IntervalStats/BaselineTracker machinery that
baseline.baseline builds every refresh. No rule uses ML: every alert comes
from a stated, inspectable threshold (SRS 2.5).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from baseline.baseline import BaselineTracker, IntervalStats


@dataclass
class Alert:
    rule_name: str
    host: str
    observed_value: float
    baseline_value: float
    threshold_multiplier: float
    timestamp: float
    message: str
    # Not persisted in the alerts table - carried for the UI and the signed
    # evidence ledger (old/new MAC, window length, thresholds, ...).
    evidence: Dict[str, Any] = field(default_factory=dict)
    severity: str = "medium"


def check_bandwidth_hog(
    interval_stats: Dict[str, IntervalStats],
    tracker: BaselineTracker,
    multiplier: float = 3.0,
    min_baseline_bytes: float = 500.0,
    min_observed_bytes: float = 0.0,
) -> List[Alert]:
    """
    For every host with a READY baseline (BaselineTracker.is_baseline_ready),
    compare this interval's byte_count to that host's ewma_bytes. Fires when:

        observed_bytes > baseline_bytes * multiplier
        AND baseline_bytes > min_baseline_bytes
        AND observed_bytes >= min_observed_bytes

    The min_baseline_bytes floor exists so a host with a near-zero baseline
    (one stray packet so far) doesn't trip the rule on its second packet
    ever - a real baseline has to mean something before "3x it" does.

    min_observed_bytes is the matching floor on the OTHER side: a host that has
    been idle (tiny baseline) shouldn't be called a bandwidth hog because a
    small background burst is 3x its near-zero average. A hog has to move a
    meaningful absolute amount. Default 0 keeps the original behaviour.
    """
    alerts: List[Alert] = []
    now = time.time()

    for host, stats in interval_stats.items():
        if not tracker.is_baseline_ready(host):
            continue

        baseline = tracker.get_baseline(host)
        baseline_bytes = baseline.ewma_bytes
        observed_bytes = float(stats.byte_count)

        if baseline_bytes <= min_baseline_bytes:
            continue
        if observed_bytes <= baseline_bytes * multiplier:
            continue
        if observed_bytes < min_observed_bytes:
            continue

        actual_multiplier = observed_bytes / baseline_bytes
        alerts.append(
            Alert(
                rule_name="bandwidth_hog",
                host=host,
                observed_value=observed_bytes,
                baseline_value=baseline_bytes,
                threshold_multiplier=multiplier,
                timestamp=now,
                message=(
                    f"{host} moved {observed_bytes:,.0f} bytes this interval "
                    f"— {actual_multiplier:.1f}x its baseline of {baseline_bytes:,.0f} bytes"
                ),
            )
        )

    return alerts


def check_port_scan(
    interval_stats: Dict[str, IntervalStats],
    tracker: BaselineTracker,
    min_ports: int = 15,
    multiplier: float = 3.0,
    window_seconds: float = 0.0,
) -> List[Alert]:
    """
    Fires for a host with a READY baseline when, in one interval,

        distinct_destination_ports >= max(min_ports, baseline_ports * multiplier)

    min_ports is the absolute floor (the execution plan's example uses 15);
    the multiplier term stops a legitimately chatty host - a phone that
    always talks to many ports - from tripping it. The alert also reports
    how many distinct destination IPs were touched (horizontal fan-out).
    """
    alerts: List[Alert] = []
    now = time.time()

    for host, stats in interval_stats.items():
        if not tracker.is_baseline_ready(host):
            continue

        baseline = tracker.get_baseline(host)
        observed_ports = len(stats.distinct_dst_ports)
        threshold = max(float(min_ports), baseline.ewma_distinct_ports * multiplier)
        if observed_ports < threshold:
            continue

        window = f"{window_seconds:g}s" if window_seconds else "one interval"
        alerts.append(
            Alert(
                rule_name="port_scan",
                host=host,
                observed_value=float(observed_ports),
                baseline_value=baseline.ewma_distinct_ports,
                threshold_multiplier=threshold,
                timestamp=now,
                message=(
                    f"{host} contacted {observed_ports} distinct ports across "
                    f"{len(stats.distinct_dst_ips)} host(s) in {window} "
                    f"- baseline {baseline.ewma_distinct_ports:.1f}, threshold {threshold:.0f}"
                ),
                evidence={
                    "distinct_ports": observed_ports,
                    "distinct_hosts": len(stats.distinct_dst_ips),
                    "baseline_ports": round(baseline.ewma_distinct_ports, 2),
                    "threshold": round(threshold, 2),
                    "window_seconds": window_seconds,
                    "sample_ports": sorted(stats.distinct_dst_ports)[:12],
                },
                severity="high",
            )
        )

    return alerts


class ArpWatcher:
    """
    Maintains an IP -> MAC table from ARP packets (the sender fields of both
    requests and replies) and fires when a known IP is claimed by a different
    MAC. This is the classic ARP-cache-poisoning signature: the attacker tells
    the victim "the gateway's IP is at MY MAC".

    Evidence only, not a verdict: a legitimate NIC swap or DHCP re-lease can
    look identical, which is why the alert states old MAC, new MAC and time
    rather than claiming an attack.
    """

    def __init__(self) -> None:
        self._table: Dict[str, str] = {}
        self._first_seen: Dict[str, float] = {}

    def table(self) -> Dict[str, str]:
        return dict(self._table)

    def observe(
        self,
        ip: Optional[str],
        mac: Optional[str],
        timestamp: Optional[float] = None,
    ) -> Optional[Alert]:
        if not ip or not mac or ip == "0.0.0.0":
            return None  # ARP probes carry 0.0.0.0 as sender; not a claim
        mac = mac.lower()
        known = self._table.get(ip)
        if known is None:
            self._table[ip] = mac
            self._first_seen[ip] = timestamp or time.time()
            return None
        if known == mac:
            return None

        now = timestamp or time.time()
        # Keep the ORIGINAL binding as the trusted one so a sustained spoof
        # keeps firing against the first-seen MAC instead of "accepting" it.
        return Alert(
            rule_name="arp_spoof",
            host=ip,
            observed_value=2.0,
            baseline_value=1.0,
            threshold_multiplier=1.0,
            timestamp=now,
            message=f"{ip} was claimed by a second MAC: {known} -> {mac}",
            evidence={
                "ip": ip,
                "old_mac": known,
                "new_mac": mac,
                "first_bound_at": self._first_seen.get(ip),
            },
            severity="critical",
        )

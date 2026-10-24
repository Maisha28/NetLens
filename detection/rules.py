"""
Detection rules compare live per-interval stats against BaselineTracker
history and emit Alerts - evidence, not a verdict: every Alert carries the
numbers that caused it rather than a claim it can't prove.

check_bandwidth_hog() is the first of the committed detections: it flags
a host whose traffic this interval is far above its own established
baseline, reusing the IntervalStats/BaselineTracker machinery
baseline.baseline already builds every refresh.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List

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


def check_bandwidth_hog(
    interval_stats: Dict[str, IntervalStats],
    tracker: BaselineTracker,
    multiplier: float = 3.0,
    min_baseline_bytes: float = 500.0,
) -> List[Alert]:
    """
    For every host with a READY baseline (BaselineTracker.is_baseline_ready),
    compare this interval's byte_count to that host's ewma_bytes. Fires when:

        observed_bytes > baseline_bytes * multiplier
        AND baseline_bytes > min_baseline_bytes

    The min_baseline_bytes floor exists so a host with a near-zero baseline
    (one stray packet so far) doesn't trip the rule on its second packet
    ever - a real baseline has to mean something before "3x it" does.
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

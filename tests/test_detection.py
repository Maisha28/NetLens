"""
Tests for detection.rules.check_bandwidth_hog(): the first committed
detection rule, comparing this interval's per-host byte_count against
that host's ready EWMA baseline.
"""

from baseline.baseline import BaselineTracker, IntervalStats
from detection.rules import check_bandwidth_hog


def _ready_tracker(host: str, ewma_bytes: float, samples: int = 3) -> BaselineTracker:
    tracker = BaselineTracker()
    # A constant observed value across samples keeps the EWMA equal to
    # that value once seeded, giving a known, ready baseline to test against.
    for i in range(samples):
        tracker.update(host, IntervalStats(byte_count=int(ewma_bytes)), now=float(i))
    return tracker


def test_host_over_threshold_produces_one_alert():
    host = "10.0.0.5"
    tracker = _ready_tracker(host, ewma_bytes=1000)
    interval_stats = {host: IntervalStats(byte_count=5000)}

    alerts = check_bandwidth_hog(interval_stats, tracker)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "bandwidth_hog"
    assert alert.host == host
    assert alert.observed_value == 5000
    assert alert.baseline_value == 1000
    assert host in alert.message


def test_host_under_threshold_produces_no_alert():
    host = "10.0.0.5"
    tracker = _ready_tracker(host, ewma_bytes=1000)
    interval_stats = {host: IntervalStats(byte_count=2000)}  # only 2x baseline

    assert check_bandwidth_hog(interval_stats, tracker) == []


def test_tiny_baseline_does_not_fire_even_at_multiplier():
    host = "10.0.0.5"
    tracker = _ready_tracker(host, ewma_bytes=50)  # below min_baseline_bytes=500
    interval_stats = {host: IntervalStats(byte_count=1000)}  # 20x, but baseline is tiny

    assert check_bandwidth_hog(interval_stats, tracker) == []


def test_unready_baseline_never_fires():
    host = "10.0.0.5"
    tracker = BaselineTracker()
    tracker.update(host, IntervalStats(byte_count=1000), now=0.0)  # only 1 sample, not ready
    interval_stats = {host: IntervalStats(byte_count=1_000_000)}

    assert check_bandwidth_hog(interval_stats, tracker) == []

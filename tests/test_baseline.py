"""
Tests for baseline.baseline: per-host EWMA tracking over per-interval
stats - the "usual" that detection.rules.check_bandwidth_hog() compares
live intervals against.
"""

import pytest

from baseline.baseline import BaselineTracker, IntervalStats
from storage.db import get_all_baselines, get_connection, upsert_baseline


def _stats(byte_count=0, packet_count=0, ports=None):
    return IntervalStats(
        byte_count=byte_count,
        packet_count=packet_count,
        distinct_dst_ports=set(ports or []),
    )


def test_cold_start_seeds_ewma_to_observed_value():
    tracker = BaselineTracker()
    tracker.update("10.0.0.5", _stats(byte_count=1000, packet_count=5, ports=[80]), now=1000.0)

    baseline = tracker.get_baseline("10.0.0.5")
    assert baseline.ewma_bytes == 1000
    assert baseline.ewma_packets == 5
    assert baseline.ewma_distinct_ports == 1
    assert baseline.samples_seen == 1


def test_known_sequence_produces_expected_ewma():
    # alpha=0.2: cold start seeds directly, then each step blends
    # 0.2*observed + 0.8*previous. Hand-computed:
    #   1000 -> 1000
    #   2000 -> 0.2*2000 + 0.8*1000 = 1200
    #   1500 -> 0.2*1500 + 0.8*1200 = 1260
    #   3000 -> 0.2*3000 + 0.8*1260 = 1608
    tracker = BaselineTracker()
    host = "10.0.0.5"
    observed = [1000, 2000, 1500, 3000]
    expected = [1000, 1200, 1260, 1608]

    for i, value in enumerate(observed):
        tracker.update(host, _stats(byte_count=value), now=float(i), alpha=0.2)
        assert tracker.get_baseline(host).ewma_bytes == pytest.approx(expected[i])


def test_baseline_ready_gate():
    tracker = BaselineTracker()
    host = "10.0.0.5"

    tracker.update(host, _stats(byte_count=1000), now=0.0)
    assert tracker.is_baseline_ready(host) is False

    tracker.update(host, _stats(byte_count=1000), now=1.0)
    assert tracker.is_baseline_ready(host) is False

    tracker.update(host, _stats(byte_count=1000), now=2.0)
    assert tracker.is_baseline_ready(host) is True


def test_persistence_round_trip(tmp_path):
    tracker = BaselineTracker()
    tracker.update("10.0.0.5", _stats(byte_count=1000, packet_count=5, ports=[80, 443]), now=1000.0)
    baseline = tracker.get_baseline("10.0.0.5")

    conn = get_connection(tmp_path / "netlens_test.db")
    upsert_baseline(baseline, conn)

    fetched = get_all_baselines(conn)
    conn.close()

    assert fetched["10.0.0.5"].ewma_bytes == baseline.ewma_bytes
    assert fetched["10.0.0.5"].ewma_packets == baseline.ewma_packets
    assert fetched["10.0.0.5"].ewma_distinct_ports == baseline.ewma_distinct_ports
    assert fetched["10.0.0.5"].samples_seen == baseline.samples_seen
    assert fetched["10.0.0.5"].last_updated == baseline.last_updated

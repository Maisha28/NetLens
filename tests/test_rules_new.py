"""
Tests for the two detection rules added to complete the SRS trio
(check_port_scan = REQ-26, ArpWatcher = REQ-27) and the bandwidth rule's
absolute-volume floor.
"""

from baseline.baseline import BaselineTracker, IntervalStats
from detection.rules import ArpWatcher, check_bandwidth_hog, check_port_scan


def _ready(host, ports=2.0, nbytes=10_000):
    tracker = BaselineTracker()
    for i in range(3):
        tracker.update(host, IntervalStats(byte_count=nbytes, distinct_dst_ports=set(range(int(ports)))), float(i))
    return tracker


# --- port scan ---------------------------------------------------------------


def test_scan_fires_above_floor_and_reports_evidence():
    tracker = _ready("10.0.0.5", ports=2)
    stats = {"10.0.0.5": IntervalStats(distinct_dst_ports=set(range(1, 60)), distinct_dst_ips={"10.0.0.1"})}
    (alert,) = check_port_scan(stats, tracker, window_seconds=4)
    assert alert.rule_name == "port_scan"
    assert alert.observed_value == 59
    assert alert.threshold_multiplier == 15
    assert alert.evidence["distinct_hosts"] == 1
    assert alert.evidence["window_seconds"] == 4
    assert "59 distinct ports" in alert.message


def test_scan_does_not_fire_below_floor():
    tracker = _ready("10.0.0.5", ports=2)
    stats = {"10.0.0.5": IntervalStats(distinct_dst_ports=set(range(1, 15)))}
    assert check_port_scan(stats, tracker) == []


def test_scan_threshold_scales_with_a_chatty_hosts_baseline():
    tracker = _ready("10.0.0.5", ports=20)  # normally probes ~20 ports
    stats = {"10.0.0.5": IntervalStats(distinct_dst_ports=set(range(1, 41)))}  # 40 < 3 x 20 = 60
    assert check_port_scan(stats, tracker) == []


def test_scan_never_fires_without_a_ready_baseline():
    tracker = BaselineTracker()
    tracker.update("10.0.0.5", IntervalStats(distinct_dst_ports={1, 2}), 0.0)  # 1 sample only
    stats = {"10.0.0.5": IntervalStats(distinct_dst_ports=set(range(1, 500)))}
    assert check_port_scan(stats, tracker) == []  # REQ-29


# --- ARP spoofing ----------------------------------------------------------------


def test_arp_first_binding_is_silent_and_same_mac_repeats_are_silent():
    arp = ArpWatcher()
    assert arp.observe("10.0.0.1", "aa:aa:aa:aa:aa:01", 1.0) is None
    assert arp.observe("10.0.0.1", "AA:AA:AA:AA:AA:01", 2.0) is None  # case-insensitive


def test_arp_second_mac_fires_with_old_and_new():
    arp = ArpWatcher()
    arp.observe("10.0.0.1", "aa:aa:aa:aa:aa:01", 1.0)
    alert = arp.observe("10.0.0.1", "bb:bb:bb:bb:bb:02", 5.0)
    assert alert.rule_name == "arp_spoof" and alert.host == "10.0.0.1"
    assert alert.evidence["old_mac"] == "aa:aa:aa:aa:aa:01"
    assert alert.evidence["new_mac"] == "bb:bb:bb:bb:bb:02"
    assert alert.severity == "critical"


def test_arp_keeps_the_original_binding_so_a_sustained_spoof_keeps_firing():
    arp = ArpWatcher()
    arp.observe("10.0.0.1", "aa:aa:aa:aa:aa:01", 1.0)
    assert arp.observe("10.0.0.1", "bb:bb:bb:bb:bb:02", 2.0)
    assert arp.observe("10.0.0.1", "bb:bb:bb:bb:bb:02", 3.0)  # still against the first-seen MAC
    assert arp.table()["10.0.0.1"] == "aa:aa:aa:aa:aa:01"


def test_arp_probe_with_unspecified_sender_is_ignored():
    arp = ArpWatcher()
    assert arp.observe("0.0.0.0", "aa:aa:aa:aa:aa:01") is None
    assert arp.table() == {}


# --- bandwidth floor ---------------------------------------------------------------


def test_hog_absolute_floor_blocks_small_bursts_from_idle_hosts():
    tracker = _ready("10.0.0.5", nbytes=5_000)
    stats = {"10.0.0.5": IntervalStats(byte_count=16_000)}  # 3.2x baseline but tiny
    assert len(check_bandwidth_hog(stats, tracker)) == 1  # default floor 0: original behaviour
    assert check_bandwidth_hog(stats, tracker, min_observed_bytes=45_000) == []
    big = {"10.0.0.5": IntervalStats(byte_count=900_000)}
    assert len(check_bandwidth_hog(big, tracker, min_observed_bytes=45_000)) == 1

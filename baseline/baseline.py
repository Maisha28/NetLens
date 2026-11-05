"""
Per-host EWMA baseline tracking.

At every existing main.py refresh point (every 50 packets or 10s), the
caller derives one IntervalStats per host from that interval's
PacketRecords alone and calls BaselineTracker.update() - the exponential
weighted moving average blends each interval's observed value into a
running per-host average of "usual" behaviour. This module only consumes
IntervalStats; it knows nothing about packets, flows, or SQLite.

Reused (per the project reference) as the same mechanism a future
port-scan rule would need: sliding-window counts plus an EWMA threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Set


@dataclass
class IntervalStats:
    byte_count: int = 0
    packet_count: int = 0
    distinct_dst_ports: Set[int] = field(default_factory=set)
    distinct_dst_ips: Set[str] = field(default_factory=set)


@dataclass
class HostBaseline:
    host: str
    ewma_bytes: float
    ewma_packets: float
    ewma_distinct_ports: float
    samples_seen: int
    last_updated: float


class BaselineTracker:
    def __init__(self, min_samples: int = 3) -> None:
        self._baselines: Dict[str, HostBaseline] = {}
        self.min_samples = min_samples

    def update(self, host: str, stats: IntervalStats, now: float, alpha: float = 0.2) -> None:
        observed_ports = float(len(stats.distinct_dst_ports))
        existing = self._baselines.get(host)

        if existing is None:
            # Cold start: seed the average directly from this interval's
            # observation rather than averaging against zero.
            self._baselines[host] = HostBaseline(
                host=host,
                ewma_bytes=float(stats.byte_count),
                ewma_packets=float(stats.packet_count),
                ewma_distinct_ports=observed_ports,
                samples_seen=1,
                last_updated=now,
            )
            return

        existing.ewma_bytes = alpha * stats.byte_count + (1 - alpha) * existing.ewma_bytes
        existing.ewma_packets = alpha * stats.packet_count + (1 - alpha) * existing.ewma_packets
        existing.ewma_distinct_ports = alpha * observed_ports + (1 - alpha) * existing.ewma_distinct_ports
        existing.samples_seen += 1
        existing.last_updated = now

    def is_baseline_ready(self, host: str, min_samples: Optional[int] = None) -> bool:
        needed = self.min_samples if min_samples is None else min_samples
        baseline = self._baselines.get(host)
        return baseline is not None and baseline.samples_seen >= needed

    def get_baseline(self, host: str) -> Optional[HostBaseline]:
        return self._baselines.get(host)

    def all_baselines(self) -> Dict[str, HostBaseline]:
        return dict(self._baselines)

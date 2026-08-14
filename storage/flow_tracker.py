"""
Person C's part: group PacketRecords into flows by the 5-tuple
(src_ip, src_port, dst_ip, dst_port, protocol).

Note: this groups strictly by direction - a request (A->B) and its reply
(B->A) land in two different flows, since their 5-tuples differ (src/dst
swapped). That's a deliberate Day 1 simplification; bidirectional flow
merging is integration-day territory, not this module's job today.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from shared.packet_record import PacketRecord

FlowKey = Tuple[str, int, str, int, str]


@dataclass
class FlowStats:
    key: FlowKey
    records: List[PacketRecord] = field(default_factory=list)
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    def add(self, record: PacketRecord) -> None:
        self.records.append(record)
        self.packet_count += 1
        self.byte_count += record.length
        if self.packet_count == 1:
            self.first_seen = self.last_seen = record.timestamp
        else:
            self.first_seen = min(self.first_seen, record.timestamp)
            self.last_seen = max(self.last_seen, record.timestamp)


def _flow_key(record: PacketRecord) -> FlowKey:
    return (
        record.src_ip or "",
        record.src_port or 0,
        record.dst_ip or "",
        record.dst_port or 0,
        record.protocol or "OTHER",
    )


def group_into_flows(records: List[PacketRecord]) -> Dict[FlowKey, FlowStats]:
    flows: Dict[FlowKey, FlowStats] = {}
    for record in records:
        key = _flow_key(record)
        if key not in flows:
            flows[key] = FlowStats(key=key)
        flows[key].add(record)
    return flows


if __name__ == "__main__":
    from storage.sample_records import SAMPLE_RECORDS

    flows = group_into_flows(SAMPLE_RECORDS)
    print(f"Grouped {len(SAMPLE_RECORDS)} records into {len(flows)} flow(s):\n")
    for key, stats in flows.items():
        src_ip, src_port, dst_ip, dst_port, protocol = key
        print(
            f"  [{protocol:>4}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}  "
            f"pkts={stats.packet_count} bytes={stats.byte_count} "
            f"first={stats.first_seen:.3f} last={stats.last_seen:.3f}"
        )

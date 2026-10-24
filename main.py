"""
Day 2 integration: wires the three independent modules built on Day 1
into one live pipeline. All the real logic (capturing, decoding,
storing, displaying) stays in capture/, decoder/, and storage/ - this
file only sequences calls between them:

    capture.capture_packets()  ->  decoder.decode()  ->  storage.db.store_packet()
                                                      ->  storage.display.print_packet_row()

Every ~50 packets (or ~10 seconds of traffic, whichever comes first),
it also pulls everything stored so far, groups it into flows, and
prints a flow summary table.

Run:
    python main.py
Stop with Ctrl+C.

See capture/capture.py's module docstring for the Administrator/Npcap
requirements this depends on - if capture can't open the interface,
that same guidance is surfaced below instead of a raw traceback.

To capture a phone's traffic through a Windows mobile hotspot, scapy's
default interface is often the wrong one - the hotspot's clients show up
on a separate virtual adapter (typically named "Local Area Connection*
N", description "Microsoft Wi-Fi Direct Virtual Adapter"). Run with
--list-interfaces to see every adapter Npcap can see, then pass the
right one with --iface "<name>".

Run:
    python main.py --list-interfaces
    python main.py --iface "Local Area Connection* 3"
Stop with Ctrl+C.
"""

from __future__ import annotations

import argparse
import ipaddress
import time
from typing import Dict, List

from rich.console import Console

from baseline.baseline import BaselineTracker, IntervalStats
from capture.capture import capture_packets
from decoder.decoder import decode
from detection.rules import check_bandwidth_hog
from enrichment.hostnames import HostnameMap
from shared.packet_record import PacketRecord
from storage.db import (
    DEFAULT_DB_PATH,
    get_all_packets,
    get_connection,
    store_alert,
    store_flows,
    store_packet,
    upsert_baseline,
)
from storage.display import print_alert, print_flow_table, print_packet_row
from storage.flow_tracker import group_into_flows

console = Console()

FLOW_TABLE_EVERY_N_PACKETS = 50
FLOW_TABLE_EVERY_N_SECONDS = 10
# Baselines/alerts use fixed time windows only, so every interval is
# comparable (a packet-count window shrinks during a burst and hides it).
DETECTION_WINDOW_SECONDS = 10


def _is_local(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NetLens - live packet capture, decode, and flow view.")
    parser.add_argument(
        "--iface",
        default=None,
        help='Interface name to capture on, e.g. "Local Area Connection* 3" '
        "(the hotspot's virtual adapter). Defaults to scapy's active interface.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available capture interfaces (name, description, GUID) and exit.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Hide per-packet rows so alerts and flow tables stay visible on screen.",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Clear all stored packets, flows, baselines and alerts before capturing "
        "(clean slate - otherwise earlier sessions are mixed into the flow table).",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Only show flows involving this IP, e.g. the phone's 192.168.137.x address.",
    )
    return parser.parse_args()


def _list_interfaces() -> None:
    from scapy.arch import get_windows_if_list

    for iface in get_windows_if_list():
        console.print(f"[bold]{iface.get('name')}[/bold]  -  {iface.get('description')}")


def main() -> None:
    args = _parse_args()
    if args.list_interfaces:
        _list_interfaces()
        return

    conn = get_connection()
    if args.fresh:
        for table in ("packets", "flows", "baselines", "alerts"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        console.print("[dim]Cleared previous capture data.[/dim]")
    console.print(f"[bold]NetLens[/bold] - live capture starting, writing to {DEFAULT_DB_PATH}")
    if args.iface:
        console.print(f"Interface: {args.iface}")
    console.print("Press Ctrl+C to stop.\n")

    packet_count = 0
    warning_count = 0
    last_flow_table_at = time.monotonic()
    last_detection_at = time.monotonic()
    pending_alerts: list = []
    baseline_tracker = BaselineTracker()
    hostnames = HostnameMap()
    interval_records: List[PacketRecord] = []

    try:
        for raw_bytes, timestamp in capture_packets(iface=args.iface):
            try:
                record = decode(raw_bytes, timestamp)
                hostnames.learn(record)
                store_packet(record, conn)
                if not args.quiet:
                    print_packet_row(record)
                packet_count += 1
                interval_records.append(record)
            except Exception as exc:
                # One bad frame must never take the whole capture down -
                # log it and keep going.
                warning_count += 1
                console.print(
                    f"[yellow]warning:[/yellow] skipped a {len(raw_bytes)}-byte frame "
                    f"({type(exc).__name__}: {exc})"
                )
                continue

            now = time.monotonic()
            due_by_count = packet_count % FLOW_TABLE_EVERY_N_PACKETS == 0
            due_by_time = now - last_flow_table_at >= FLOW_TABLE_EVERY_N_SECONDS
            if due_by_count or due_by_time:
                last_flow_table_at = now
                wall_clock_now = time.time()

                if now - last_detection_at >= DETECTION_WINDOW_SECONDS:
                    last_detection_at = now

                    # Count a packet toward BOTH ends when they are local
                    # devices, so a phone's downloads (it is the destination)
                    # count as its traffic, not just its uploads.
                    interval_stats: Dict[str, IntervalStats] = {}
                    for interval_record in interval_records:
                        for ip, is_sender in ((interval_record.src_ip, True), (interval_record.dst_ip, False)):
                            if not ip or not _is_local(ip):
                                continue
                            stats = interval_stats.setdefault(ip, IntervalStats())
                            stats.byte_count += interval_record.length
                            stats.packet_count += 1
                            if is_sender and interval_record.dst_port is not None:
                                stats.distinct_dst_ports.add(interval_record.dst_port)

                    # Check against the PRIOR baseline, then learn from this
                    # interval - otherwise the spike inflates its own baseline.
                    new_alerts = check_bandwidth_hog(interval_stats, baseline_tracker)
                    for alert in new_alerts:
                        store_alert(alert, conn)
                        print_alert(alert)
                    pending_alerts.extend(new_alerts)

                    for host, stats in interval_stats.items():
                        baseline_tracker.update(host, stats, wall_clock_now)
                        upsert_baseline(baseline_tracker.get_baseline(host), conn)

                    interval_records = []

                flows = group_into_flows(get_all_packets(conn))
                if args.host:
                    all_flows = flows
                    flows = {k: v for k, v in all_flows.items() if args.host in (k[0], k[2])}
                    if not flows:
                        seen = sorted({ip for k in all_flows for ip in (k[0], k[2]) if ip.startswith("192.168.137.")})
                        console.print(
                            f"[yellow]No flows involve {args.host}.[/yellow] "
                            f"Hotspot addresses seen so far: {', '.join(seen) or 'none'}"
                        )
                        continue
                store_flows(flows, conn)
                console.print()
                print_flow_table(flows, hostnames)
                console.print()
                # Repeat alerts under the flow table so they are the last thing
                # on screen when the table refreshes, not buried above it.
                for alert in pending_alerts:
                    print_alert(alert)
                pending_alerts = []

    except KeyboardInterrupt:
        pass
    except PermissionError:
        console.print(
            "\n[red]Permission denied opening the capture device.[/red]\n"
            "Run this from a terminal opened 'as Administrator' on Windows, "
            "and make sure Npcap is installed (https://npcap.com/) with "
            "'Install Npcap in WinPcap API-compatible Mode' enabled."
        )
        conn.close()
        return
    except OSError as exc:
        console.print(
            f"\n[red]Capture failed to start ({exc}).[/red]\n"
            "Most likely causes: Npcap is not installed, the terminal isn't "
            "running as Administrator, or no active network interface was found."
        )
        conn.close()
        return

    conn.close()
    console.print(f"\nStopped. Processed {packet_count} packet(s), {warning_count} warning(s).")


if __name__ == "__main__":
    main()

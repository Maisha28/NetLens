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
import time

from rich.console import Console

from capture.capture import capture_packets
from decoder.decoder import decode
from storage.db import DEFAULT_DB_PATH, get_all_packets, get_connection, store_flows, store_packet
from storage.display import print_flow_table, print_packet_row
from storage.flow_tracker import group_into_flows

console = Console()

FLOW_TABLE_EVERY_N_PACKETS = 50
FLOW_TABLE_EVERY_N_SECONDS = 10


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
    console.print(f"[bold]NetLens[/bold] - live capture starting, writing to {DEFAULT_DB_PATH}")
    if args.iface:
        console.print(f"Interface: {args.iface}")
    console.print("Press Ctrl+C to stop.\n")

    packet_count = 0
    warning_count = 0
    last_flow_table_at = time.monotonic()

    try:
        for raw_bytes, timestamp in capture_packets(iface=args.iface):
            try:
                record = decode(raw_bytes, timestamp)
                store_packet(record, conn)
                print_packet_row(record)
                packet_count += 1
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
                flows = group_into_flows(get_all_packets(conn))
                store_flows(flows, conn)
                console.print()
                print_flow_table(flows)
                console.print()

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

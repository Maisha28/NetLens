"""
NetLens terminal mode - the same pipeline as the web dashboard, printed to the console.

    capture.capture_packets() -> engine.Engine (decode -> flows -> SQLite -> baselines
                                 -> bandwidth_hog / port_scan / arp_spoof -> signed ledger)
                              -> rich packet rows, flow tables and alert panels

Engine is shared with `python app.py` (the browser dashboard), so the two
interfaces can never disagree about what was detected.

Run (Administrator terminal + Npcap, see capture/capture.py):
    python main.py --list-interfaces
    python main.py --iface "Local Area Connection* 3"
Stop with Ctrl+C.

To capture a phone's traffic through a Windows mobile hotspot, scapy's default
interface is often the wrong one - the hotspot's clients show up on a separate
virtual adapter (typically "Local Area Connection* N", description "Microsoft
Wi-Fi Direct Virtual Adapter"). Run with --list-interfaces to see every adapter,
then pass the right one with --iface "<name>".
"""

from __future__ import annotations

import argparse
import time

from rich.console import Console

from capture.capture import capture_packets
from detection.rules import Alert
from engine.engine import Engine
from storage.db import DEFAULT_DB_PATH
from storage.display import print_alert, print_flow_table, print_packet_row

console = Console()

FLOW_TABLE_EVERY_N_PACKETS = 50
FLOW_TABLE_EVERY_N_SECONDS = 10
DETECTION_WINDOW_SECONDS = 10


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NetLens - live packet capture, decode, flow view and alerts.")
    parser.add_argument(
        "--iface",
        default=None,
        help='Interface name to capture on, e.g. "Local Area Connection* 3" '
        "(the hotspot's virtual adapter). Defaults to scapy's active interface.",
    )
    parser.add_argument("--list-interfaces", action="store_true", help="List capture interfaces and exit.")
    parser.add_argument("--quiet", action="store_true", help="Hide per-packet rows so alerts and flow tables stay visible.")
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Clear all stored packets, flows, baselines and alerts before capturing.",
    )
    parser.add_argument("--host", default=None, help="Only show flows involving this IP, e.g. the phone's 192.168.137.x address.")
    parser.add_argument("--window", type=float, default=DETECTION_WINDOW_SECONDS, help="Detection window in seconds.")
    return parser.parse_args()


def _list_interfaces() -> None:
    from web.system import list_interfaces

    for iface in (i for i in list_interfaces() if not i["noise"]):
        tag = "  [bold green]<- hotspot[/bold green]" if iface["recommended"] else ""
        console.print(f"[bold]{iface['name']}[/bold]  -  {iface['description']}  {' '.join(iface['ips'])}{tag}")


def _as_alert(rec: dict) -> Alert:
    return Alert(
        rule_name=rec["rule"], host=rec["host"], observed_value=rec["observed"], baseline_value=rec["baseline"],
        threshold_multiplier=rec["threshold"], timestamp=rec["ts"], message=rec["message"],
        evidence=rec["evidence"], severity=rec["severity"],
    )


def main() -> None:
    args = _parse_args()
    if args.list_interfaces:
        _list_interfaces()
        return

    engine = Engine(db_path=DEFAULT_DB_PATH, window_seconds=args.window, time_source="wall", fresh=args.fresh)
    if args.fresh:
        console.print("[dim]Cleared previous capture data.[/dim]")
    pending_alerts: list = []
    if not args.quiet:
        engine.on_packet.append(print_packet_row)

    def on_alert(rec: dict) -> None:
        alert = _as_alert(rec)
        print_alert(alert)
        pending_alerts.append(alert)

    engine.on_alert.append(on_alert)
    engine.start_ticker()

    console.print(f"[bold]NetLens[/bold] - live capture starting, writing to {DEFAULT_DB_PATH}")
    if args.iface:
        console.print(f"Interface: {args.iface}")
    console.print("Press Ctrl+C to stop.\n")

    packet_count = 0
    warning_count = 0
    last_table = time.monotonic()
    try:
        for raw_bytes, timestamp in capture_packets(iface=args.iface):
            before = engine.counters["decode_errors"] + engine.counters["pipeline_errors"]
            engine.ingest_frame(raw_bytes, timestamp)
            if engine.counters["decode_errors"] + engine.counters["pipeline_errors"] > before:
                # One bad frame must never take the whole capture down - log it and keep going.
                warning_count += 1
                console.print(f"[yellow]warning:[/yellow] skipped a {len(raw_bytes)}-byte frame")
                continue
            packet_count += 1

            now = time.monotonic()
            if packet_count % FLOW_TABLE_EVERY_N_PACKETS == 0 or now - last_table >= FLOW_TABLE_EVERY_N_SECONDS:
                last_table = now
                with engine.lock:
                    flows = dict(engine.flows)
                if args.host:
                    flows = {k: v for k, v in flows.items() if args.host in (k[0], k[2])}
                    if not flows:
                        seen = sorted({ip for k in engine.flows for ip in (k[0], k[2]) if ip.startswith("192.168.137.")})
                        console.print(f"[yellow]No flows involve {args.host}.[/yellow] Hotspot addresses seen so far: {', '.join(seen) or 'none'}")
                        continue
                console.print()
                print_flow_table(flows, engine.hostnames)
                console.print()
                # Repeat alerts under the flow table so they are the last thing on screen.
                for alert in pending_alerts:
                    print_alert(alert)
                pending_alerts.clear()

    except KeyboardInterrupt:
        pass
    except PermissionError:
        console.print(
            "\n[red]Permission denied opening the capture device.[/red]\n"
            "Run this from a terminal opened 'as Administrator' on Windows, "
            "and make sure Npcap is installed (https://npcap.com/) with "
            "'Install Npcap in WinPcap API-compatible Mode' enabled."
        )
        engine.shutdown()
        return
    except OSError as exc:
        console.print(
            f"\n[red]Capture failed to start ({exc}).[/red]\n"
            "Most likely causes: Npcap is not installed, the terminal isn't "
            "running as Administrator, or no active network interface was found."
        )
        engine.shutdown()
        return

    engine.shutdown()
    console.print(f"\nStopped. Processed {packet_count} packet(s), {warning_count} warning(s).")


if __name__ == "__main__":
    main()

"""
Person C's part: terminal output. print_packet_row() gives one line per
packet; print_flow_table() summarises grouped flows, enriched with each
destination's organisation; print_alert() renders a detection Alert as a
bordered panel, visually distinct from ordinary packet/flow output.
"""

from __future__ import annotations

from typing import Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from detection.rules import Alert
from enrichment.enrichment import resolve_org
from shared.packet_record import PacketRecord
from storage.flow_tracker import FlowKey, FlowStats

console = Console()

_PROTOCOL_COLORS = {
    "TCP": "cyan",
    "UDP": "magenta",
    "ARP": "yellow",
    "ICMP": "green",
    "OTHER": "white",
}


def print_packet_row(record: PacketRecord) -> None:
    color = _PROTOCOL_COLORS.get(record.protocol or "OTHER", "white")
    proto = f"[{color}]{record.protocol or '?':<5}[/{color}]"

    if record.src_port is not None or record.dst_port is not None:
        endpoints = f"{record.src_ip}:{record.src_port} -> {record.dst_ip}:{record.dst_port}"
    elif record.src_ip:
        endpoints = f"{record.src_ip} -> {record.dst_ip}"
    else:
        endpoints = f"{record.src_mac} -> {record.dst_mac}"

    extra = f" [{record.tcp_flags}]" if record.tcp_flags else ""
    console.print(
        f"{record.timestamp:>14.3f}  {proto}  {endpoints:<40}{extra}  "
        f"{record.length:>5}B  [dim]{record.summary or ''}[/dim]"
    )


def print_flow_table(flows: Dict[FlowKey, FlowStats]) -> None:
    table = Table(title="Flows", show_lines=False)
    table.add_column("Protocol", style="bold")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Organisation")
    table.add_column("Packets", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("First seen", justify="right")
    table.add_column("Last seen", justify="right")
    table.add_column("Duration (s)", justify="right")

    for (src_ip, src_port, dst_ip, dst_port, protocol), stats in flows.items():
        color = _PROTOCOL_COLORS.get(protocol, "white")
        src = f"{src_ip}:{src_port}" if src_port else src_ip
        dst = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
        organisation = resolve_org(dst_ip)
        duration = stats.last_seen - stats.first_seen
        table.add_row(
            f"[{color}]{protocol}[/{color}]",
            src,
            dst,
            organisation,
            str(stats.packet_count),
            str(stats.byte_count),
            f"{stats.first_seen:.3f}",
            f"{stats.last_seen:.3f}",
            f"{duration:.3f}",
        )

    console.print(table)


def print_alert(alert: Alert) -> None:
    console.print(
        Panel(
            f"[bold red]{alert.message}[/bold red]",
            title=f"[bold red]ALERT: {alert.rule_name}[/bold red]",
            border_style="bold red",
            expand=False,
        )
    )


if __name__ == "__main__":
    from storage.flow_tracker import group_into_flows
    from storage.sample_records import SAMPLE_RECORDS

    console.rule("print_packet_row()")
    for record in SAMPLE_RECORDS:
        print_packet_row(record)

    console.print()
    console.rule("print_flow_table()")
    print_flow_table(group_into_flows(SAMPLE_RECORDS))

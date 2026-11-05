"""
Environment checks for the live-capture setup wizard.

Capture fails for three boring reasons - not elevated, no Npcap, wrong adapter -
and the execution plan names the first as "the one blocker that can kill this
project". So the UI tests all three up front and says exactly what to fix,
instead of surfacing a raw traceback in front of the judges.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import List

HOTSPOT_SUBNET = "192.168.137."  # Windows Mobile Hotspot (Internet Connection Sharing) default


def is_admin() -> bool:
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def npcap_installed() -> bool:
    if os.name != "nt":
        return True  # libpcap is checked when sniffing starts
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    return (system32 / "Npcap").is_dir() or (system32 / "wpcap.dll").exists()


def list_interfaces() -> List[dict]:
    """Capture interfaces with a recommendation for the one carrying hotspot traffic."""
    items: List[dict] = []
    try:
        from scapy.arch import get_windows_if_list

        raw = get_windows_if_list()
    except Exception:
        try:
            from scapy.all import get_if_list

            raw = [{"name": n, "description": "", "ips": []} for n in get_if_list()]
        except Exception:
            raw = []

    for iface in raw:
        ips = [ip for ip in (iface.get("ips") or []) if ":" not in ip]
        desc = iface.get("description") or ""
        name = iface.get("name") or ""
        # Windows lists every filter-driver layer ("Wi-Fi-QoS Packet Scheduler-0000",
        # "...-Npcap Packet Driver (NPCAP)-0000") and tunnel/miniport pseudo-adapters
        # as separate interfaces. None of them carries a phone's traffic, so hide
        # them by default; the UI can still reveal them.
        noise = name.endswith("-0000") or any(
            marker in desc for marker in ("WAN Miniport", "Kernel Debug", "Teredo", "6to4", "IP-HTTPS", "Loopback")
        )
        on_hotspot = any(ip.startswith(HOTSPOT_SUBNET) for ip in ips)
        virtual_wifi = "virtual adapter" in desc.lower() or "wi-fi direct" in desc.lower() or name.startswith("Local Area Connection*")
        items.append(
            {
                "name": name, "description": desc, "ips": ips,
                "hotspot": on_hotspot or virtual_wifi,
                "recommended": on_hotspot,
                "noise": noise,
            }
        )
    items.sort(key=lambda i: (i["noise"], not i["recommended"], not i["hotspot"], not i["ips"], i["name"]))
    return items


def system_check() -> dict:
    interfaces = list_interfaces()
    recommended = next((i for i in interfaces if i["recommended"]), None)
    hotspot_candidates = [i for i in interfaces if i["hotspot"]]
    return {
        "platform": sys.platform,
        "admin": is_admin(),
        "npcap": npcap_installed(),
        "interfaces": interfaces,
        "recommended": recommended["name"] if recommended else (hotspot_candidates[0]["name"] if hotspot_candidates else None),
        "hotspot_on": recommended is not None,
        "self_ips": sorted({ip for i in interfaces for ip in i["ips"]}),
    }

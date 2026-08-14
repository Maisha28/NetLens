"""
Person A's part: get raw bytes off the wire.

capture_packets() does NOT parse anything - it just hands back
(raw_bytes, timestamp) tuples for every frame scapy's sniff() sees on the
active interface. All header parsing lives in decoder/decoder.py.

--- Privilege / driver requirements (read this before running) ---

Windows:
  - Requires Npcap (https://npcap.com/) installed with "Support raw 802.11
    traffic (and monitor mode) for wireless adapters" NOT required, but
    "Install Npcap in WinPcap API-compatible Mode" should be checked so
    scapy can find it.
  - Must be run from a terminal opened "as Administrator". Packet capture
    needs raw access to the NIC driver, which Npcap only grants to
    elevated processes on Windows.
  - If Npcap isn't installed, or the terminal isn't elevated, sniff() will
    raise a PermissionError / OSError, or scapy will report no capture
    devices at all.

Linux/macOS (for reference, not this machine):
  - Requires root (sudo) or the CAP_NET_RAW capability on the interpreter.

This module always uses scapy's sniff() (never raw sockets directly),
since Npcap/libpcap is what actually provides raw-frame access.
"""

from __future__ import annotations

import queue
import threading
from typing import Iterator, Optional, Tuple

from scapy.all import sniff


def capture_packets(
    iface: Optional[str] = None,
    count: int = 0,
) -> Iterator[Tuple[bytes, float]]:
    """
    Yield (raw_bytes, timestamp) for every frame captured on `iface`
    (or scapy's default/active interface if None), as they arrive.

    count=0 means capture indefinitely; stop by breaking out of the
    consuming loop (e.g. Ctrl+C), which closes this generator.

    No parsing happens here - raw_bytes is the untouched frame as scapy
    handed it to us, straight from Npcap/libpcap.
    """
    frame_queue: "queue.Queue[Tuple[bytes, float]]" = queue.Queue()
    stop_event = threading.Event()
    sniff_error: list = []

    def _on_frame(pkt) -> None:
        # bytes(pkt) serialises the frame exactly as scapy received it -
        # this is the raw wire data, not a parsed/decoded structure.
        frame_queue.put((bytes(pkt), float(pkt.time)))

    def _run_sniff() -> None:
        try:
            sniff(
                iface=iface,
                prn=_on_frame,
                store=False,
                count=count,
                stop_filter=lambda _pkt: stop_event.is_set(),
            )
        except Exception as exc:  # surfaced to the consumer below
            sniff_error.append(exc)
        finally:
            stop_event.set()

    sniff_thread = threading.Thread(target=_run_sniff, daemon=True)
    sniff_thread.start()

    try:
        while not stop_event.is_set() or not frame_queue.empty():
            try:
                yield frame_queue.get(timeout=0.5)
            except queue.Empty:
                continue
    finally:
        # Consumer stopped iterating (e.g. Ctrl+C / break) - ask the
        # sniff thread to wind down; it'll exit on its next packet or
        # timeout since scapy checks stop_filter per-packet.
        stop_event.set()

    if sniff_error:
        raise sniff_error[0]


if __name__ == "__main__":
    print("NetLens capture sanity check - press Ctrl+C to stop.\n")
    frame_count = 0
    try:
        for raw_bytes, timestamp in capture_packets():
            frame_count += 1
            print(f"[{frame_count:>5}] len={len(raw_bytes):>5} bytes  ts={timestamp:.6f}")
    except KeyboardInterrupt:
        print(f"\nStopped. Captured {frame_count} frame(s).")
    except PermissionError:
        print(
            "\nPermission denied opening the capture device.\n"
            "This script needs to be run from an Administrator terminal on "
            "Windows, and Npcap must be installed (https://npcap.com/) with "
            "'Install Npcap in WinPcap API-compatible Mode' enabled."
        )
    except OSError as exc:
        print(
            f"\nCapture failed to start ({exc}).\n"
            "Most likely causes:\n"
            "  - Npcap is not installed - get it from https://npcap.com/\n"
            "  - The terminal is not running as Administrator\n"
            "  - No active network interface was found"
        )

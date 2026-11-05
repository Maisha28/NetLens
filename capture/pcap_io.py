"""
Pcap recording and replay.

Every live session is recorded to captures/live-<timestamp>.pcap as it is
captured, so a demo that goes wrong on the day (hotspot dies, projector room
Wi-Fi misbehaves) can be replayed offline from the exact same bytes - the
fallback the execution plan calls for ("a saved capture file we can replay
offline").

PcapRecorder writes the classic libpcap format by hand with struct:

  global header (24 bytes): magic 0xa1b2c3d4, version 2.4, thiszone 0,
                            sigfigs 0, snaplen 65535, network 1 (Ethernet)
  per packet (16 + n):      ts_sec, ts_usec, incl_len, orig_len, then n bytes

Replay uses scapy's reader so both .pcap and Wireshark's default .pcapng open.
"""

from __future__ import annotations

import struct
import time
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

CAPTURE_DIR = Path(__file__).resolve().parent.parent / "captures"
_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


class PcapRecorder:
    def __init__(self, directory: Path = CAPTURE_DIR, prefix: str = "live", filename: Optional[str] = None) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / (filename or f"{prefix}-{time.strftime('%Y%m%d-%H%M%S')}.pcap")
        self._file = open(self.path, "wb")
        self._file.write(_GLOBAL_HEADER)
        self._file.flush()
        self.packets = 0

    def write(self, raw: bytes, ts: float) -> None:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self._file.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)) + raw)
        self.packets += 1
        if self.packets % 20 == 0:
            self._file.flush()

    def close(self) -> None:
        try:
            self._file.flush()
            self._file.close()
        except OSError:
            pass


def list_captures() -> List[dict]:
    if not CAPTURE_DIR.exists():
        return []
    files = [p for p in CAPTURE_DIR.iterdir() if p.suffix.lower() in (".pcap", ".pcapng")]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return [
        {"name": p.name, "size": p.stat().st_size, "modified": p.stat().st_mtime}
        for p in files[:12]
    ]


def resolve_capture(name: str) -> Path:
    """Map a bare file name to captures/<name>, refusing anything outside that folder."""
    path = (CAPTURE_DIR / Path(name).name).resolve()
    if CAPTURE_DIR.resolve() not in path.parents or not path.is_file():
        raise ValueError(f"no such recording: {name}")
    return path


def replay_pcap(path: Path, speed: float = 1.0) -> Iterator[Tuple[bytes, float]]:
    """Yield (raw, timestamp) at the original pace (scaled by speed; gaps capped at 1s)."""
    import logging

    from scapy.utils import PcapReader

    # scapy warns "unknown LL type" because only its utils are imported here; the bytes are
    # returned untouched either way, so the warning is noise.
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    previous = None
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            ts = float(pkt.time)
            if previous is not None and speed > 0:
                time.sleep(min(max(0.0, (ts - previous) / speed), 1.0))
            previous = ts
            yield bytes(pkt), ts

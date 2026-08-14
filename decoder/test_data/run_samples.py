"""
Sanity check for decoder.decode(): loads each sample raw frame in this
directory, decodes it, and prints the resulting PacketRecord so it can
be eyeballed against the sample's known contents.

Run:
    python decoder/test_data/run_samples.py
(regenerate fixtures first with generate_samples.py if .bin files are missing)
"""

import time
from pathlib import Path
from dataclasses import asdict

from decoder.decoder import decode

SAMPLES_DIR = Path(__file__).parent

SAMPLE_FILES = [
    "tcp_packet.bin",
    "udp_packet.bin",
    "arp_packet.bin",
    "dns_query.bin",
    "dns_response.bin",
]


def main() -> None:
    for filename in SAMPLE_FILES:
        path = SAMPLES_DIR / filename
        if not path.exists():
            print(f"[skip] {filename} not found - run generate_samples.py first")
            continue

        raw_bytes = path.read_bytes()
        record = decode(raw_bytes, timestamp=time.time())

        print(f"=== {filename} ({len(raw_bytes)} bytes) ===")
        for field_name, value in asdict(record).items():
            if value not in (None, "", []):
                print(f"  {field_name}: {value}")
        print()


if __name__ == "__main__":
    main()

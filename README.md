# NetLens

Adaptive packet analysis and anomaly detection. NetLens captures live traffic from a
phone connected to your laptop's Wi-Fi hotspot, decodes every protocol header **by hand**,
groups packets into conversations, learns what *normal* looks like for each device, and
raises evidence-backed alerts when behaviour departs from it - then seals those alerts in a
tamper-evident cryptographic ledger.

It works from **metadata only** (addresses, ports, sizes, timing, cleartext handshake fields).
It never decrypts or stores message content.

## Run it

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

run_netlens.bat            # double-click: asks for Administrator, starts the dashboard
# or, from an Administrator PowerShell:
python app.py              # opens http://localhost:8765
```

The browser opens a **setup wizard** with three sources - nothing is captured or simulated until you choose:

| Source | What it is |
|---|---|
| **Live capture** | Your own phone's real traffic through the Windows Mobile Hotspot. The wizard checks Administrator rights, Npcap and the hotspot adapter, and tells you exactly what to fix. Every live session is recorded to `captures/*.pcap`. |
| **Simulation** | Clearly-labelled synthetic traffic (no hardware needed) that can stage a port scan, ARP spoof and bandwidth spike on demand. It sends raw bytes through the *real* decoder, rules and ledger. |
| **Replay** | Replays a saved `.pcap`/`.pcapng` - the safety net if the demo room's network fails. |

Shortcuts: `python app.py --live [--iface "Local Area Connection* 3"]`, `--sim`, `--pcap file.pcap`, `--list-interfaces`.
Terminal-only mode (same engine): `python main.py --iface "<adapter>"`.

### Live demo setup (your phone)
1. Windows **Settings → Network & internet → Mobile hotspot → On**; join it from your phone.
2. Start NetLens as Administrator (`run_netlens.bat`), choose **Live capture**, pick the adapter that has `192.168.137.1`.
3. Use apps on the phone. Devices, sites, baselines and alerts appear live. The **Demo Playbook** page is a self-ticking script for presenting.

> Only capture and scan **your own devices** on **your own network**. Staged scans are for testing NetLens against your own laptop.

## What's in the dashboard

| Page | Shows |
|---|---|
| Overview | Live network map (devices → this laptop → organisations), KPIs, throughput with alert markers, detection status |
| Live Feed | One line per packet, decoded by hand; click a row to open it in the Packet Lab |
| Conversations | Flows merged by 5-tuple, named by site (DNS/SNI) and organisation (offline IP table), with encryption posture |
| Devices & Baselines | Per-device learned baseline vs live traffic vs alert threshold; idle-chatter beacon timeline; ARP table |
| Alerts | The three rules in plain English; each alert as rule / host / observed / baseline / threshold, sealed in the ledger |
| Packet Lab | Hex dump coloured by layer; click a field to highlight its bytes; checksums verified |
| Crypto & Integrity | Passive TLS handshake audit (versions, cipher grades, JA3), plaintext findings, and the HMAC-sealed hash-chain ledger with a tamper demo |
| Pipeline | The 8-stage data path with live counters and the real last packet at each stage |
| Demo Playbook | Do / you'll see / say, ticking itself off as NetLens detects each result |

Toggle **Guide** in the header to hide/show the plain-language explanations.

## Architecture

```
capture/      raw frames off the interface (scapy/Npcap), pcap recorder + replay
decoder/      Ethernet, IPv4, TCP, UDP, ARP, DNS, TLS-hello parsed by hand with struct;  explain.py = field-by-field annotation
storage/      SQLite schema + flow tracker + terminal display
enrichment/   offline IP->organisation, DNS/SNI->site, MAC->vendor
baseline/     per-host EWMA of bytes, packets, distinct ports
detection/    bandwidth_hog, port_scan, arp_spoof (explicit thresholds - no ML)
crypto/       tls.py (handshake audit, JA3)   ledger.py (SHA-256 chain + HMAC-SHA256 seal)
engine/       the pipeline as one object, shared by the CLI and the dashboard
sim/          byte-level frame builder + scenario simulator
web/          stdlib-only HTTP server + static single-page dashboard (no CDN, works offline)
```

Data path: `capture -> decode -> flow tracker -> SQLite -> baseline -> detection -> signed ledger -> UI`.

### Detection rules (SRS REQ-25 to REQ-30)
- **bandwidth_hog** - window bytes > 3x the host's own baseline, baseline meaningful (> 1 KB/s) and the host moved at least 15 KB/s.
- **port_scan** - distinct destination ports in connection-opening packets >= max(15, 3x baseline). Only SYNs / UDP-to-service-port packets count, so a DNS server answering many clients is *not* a scanner.
- **arp_spoof** - one IP seen with a second MAC; the original binding stays trusted so a sustained spoof keeps firing.
- No alert until a host has 3 learned windows; a window that alerts is *not* learned from; identical alerts inside 12 s are counted, not repeated.

### Cryptography
- **Passive TLS audit** - parses the cleartext ClientHello/ServerHello: version, offered/negotiated cipher, forward secrecy, ALPN, SNI, JA3 fingerprint; grades A-F (RC4, 3DES, export, NULL, TLS <= 1.1 flagged). Nothing is decrypted.
- **Evidence ledger** - `hash[i] = SHA-256(hash[i-1] || alert)`, each signed with `HMAC-SHA256(key)`; the key lives in `storage/.ledger_key`, separate from the database. Edits, deletions, reordering and tail-truncation are detected and located. This gives integrity, not secrecy.

## Honest limits
- A TLS hello split across TCP segments is not reassembled; QUIC and encrypted DNS (DoH / Private Relay) hide names - those flows fall back to organisation-level labels.
- The IP-range and MAC-vendor tables are small, hand-curated, and offline by design.
- ARP spoofing can't be staged safely against a real phone; it is demonstrated in Simulation (and fires live if a second device really claims the gateway IP).
- Thresholds (3x, 15 ports, 15 KB/s) are tuned defaults, listed as TBD items in the SRS.

## Tests
```
python -m pytest        # ~100 tests, ~15 s
```
Covers the decoder, flow tracker, storage, baseline, all three rules, TLS parsing, the ledger (including forged-hash and truncation attacks), the end-to-end engine in deterministic packet time, pcap record/replay, and the web API.

## Team
- Person A: capture/ and decoder/
- Person B: baseline/ and detection/
- Person C: storage/ and the terminal/web interface
- `shared/packet_record.py` is the shared contract - change it only by agreement.

"""
NetLens dashboard - one command, one browser tab.

    python app.py                       open the dashboard; pick Live / Simulation / Replay in the browser
    python app.py --live                start capturing your hotspot straight away (Administrator + Npcap)
    python app.py --live --iface "Local Area Connection* 3"
    python app.py --sim                 start the clearly-labelled simulation straight away
    python app.py --pcap capture.pcap   replay a saved capture
    python app.py --list-interfaces

Nothing runs until a source is chosen, and there is no mock data unless you pick
Simulation. Simulation feeds RAW FRAMES through the real decoder, flow tracker,
baseline learner, detection rules and signed ledger - only the source of the
bytes differs from a live run, and the UI says "SIMULATION" in its header.
Live sessions are recorded to captures/*.pcap so they can be replayed offline.
"""

from __future__ import annotations

import argparse
import sys
import threading
import webbrowser
from pathlib import Path

from engine.engine import Engine
from sim.scenario import Simulator
from web.server import App, serve

DEMO_DB = Path(__file__).resolve().parent / "storage" / "netlens_demo.db"


def _replay_external(app: App, path: str, speed: float) -> None:
    """Replay a pcap from anywhere on disk (the web UI itself only offers files in captures/)."""
    from capture.pcap_io import replay_pcap

    app._begin("packet", f"Replay - {Path(path).name}")
    app.engine.run_source(replay_pcap(Path(path), speed), "pcap")


def main() -> int:
    parser = argparse.ArgumentParser(description="NetLens - packet analysis and anomaly detection dashboard.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true", help="capture live traffic (Administrator + Npcap required)")
    mode.add_argument("--sim", action="store_true", help="start the simulation immediately")
    mode.add_argument("--pcap", metavar="FILE", help="replay a pcap file instead of capturing")
    parser.add_argument("--iface", default=None, help="capture interface (with --live)")
    parser.add_argument("--list-interfaces", action="store_true", help="list capture interfaces and exit")
    parser.add_argument("--window", type=float, default=4.0, help="detection window in seconds (default 4)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: this machine only)")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--rate", type=float, default=1.0, help="simulation traffic rate multiplier")
    parser.add_argument("--seed", type=int, default=None, help="simulation random seed (repeatable demo)")
    parser.add_argument("--speed", type=float, default=1.0, help="pcap replay speed multiplier")
    args = parser.parse_args()

    if args.list_interfaces:
        from web.system import list_interfaces

        for iface in (i for i in list_interfaces() if not i['noise']):
            tag = '  <- hotspot' if iface['recommended'] else ''
            print(f"{iface['name']}  -  {iface['description']}  {' '.join(iface['ips'])}{tag}")
        return 0

    engine = Engine(db_path=DEMO_DB, window_seconds=args.window, time_source="wall")
    simulator = Simulator(seed=args.seed, rate=args.rate)
    app = App(engine, simulator)
    engine.start_ticker()

    try:
        if args.live:
            app.use_live(args.iface)
        elif args.sim:
            app.use_simulator()
        elif args.pcap:
            _replay_external(app, args.pcap, args.speed)
    except (PermissionError, RuntimeError, ValueError) as exc:
        print(f"Could not start: {exc}\nThe dashboard will open so you can pick another source.")

    server, port = serve(app, args.host, args.port)
    url = f"http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{port}"
    print(f"NetLens dashboard running at {url}  (mode: {engine.mode})  - Ctrl+C to stop")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        engine.shutdown()
        server.server_close()
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

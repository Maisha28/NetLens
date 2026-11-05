"""
NetLens web dashboard server - standard library only.

No Flask, no CDN, no fonts fetched: the whole UI is served from web/static/, so
the demo works with the network unplugged (the project's "no API can fail on
demo day" rule applies to the front end too).

    GET  /                       the landing page;  GET /dashboard  the single-page dashboard
    GET  /api/state              full snapshot (hosts, conversations, TLS, alerts, ...)
    GET  /api/feed?since=N       packets newer than sequence N
    GET  /api/packet/<seq>       field-by-field decode of one frame (Packet Lab)
    GET  /api/ledger             sealed alert ledger + live verification
    POST /api/ledger/verify|tamper|restore
    POST /api/scenario           {"name": "port_scan"} stage a scenario (simulation only)
    POST /api/control            {"action": "pause"|"resume"|"reset"}
    POST /api/source             {"mode": "sim"|"live", "iface": "..."}
    GET  /api/system             Administrator / Npcap / hotspot-adapter checks + saved recordings
    POST /api/source  (modes)    live | sim | pcap | stop  - switching always starts from a clean slate
    GET  /api/report             downloadable JSON evidence bundle
    GET  /api/security           per-device security grades (A-F) with every deduction explained
    GET  /api/tuning/info        recordings that can be studied + the detector's tunable settings
    POST /api/tuning/benchmark   (re)generate the labelled benchmark recording
    POST /api/tuning/run         {"kind": "study"|"sweep"|"holdout", "capture": "...", "param": "..."}
    GET  /api/tuning/job         progress / result of the running study
"""

from __future__ import annotations

import json
import mimetypes
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from capture.pcap_io import PcapRecorder, list_captures, replay_pcap, resolve_capture
from engine.engine import Engine
from sim.scenario import SCENARIOS, Simulator
from tuning.lab import TuningLab
from web import system

STATIC_DIR = Path(__file__).resolve().parent / "static"


class App:
    """Owns the engine, the simulator, and which of them is feeding the pipeline."""

    def __init__(self, engine: Engine, simulator: Optional[Simulator], frame_source: Optional[Callable] = None) -> None:
        self.engine = engine
        self.sim = simulator
        engine.simulator = simulator
        self.frame_source = frame_source
        self.recorder: Optional[PcapRecorder] = None
        self.lab = TuningLab()
        self.started = time.time()

    # --- source switching -------------------------------------------------

    def _begin(self, time_source: str, label: str) -> None:
        """Start of every switch: stop the old source's side effects and begin from a clean
        slate, so simulated and real data can never be mixed on one dashboard."""
        if self.recorder is not None:
            self.recorder.close()
            self.recorder = None
        if self.sim is not None:
            self.sim.pause(True)
        self.engine.paused = False
        self.engine.set_time_source(time_source)
        self.engine.reset()
        self.engine.meta.update({"iface": None, "record": None, "label": label})

    def use_simulator(self) -> None:
        if self.sim is None:
            self.sim = Simulator()
            self.engine.simulator = self.sim
        self._begin("wall", "Simulation")
        self.sim.pause(False)
        self.engine.run_source(self.sim.stream(), "sim")

    def use_live(self, iface: Optional[str]) -> None:
        from capture.capture import capture_packets

        check = system.system_check()
        if not check["admin"]:
            raise PermissionError(
                "NetLens must be started from an Administrator terminal to capture packets. "
                "Close it, open PowerShell as Administrator, and run `python app.py` again."
            )
        if not check["npcap"]:
            raise RuntimeError(
                "Npcap is not installed. Install it from https://npcap.com with "
                "'WinPcap API-compatible Mode' ticked, then try again."
            )
        iface = iface or check["recommended"]
        if not iface:
            raise RuntimeError(
                "No capture interface selected. Turn on the Windows Mobile Hotspot and pick its adapter."
            )

        self._begin("wall", f"Live capture - {iface}")
        recorder = PcapRecorder()
        self.recorder = recorder
        self.engine.meta.update({"iface": iface, "record": recorder.path.name, "self_ips": check["self_ips"]})

        def frames():
            for raw, ts in capture_packets(iface=iface):
                recorder.write(raw, ts)
                yield raw, ts

        self.engine.run_source(frames(), "live")

    def use_pcap(self, name: str, speed: float = 1.0) -> None:
        path = resolve_capture(name)
        self._begin("packet", f"Replay - {path.name}")
        self.engine.meta.update({"record": path.name})
        self.engine.run_source(replay_pcap(path, speed), "pcap")

    def use_standby(self) -> None:
        self._begin("wall", "")
        self.engine.run_source(iter(()), "idle")
        self.engine.mode = "idle"

    def recordings(self) -> list:
        return list_captures()

    # --- actions ----------------------------------------------------------

    def control(self, action: str) -> dict:
        if action == "pause":
            self.engine.paused = True
            if self.sim:
                self.sim.pause(True)
        elif action == "resume":
            self.engine.paused = False
            if self.sim and self.engine.mode == "sim":
                self.sim.pause(False)
        elif action == "reset":
            self.engine.reset()
        else:
            raise ValueError(f"unknown action {action!r}")
        return {"ok": True, "paused": self.engine.paused}

    def state(self) -> dict:
        snap = self.engine.snapshot()
        snap["sim"] = self.sim.status() if self.sim and snap["mode"] == "sim" else None
        snap["scenarios"] = SCENARIOS if snap["mode"] == "sim" else {}
        snap["server_time"] = time.time()
        return snap


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "NetLens"

        def log_message(self, fmt, *args):  # keep the terminal clean for the presenter
            pass

        # --- helpers ---------------------------------------------------------

        def _send(self, status: int, body: bytes, content_type: str, extra: Optional[dict] = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _json(self, payload, status: int = 200, extra: Optional[dict] = None) -> None:
            self._send(status, json.dumps(payload, default=str).encode(), "application/json; charset=utf-8", extra)

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return {}
            try:
                return json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return {}

        def _static(self, path: str) -> None:
            if path in ("", "/"):
                rel = "landing.html"          # the welcome page
            elif path.rstrip("/") == "/dashboard":
                rel = "index.html"            # the application
            else:
                rel = path.lstrip("/").removeprefix("static/")
            target = (STATIC_DIR / rel).resolve()
            if STATIC_DIR not in target.parents and target != STATIC_DIR:
                return self._json({"error": "forbidden"}, 403)
            if not target.is_file():
                return self._json({"error": "not found"}, 404)
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
                ctype += "; charset=utf-8"
            self._send(200, target.read_bytes(), ctype)

        # --- routes ------------------------------------------------------------

        def do_GET(self) -> None:
            url = urlparse(self.path)
            query = parse_qs(url.query)
            path = url.path
            try:
                if path == "/api/state":
                    return self._json(app.state())
                if path == "/api/feed":
                    since = int(query.get("since", ["0"])[0])
                    return self._json(app.engine.packets_since(since))
                if path.startswith("/api/packet/"):
                    detail = app.engine.frame_detail(int(path.rsplit("/", 1)[1]))
                    return self._json(detail or {"error": "frame no longer in the buffer"}, 200 if detail else 404)
                if path == "/api/alerts":
                    return self._json(app.engine.alerts_since(int(query.get("after", ["0"])[0])))
                if path == "/api/ledger":
                    return self._json(
                        {"entries": app.engine.ledger.entries(120), "verification": app.engine.ledger.verify(),
                         "count": app.engine.ledger.count}
                    )
                if path == "/api/security":
                    return self._json(app.engine.security_report())
                if path == "/api/tuning/info":
                    return self._json(app.lab.info())
                if path == "/api/tuning/job":
                    return self._json(app.lab.job())
                if path == "/api/system":
                    return self._json({**system.system_check(), "recordings": app.recordings(),
                                       "mode": app.engine.mode, "meta": app.engine.meta})
                if path == "/api/report":
                    stamp = time.strftime("%Y%m%d-%H%M%S")
                    return self._json(
                        app.engine.report(),
                        extra={"Content-Disposition": f'attachment; filename="netlens-evidence-{stamp}.json"'},
                    )
                if path.startswith("/api/"):
                    return self._json({"error": "unknown endpoint"}, 404)
                return self._static(path)
            except (ValueError, KeyError) as exc:
                return self._json({"error": str(exc)}, 400)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            body = self._body()
            try:
                if path == "/api/scenario":
                    if app.engine.mode != "sim" or app.sim is None:
                        return self._json({"error": "Scenarios are staged only in simulation mode."}, 409)
                    return self._json(app.sim.trigger(body.get("name", "")))
                if path == "/api/tuning/benchmark":
                    return self._json(app.lab.generate_benchmark())
                if path == "/api/tuning/run":
                    return self._json(app.lab.start(body.get("kind", ""), body.get("capture", ""), body.get("param")))
                if path == "/api/control":
                    return self._json(app.control(body.get("action", "")))
                if path == "/api/source":
                    mode = body.get("mode")
                    if mode == "live":
                        app.use_live(body.get("iface"))
                    elif mode == "sim":
                        app.use_simulator()
                    elif mode == "pcap":
                        app.use_pcap(body.get("file", ""), float(body.get("speed", 1.0)))
                    elif mode == "stop":
                        app.use_standby()
                    else:
                        return self._json({"error": "mode must be live, sim, pcap or stop"}, 400)
                    return self._json({"ok": True, "mode": app.engine.mode})
                if path == "/api/ledger/verify":
                    return self._json(app.engine.ledger.verify())
                if path == "/api/ledger/tamper":
                    result = app.engine.ledger.tamper(body.get("idx"))
                    if result is None:
                        return self._json({"error": "No sealed alerts yet - stage a scenario first."}, 409)
                    return self._json({**result, "verification": app.engine.ledger.verify()})
                if path == "/api/ledger/restore":
                    restored = app.engine.ledger.restore()
                    return self._json({"restored": restored, "verification": app.engine.ledger.verify()})
                return self._json({"error": "unknown endpoint"}, 404)
            except KeyError as exc:
                return self._json({"error": f"unknown scenario {exc}"}, 400)
            except (ValueError, PermissionError, RuntimeError) as exc:
                return self._json({"error": str(exc)}, 400 if isinstance(exc, ValueError) else 409)

    return Handler


def serve(app: App, host: str = "127.0.0.1", port: int = 8765) -> Tuple[ThreadingHTTPServer, int]:
    """Bind (trying the next few ports if busy) and return the server; caller runs serve_forever()."""
    last_error: Optional[Exception] = None
    for candidate in range(port, port + 10):
        try:
            server = ThreadingHTTPServer((host, candidate), make_handler(app))
            server.daemon_threads = True
            return server, server.server_address[1]
        except OSError as exc:
            last_error = exc
    raise OSError(f"no free port in {port}-{port + 9}: {last_error}")

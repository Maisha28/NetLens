"""
The Tuning Lab: replay ONE recording under different detector settings and score
every alert against ground truth.

Scoring (per alert, using the recording's labels):
  caught   - first alert for an attack event (right rule, right device, right time)
  repeat   - a further alert for an event already caught (noise, not a new catch)
  false    - an alert for a harmless event, or for nothing at all

Per event: an attack is "caught" or "missed"; a harmless event is "quiet" (good)
or "false alarm". From those: attacks caught of attacks, false alarms, repeats.

The whole study replays the same decoded packets, so the ONLY thing that changes
between runs is the settings - which is what makes the comparison a measurement.
"""

from __future__ import annotations

import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from capture.pcap_io import CAPTURE_DIR, replay_pcap, resolve_capture
from decoder.decoder import decode
from engine.engine import Engine
from engine.params import DEFAULT_PARAMS, NAIVE_PARAMS, PARAM_INFO, EngineParams, study_configs
from tuning.benchmark import BENCHMARK_NAME, WINDOW, build_benchmark, load_labels, write_benchmark

# One-parameter sweeps offered in the UI (all other settings stay at the defaults).
SWEEPS: Dict[str, List[float]] = {
    "hog_multiplier": [1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 8.0, 12.0],
    "scan_min_ports": [3, 5, 10, 15, 25, 50, 100, 200],
    "hog_min_observed_per_s": [0, 5000, 15000, 20000, 40000, 100000, 200000, 300000],
}

_KEY_DIR = Path(tempfile.mkdtemp(prefix="netlens-lab-"))


# ------------------------------------------------------------------- scoring


def score_alerts(alerts: List[dict], labels: List[dict], window: float) -> dict:
    """Judge each alert against the labelled events and summarise."""
    slack = window * 1.5
    attacks = [l for l in labels if l["kind"] == "attack"]
    caught: Dict[str, float] = {}
    outcomes: Dict[str, dict] = {l["id"]: {"alerts": 0, "flagged": 0} for l in labels}
    judged = []

    def matches(alert, label):
        if alert["rule"] != label["rule"]:
            return False
        if label.get("host") not in (None, alert["host"]):
            return False
        return label["start"] - slack <= alert["ts"] <= label["end"] + slack

    for a in sorted(alerts, key=lambda a: a["ts"]):
        hit_attack = next((l for l in attacks if matches(a, l)), None)
        hit_benign = next((l for l in labels if l["kind"] == "benign" and matches(a, l)), None)
        if hit_attack:
            outcomes[hit_attack["id"]]["alerts"] += 1
            # an alert record also stands for the identical alerts it suppressed (its "repeats"),
            # so this counts how many windows of the attack were actually flagged
            outcomes[hit_attack["id"]]["flagged"] += 1 + int(a.get("repeats", 0))
            if hit_attack["id"] not in caught:
                caught[hit_attack["id"]] = a["ts"] - hit_attack["start"]
                verdict, label = "caught", hit_attack
            else:
                verdict, label = "repeat", hit_attack
        elif hit_benign:
            outcomes[hit_benign["id"]]["alerts"] += 1
            verdict, label = "false", hit_benign
        else:
            verdict, label = "false", None
        judged.append({
            "t": a["ts"], "rule": a["rule"], "host": a["host"], "message": a["message"], "verdict": verdict,
            "label": label["title"] if label else None,
            "reason": ("matches the attack it should catch" if verdict == "caught" else
                       "another alert for an attack already caught" if verdict == "repeat" else
                       f"harmless event: {label['title']}" if label else "no attack or known event at this time"),
        })

    events = []
    for l in labels:
        n = outcomes[l["id"]]["alerts"]
        if l["kind"] == "attack":
            outcome = "caught" if l["id"] in caught else "missed"
        else:
            outcome = "false_alarm" if n else "quiet"
        span = max(1, round((l["end"] - l["start"]) / window))
        flagged = min(span, outcomes[l["id"]]["flagged"]) if l["kind"] == "attack" else None
        events.append({**{k: l[k] for k in ("id", "kind", "rule", "host", "title", "why", "start", "end")},
                       "outcome": outcome, "alerts": n, "delay": round(caught[l["id"]], 1) if l["id"] in caught else None,
                       "windows": span, "flagged": flagged})

    false_alarms = sum(1 for j in judged if j["verdict"] == "false")
    repeats = sum(1 for j in judged if j["verdict"] == "repeat")
    n_caught, n_attacks = len(caught), len(attacks)
    attack_events = [e for e in events if e["kind"] == "attack"]
    total_windows = sum(e["windows"] for e in attack_events)
    flagged_windows = sum(e["flagged"] for e in attack_events)
    return {
        "coverage": round(flagged_windows / total_windows, 3) if total_windows else None,
        "alerts": len(judged), "caught": n_caught, "attacks": n_attacks, "missed": n_attacks - n_caught,
        "false_alarms": false_alarms, "repeats": repeats,
        "recall": round(n_caught / n_attacks, 3) if n_attacks else None,
        "precision": round(n_caught / (n_caught + false_alarms), 3) if (n_caught + false_alarms) else None,
        "events": events, "judged": judged,
    }


# ---------------------------------------------------------------- replaying


class LoadedCapture:
    def __init__(self, name: str, records: list, labels: Optional[List[dict]], window: float) -> None:
        self.name, self.records, self.labels, self.window = name, records, labels, window


_CACHE: Dict[Tuple[str, float], LoadedCapture] = {}


def load_capture(name: str, window: float = WINDOW) -> LoadedCapture:
    """Decode a recording once and cache it; every run re-uses the same PacketRecords."""
    path = resolve_capture(name)
    key = (f"{path.name}:{path.stat().st_mtime}", window)
    if key not in _CACHE:
        records = [decode(raw, ts) for raw, ts in replay_pcap(path, speed=0)]
        _CACHE.clear()
        _CACHE[key] = LoadedCapture(path.name, records, load_labels(path), window)
    return _CACHE[key]


def run_once(cap: LoadedCapture, params: EngineParams) -> dict:
    """Replay the capture under `params`; return the scored result (or raw counts when unlabelled)."""
    engine = Engine(db_path=Path(":memory:"), window_seconds=cap.window, time_source="packet",
                    key_path=_KEY_DIR / "key", fresh=True, params=params, lite=True)
    try:
        for rec in cap.records:
            engine.ingest(rec)
        if cap.records:
            engine.tick(cap.records[-1].timestamp + cap.window)
        alerts = list(engine.alerts)
    finally:
        engine.shutdown()
    if cap.labels is None:
        return {"alerts": len(alerts), "caught": None, "attacks": None, "missed": None, "false_alarms": None,
                "repeats": None, "recall": None, "precision": None, "events": [],
                "judged": [{"t": a["ts"], "rule": a["rule"], "host": a["host"], "message": a["message"],
                            "verdict": "unlabelled", "label": None, "reason": "this recording has no labels file"} for a in alerts]}
    return score_alerts(alerts, cap.labels, cap.window)


def _slim(result: dict) -> dict:
    return {k: v for k, v in result.items() if k not in ("events", "judged")}


def run_study(cap: LoadedCapture, progress: Callable[[int, int], None]) -> dict:
    steps = study_configs()
    rows = []
    for i, (title, why, params) in enumerate(steps):
        res = run_once(cap, params)
        rows.append({"title": title, "why": why, "params": params.to_dict(), **_slim(res)})
        progress(i + 1, len(steps))
    final = run_once(cap, DEFAULT_PARAMS)
    return {"kind": "study", "capture": cap.name, "labelled": cap.labels is not None, "steps": rows,
            "detail": {"events": final["events"], "judged": final["judged"]},
            "naive_detail": {"judged": run_once(cap, NAIVE_PARAMS)["judged"]}}


def run_sweep(cap: LoadedCapture, param: str, values: List[float], progress: Callable[[int, int], None]) -> dict:
    if param not in PARAM_INFO:
        raise ValueError(f"unknown parameter {param!r}")
    points = []
    for i, v in enumerate(values):
        res = run_once(cap, DEFAULT_PARAMS.with_changes(**{param: type(getattr(DEFAULT_PARAMS, param))(v)}))
        points.append({"value": v, **_slim(res)})
        progress(i + 1, len(values))
    title, why = PARAM_INFO[param]
    return {"kind": "sweep", "capture": cap.name, "labelled": cap.labels is not None, "param": param, "title": title,
            "why": why, "default": getattr(DEFAULT_PARAMS, param), "points": points}


HOLDOUT_SEEDS = [11, 23, 42, 99, 123]  # never used while choosing the defaults (those were tuned on seed 7)


def run_holdout(progress: Callable[[int, int], None], seeds: Optional[List[int]] = None) -> dict:
    """
    Overfitting check: the defaults were chosen on one benchmark, so score them on
    brand-new traffic (same kinds of events, different random seeds) and compare with
    the untuned detector on the same data.
    """
    rows = []
    seeds = seeds or HOLDOUT_SEEDS
    for i, seed in enumerate(seeds):
        frames, labels = build_benchmark(seed)
        cap = LoadedCapture(f"seed {seed}", [decode(raw, ts) for ts, raw in frames], labels, WINDOW)
        tuned, naive = run_once(cap, DEFAULT_PARAMS), run_once(cap, NAIVE_PARAMS)
        rows.append({"seed": seed, "tuned": _slim(tuned), "naive": _slim(naive)})
        progress(i + 1, len(seeds))
    total = lambda who, key: sum(r[who][key] for r in rows)
    return {"kind": "holdout", "seeds": rows, "totals": {
        "attacks": total("tuned", "attacks"),
        "tuned": {"caught": total("tuned", "caught"), "false_alarms": total("tuned", "false_alarms"), "alerts": total("tuned", "alerts")},
        "naive": {"caught": total("naive", "caught"), "false_alarms": total("naive", "false_alarms"), "alerts": total("naive", "alerts")}}}


# ---------------------------------------------------------------- background job


class TuningLab:
    """Runs studies on a worker thread so the dashboard can show progress."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._job: dict = {"status": "idle"}

    def info(self) -> dict:
        caps = []
        if CAPTURE_DIR.exists():
            for p in sorted(CAPTURE_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)[:20]:
                caps.append({"name": p.name, "size": p.stat().st_size, "labelled": load_labels(p) is not None,
                             "benchmark": p.stem == BENCHMARK_NAME})
        return {"captures": caps, "sweeps": {k: {"values": v, "title": PARAM_INFO[k][0], "why": PARAM_INFO[k][1]} for k, v in SWEEPS.items()},
                "defaults": DEFAULT_PARAMS.to_dict(), "naive": NAIVE_PARAMS.to_dict(),
                "param_info": {k: {"title": t, "why": w} for k, (t, w) in PARAM_INFO.items()}}

    def job(self) -> dict:
        with self._lock:
            return dict(self._job)

    def generate_benchmark(self) -> dict:
        path = write_benchmark(CAPTURE_DIR)
        _CACHE.clear()
        return {"name": path.name}

    def start(self, kind: str, capture: str, param: Optional[str] = None) -> dict:
        with self._lock:
            if self._job.get("status") == "running":
                raise RuntimeError("A study is already running - wait for it to finish.")
            if kind != "holdout":
                resolve_capture(capture)  # validates the name before starting a thread
            if kind == "sweep" and param not in SWEEPS:
                raise ValueError(f"unknown sweep {param!r}")
            if kind not in ("study", "sweep", "holdout"):
                raise ValueError("kind must be 'study', 'sweep' or 'holdout'")
            self._job = {"status": "running", "kind": kind, "param": param, "done": 0, "total": 1, "started": time.time()}

        def progress(done: int, total: int) -> None:
            with self._lock:
                self._job.update(done=done, total=total)

        def work() -> None:
            try:
                if kind == "holdout":
                    result = run_holdout(progress)
                else:
                    cap = load_capture(capture)
                    result = run_study(cap, progress) if kind == "study" else run_sweep(cap, param, SWEEPS[param], progress)
                with self._lock:
                    self._job = {"status": "done", "kind": kind, "param": param, "result": result, "seconds": round(time.time() - self._job["started"], 1)}
            except Exception as exc:  # surfaced to the UI instead of dying silently
                with self._lock:
                    self._job = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

        threading.Thread(target=work, daemon=True, name="netlens-tuning").start()
        return self.job()

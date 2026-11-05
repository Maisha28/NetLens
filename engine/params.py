"""
Every tunable setting of the detector, in one place.

The shipped defaults are the values the dashboard runs with. They exist as a
dataclass (not constants scattered through engine.py) so the Tuning Lab can
replay one recording under many settings and measure what each choice does -
the evidence that the thresholds were *engineered*, not guessed.

NAIVE is the "first attempt" detector: low multipliers, no volume floors, every
packet's destination port counted, spikes allowed to teach the baseline, one
learned window, no alert de-duplication. TUNED (the defaults) is what each
step of the before/after study changes it into.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class EngineParams:
    # bandwidth_hog (REQ-25)
    hog_multiplier: float = 3.0            # fire when bytes > this x the host's own baseline
    hog_min_baseline_per_s: float = 1000.0  # baseline must exceed this many bytes/s to mean anything
    hog_min_observed_per_s: float = 40000.0  # ...and the host must move at least this many bytes/s (chosen from the Tuning Lab plateau)
    # port_scan (REQ-26)
    scan_min_ports: int = 15               # absolute floor on distinct destination ports per window
    scan_multiplier: float = 3.0           # ...and at least this x the host's baseline port count
    probe_only: bool = True                # count only connection-opening packets (SYN / UDP-to-service)
    # baseline learning (REQ-22, REQ-23)
    min_windows: int = 3                   # windows of history before a baseline is "ready"
    alpha: float = 0.2                     # EWMA weight of the newest window
    skip_alert_baseline: bool = True       # a window that alerted is not learned from
    # alert hygiene
    cooldown: float = 12.0                 # seconds during which an identical alert is counted, not repeated

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)

    def with_changes(self, **changes) -> "EngineParams":
        return replace(self, **changes)

    @staticmethod
    def from_dict(data: Dict) -> "EngineParams":
        known = EngineParams.__dataclass_fields__
        clean = {}
        for key, value in (data or {}).items():
            if key not in known:
                raise ValueError(f"unknown parameter {key!r}")
            default = getattr(DEFAULT_PARAMS, key)
            clean[key] = bool(value) if isinstance(default, bool) else type(default)(value)
        return replace(DEFAULT_PARAMS, **clean)


DEFAULT_PARAMS = EngineParams()

NAIVE_PARAMS = EngineParams(
    hog_multiplier=1.5, hog_min_baseline_per_s=0.0, hog_min_observed_per_s=0.0,
    scan_min_ports=5, scan_multiplier=1.0, probe_only=False,
    min_windows=1, skip_alert_baseline=False, cooldown=0.0,
)

# Human wording for every parameter - the Tuning Lab shows these, not field names.
PARAM_INFO: Dict[str, Tuple[str, str]] = {
    "hog_multiplier": ("Heavy-use multiplier", "Alert when a device uses more than this many times its own normal."),
    "hog_min_baseline_per_s": ("Minimum normal (bytes/s)", "Ignore devices whose normal is below this - too little data to judge."),
    "hog_min_observed_per_s": ("Minimum volume (bytes/s)", "Never call something heavy use unless it moves at least this much."),
    "scan_min_ports": ("Port-scan threshold (ports)", "Alert when a device tries at least this many different ports in one window."),
    "scan_multiplier": ("Port-scan multiplier", "...and at least this many times the ports it normally tries."),
    "probe_only": ("Count only connection attempts", "Count a port only when a device starts a connection to it, not when it replies."),
    "min_windows": ("Windows before alerting", "How many windows a device is watched before alerts are allowed."),
    "skip_alert_baseline": ("Don't learn from alerts", "Stop an attack from teaching NetLens that it is normal."),
    "cooldown": ("Repeat suppression (s)", "Identical alerts within this time are counted instead of repeated."),
}

# The before/after study: start from NAIVE and apply one change at a time, in this
# order, until the shipped defaults are reached. Each step has a measured effect.
def _study_steps() -> List[Tuple[str, str, Dict]]:
    d = DEFAULT_PARAMS
    return [
        ("Untuned first attempt", "Low multipliers, no volume floors, every packet's port counted.", {}),
        ("Count only connection attempts", "A DNS server answering many clients is no longer mistaken for a scanner.", {"probe_only": d.probe_only}),
        (f"Add minimum-volume floors ({d.hog_min_observed_per_s / 1000:g} KB/s)",
         "Small bursts from quiet devices stop counting as heavy use.",
         {"hog_min_baseline_per_s": d.hog_min_baseline_per_s, "hog_min_observed_per_s": d.hog_min_observed_per_s}),
        (f"Raise thresholds ({d.hog_multiplier:g}x, {d.scan_min_ports} ports)",
         "Ordinary variation and harmless discovery traffic stop alerting.",
         {"hog_multiplier": d.hog_multiplier, "scan_multiplier": d.scan_multiplier, "scan_min_ports": d.scan_min_ports}),
        (f"Require {d.min_windows} learned windows", "No alerts from a device's first few packets.", {"min_windows": d.min_windows}),
        ("Don't learn from alerts",
         "A sustained attack can no longer raise its own baseline, so every window of it stays flagged. Trade-off: a sustained harmless event keeps alerting until repeats are suppressed.",
         {"skip_alert_baseline": d.skip_alert_baseline}),
        (f"Suppress repeats ({d.cooldown:g} s)", "One event, one alert - not one per window.", {"cooldown": d.cooldown}),
    ]


STUDY_STEPS = _study_steps()


def study_configs() -> List[Tuple[str, str, EngineParams]]:
    """Cumulative parameter sets for the before/after study."""
    out = []
    current = NAIVE_PARAMS
    for title, why, changes in STUDY_STEPS:
        current = current.with_changes(**changes) if changes else current
        out.append((title, why, current))
    assert out[-1][2] == DEFAULT_PARAMS, "the final study step must equal the shipped defaults"
    return out

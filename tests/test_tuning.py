"""
Tests for the Tuning Lab: the parameterised engine, the labelled benchmark, the
alert-scoring logic, the before/after study, sweeps, the held-out check and the
background job API.
"""

import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from decoder.decoder import decode
from engine.engine import Engine
from engine.params import DEFAULT_PARAMS, NAIVE_PARAMS, EngineParams, study_configs
from sim import frames as F
from sim.scenario import GATEWAY, LAPTOP2, PHONE, SITES, Simulator
from tuning import lab
from tuning.benchmark import WINDOW, build_benchmark
from tuning.lab import LoadedCapture, run_holdout, run_once, run_study, run_sweep, score_alerts


# ---------------------------------------------------------------- shared fixture


@pytest.fixture(scope="module")
def cap():
    frames, labels = build_benchmark(7)
    return LoadedCapture("seed 7", [decode(raw, ts) for ts, raw in frames], labels, WINDOW)


# --------------------------------------------------------------------- params


def test_study_ends_exactly_at_the_shipped_defaults_and_starts_naive():
    configs = study_configs()
    assert configs[0][2] == NAIVE_PARAMS
    assert configs[-1][2] == DEFAULT_PARAMS
    assert len({c[2] for c in configs}) == len(configs)  # every step really changes something


def test_params_from_dict_validates_and_coerces():
    p = EngineParams.from_dict({"hog_multiplier": "4", "probe_only": 0, "scan_min_ports": 20.0})
    assert (p.hog_multiplier, p.probe_only, p.scan_min_ports) == (4.0, False, 20)
    with pytest.raises(ValueError):
        EngineParams.from_dict({"nonsense": 1})


def _tmp_engine(tmp_path, params):
    return Engine(db_path=tmp_path / "e.db", window_seconds=4.0, time_source="packet", key_path=tmp_path / "k", params=params)


def _warm_and_hog(engine, k):
    sim = Simulator(seed=2)
    t = 1_000_000.0
    for w in range(6):
        for n in range(3):
            for off, raw in sim._tls_session(PHONE, SITES[1], 0, 12):
                engine.ingest_frame(raw, t + n * 1.2 + off)
        t += 4.0
    engine.tick(t)
    engine._window_end = t + 4.0
    ip = SITES[1][1]
    for i in range(k):
        engine.ingest_frame(F.tcp_frame(GATEWAY.mac, PHONE.mac, ip, PHONE.ip, 443, 41000, i, 1, F.TCP_ACK, b"x" * 1400), t + i * 0.002)
    engine.tick(t + 4.0)
    return engine


def test_hog_multiplier_parameter_really_controls_the_alert(tmp_path):
    loud = _warm_and_hog(_tmp_engine(tmp_path, DEFAULT_PARAMS), 1500)
    assert any(a["rule"] == "bandwidth_hog" for a in loud.alerts)
    strict = Engine(db_path=tmp_path / "s.db", window_seconds=4.0, time_source="packet", key_path=tmp_path / "k2",
                    params=DEFAULT_PARAMS.with_changes(hog_multiplier=500.0))
    _warm_and_hog(strict, 1500)
    assert not any(a["rule"] == "bandwidth_hog" for a in strict.alerts)


def test_baseline_min_windows_parameter(tmp_path):
    eng = Engine(db_path=tmp_path / "m.db", window_seconds=4.0, time_source="packet", key_path=tmp_path / "k",
                 params=DEFAULT_PARAMS.with_changes(min_windows=1))
    assert eng.tracker.min_samples == 1


# ------------------------------------------------------------------ benchmark


def test_benchmark_is_deterministic_and_well_formed():
    f1, l1 = build_benchmark(7)
    f2, l2 = build_benchmark(7)
    assert len(f1) == len(f2) and l1 == l2
    assert [t for t, _ in f1] == sorted(t for t, _ in f1)
    ids = [l["id"] for l in l1]
    assert len(ids) == len(set(ids))  # unique ids (a past bug)
    assert sum(1 for l in l1 if l["kind"] == "attack") == 7
    assert sum(1 for l in l1 if l["kind"] == "benign") == 5
    assert {l["rule"] for l in l1} == {"port_scan", "bandwidth_hog", "arp_spoof"}
    assert len(build_benchmark(8)[0]) != len(f1)  # a different seed gives different traffic


# -------------------------------------------------------------------- scoring


def _label(id, kind, rule, host, start, end):
    return {"id": id, "kind": kind, "rule": rule, "host": host, "title": id, "why": "", "start": start, "end": end}


def _alert(rule, host, ts, repeats=0):
    return {"rule": rule, "host": host, "ts": ts, "message": "m", "repeats": repeats}


def test_scoring_classifies_every_outcome():
    labels = [
        _label("a1", "attack", "port_scan", "h1", 100, 108),
        _label("a2", "attack", "bandwidth_hog", "h2", 200, 208),
        _label("a3", "attack", "arp_spoof", "gw", 300, 301),
        _label("b1", "benign", "bandwidth_hog", "h3", 400, 404),
        _label("b2", "benign", "port_scan", "h4", 500, 504),
    ]
    alerts = [
        _alert("port_scan", "h1", 101), _alert("port_scan", "h1", 105),   # caught + repeat
        _alert("bandwidth_hog", "h3", 402),                               # false: harmless event
        _alert("bandwidth_hog", "h9", 900),                               # false: nothing there
    ]
    r = score_alerts(alerts, labels, 4.0)
    verdicts = [j["verdict"] for j in r["judged"]]
    assert verdicts == ["caught", "repeat", "false", "false"]
    assert (r["caught"], r["attacks"], r["missed"]) == (1, 3, 2)
    assert (r["false_alarms"], r["repeats"], r["alerts"]) == (2, 1, 4)
    outcome = {e["id"]: e["outcome"] for e in r["events"]}
    assert outcome == {"a1": "caught", "a2": "missed", "a3": "missed", "b1": "false_alarm", "b2": "quiet"}
    assert r["recall"] == pytest.approx(1 / 3, abs=1e-3) and r["precision"] == pytest.approx(1 / 3, abs=1e-3)


def test_scoring_requires_the_right_device_and_time():
    labels = [_label("a1", "attack", "port_scan", "h1", 100, 108)]
    wrong_host = score_alerts([_alert("port_scan", "h2", 101)], labels, 4.0)
    too_late = score_alerts([_alert("port_scan", "h1", 200)], labels, 4.0)
    assert wrong_host["caught"] == 0 and too_late["caught"] == 0
    assert wrong_host["false_alarms"] == 1 and too_late["false_alarms"] == 1


def test_flagged_windows_count_suppressed_repeats():
    labels = [_label("a1", "attack", "bandwidth_hog", "h1", 100, 124)]  # 6 windows
    r = score_alerts([_alert("bandwidth_hog", "h1", 101, repeats=2), _alert("bandwidth_hog", "h1", 113, repeats=1)], labels, 4.0)
    ev = r["events"][0]
    assert ev["windows"] == 6 and ev["flagged"] == 5 and r["coverage"] == pytest.approx(5 / 6, abs=1e-3)


# --------------------------------------------------------------- the study


def test_tuned_defaults_beat_the_untuned_detector_on_the_benchmark(cap):
    tuned, naive = run_once(cap, DEFAULT_PARAMS), run_once(cap, NAIVE_PARAMS)
    assert tuned["caught"] == tuned["attacks"] == 7
    assert tuned["false_alarms"] <= 1
    assert naive["false_alarms"] >= 20 * max(1, tuned["false_alarms"])
    assert tuned["alerts"] < naive["alerts"] / 4
    assert run_once(cap, DEFAULT_PARAMS) == tuned  # deterministic: same input, same result


def test_study_reports_every_step_and_ends_at_the_defaults(cap):
    seen = []
    st = run_study(cap, lambda d, t: seen.append((d, t)))
    assert len(st["steps"]) == 7 and seen[-1] == (7, 7)
    assert st["steps"][0]["false_alarms"] > st["steps"][-1]["false_alarms"]
    final = run_once(cap, DEFAULT_PARAMS)
    assert st["steps"][-1]["alerts"] == final["alerts"] and st["steps"][-1]["false_alarms"] == final["false_alarms"]
    assert len(st["detail"]["events"]) == 12 and st["detail"]["judged"]
    # "don't learn from alerts" is what keeps a sustained attack flagged (baseline poisoning defence)
    learn_step, no_learn_step = st["steps"][4], st["steps"][5]
    assert no_learn_step["coverage"] > learn_step["coverage"]
    json.dumps(st)  # the whole result must be JSON-serialisable for the API


def test_sweeps_show_the_trade_off(cap):
    sw = run_sweep(cap, "hog_multiplier", [1.5, 3.0, 12.0], lambda d, t: None)
    low, mid, high = sw["points"]
    assert low["false_alarms"] > mid["false_alarms"]   # too sensitive -> harmless events trip it
    assert high["missed"] > mid["missed"]              # too strict -> real attacks slip through
    assert mid["missed"] == 0
    scan = run_sweep(cap, "scan_min_ports", [3, 15, 200], lambda d, t: None)
    assert scan["points"][2]["missed"] > scan["points"][1]["missed"]
    with pytest.raises(ValueError):
        run_sweep(cap, "not_a_setting", [1], lambda d, t: None)


def test_holdout_scores_unseen_traffic():
    res = run_holdout(lambda d, t: None, seeds=[11, 23])
    t = res["totals"]
    assert t["attacks"] == 14 and t["tuned"]["caught"] >= 12
    assert t["naive"]["false_alarms"] > 10 * max(1, t["tuned"]["false_alarms"])


def test_unlabelled_capture_counts_alerts_but_cannot_judge(cap):
    bare = LoadedCapture("bare", cap.records, None, WINDOW)
    r = run_once(bare, DEFAULT_PARAMS)
    assert r["alerts"] > 0 and r["caught"] is None and r["judged"][0]["verdict"] == "unlabelled"


# ------------------------------------------------------------- job API


@pytest.fixture
def lab_server(tmp_path, monkeypatch):
    import capture.pcap_io as pcap_io
    from web.server import App, serve

    cdir = tmp_path / "captures"
    monkeypatch.setattr(pcap_io, "CAPTURE_DIR", cdir)
    monkeypatch.setattr(lab, "CAPTURE_DIR", cdir)
    lab._CACHE.clear()
    eng = Engine(db_path=tmp_path / "w.db", window_seconds=4.0, time_source="wall", key_path=tmp_path / "k")
    app = App(eng, Simulator(seed=1))
    httpd, port = serve(app, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown(); httpd.server_close(); eng.shutdown()


def _get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _wait(base, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        job = _get(base + "/api/tuning/job")
        if job["status"] != "running":
            return job
        time.sleep(0.2)
    raise AssertionError("tuning job did not finish")


def test_tuning_api_lifecycle(lab_server):
    base = lab_server
    info = _get(base + "/api/tuning/info")
    assert info["captures"] == [] and "hog_multiplier" in info["sweeps"] and info["defaults"]["scan_min_ports"] == 15

    assert _post(base + "/api/tuning/benchmark", {})[0] == 200
    info = _get(base + "/api/tuning/info")
    assert info["captures"][0]["benchmark"] and info["captures"][0]["labelled"]

    status, body = _post(base + "/api/tuning/run", {"kind": "study", "capture": "benchmark.pcap"})
    assert status == 200 and body["status"] == "running"
    assert _post(base + "/api/tuning/run", {"kind": "study", "capture": "benchmark.pcap"})[0] == 409  # one at a time
    job = _wait(base)
    assert job["status"] == "done" and len(job["result"]["steps"]) == 7

    assert _post(base + "/api/tuning/run", {"kind": "sweep", "capture": "benchmark.pcap", "param": "hog_multiplier"})[0] == 200
    assert _wait(base)["result"]["param"] == "hog_multiplier"


def test_tuning_api_rejects_bad_requests(lab_server):
    base = lab_server
    assert _post(base + "/api/tuning/run", {"kind": "teleport", "capture": "x.pcap"})[0] == 400
    assert _post(base + "/api/tuning/run", {"kind": "study", "capture": "../../etc/passwd"})[0] == 400
    assert _post(base + "/api/tuning/run", {"kind": "study", "capture": "missing.pcap"})[0] == 400

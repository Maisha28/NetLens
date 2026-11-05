"""Regression tests for the "ValueError: write to closed file" banner after switching source."""

import threading
import time

from capture.pcap_io import PcapRecorder
from engine.engine import Engine


def test_writing_to_a_closed_recorder_is_ignored(tmp_path):
    rec = PcapRecorder(tmp_path, filename="x.pcap")
    rec.write(b"\x00" * 60, 1.0)
    rec.close()
    rec.write(b"\x00" * 60, 2.0)  # used to raise ValueError: write to closed file
    rec.close()                   # closing twice is harmless too


def test_an_old_source_failing_after_a_switch_does_not_blame_the_new_one(tmp_path):
    eng = Engine(db_path=tmp_path / "e.db", window_seconds=4.0, time_source="wall", key_path=tmp_path / "k")
    release = threading.Event()

    def old_source():
        release.wait(5)
        raise ValueError("write to closed file")
        yield  # pragma: no cover - makes this a generator

    old = eng.run_source(old_source(), "live")
    eng.run_source(iter(()), "sim")        # the user switches source; the old one is now stale
    release.set()
    old.join(timeout=5)
    assert eng.source_error is None


def test_a_current_source_failing_is_still_reported(tmp_path):
    eng = Engine(db_path=tmp_path / "e.db", window_seconds=4.0, time_source="wall", key_path=tmp_path / "k")

    def failing():
        raise PermissionError("denied")
        yield  # pragma: no cover

    eng.run_source(failing(), "live").join(timeout=5)
    time.sleep(0.05)
    assert eng.source_error and "Administrator" in eng.source_error

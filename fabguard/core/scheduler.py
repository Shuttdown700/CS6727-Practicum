"""
core/scheduler.py -- one background thread per feature, each on its own interval.

A thread per feature rather than one loop over all of them, so a slow
collector (a repository snapshot over SMB) cannot delay a fast one (a 30
second printer poll). Intervals are measured from the END of a run, so a
collector that takes longer than its interval degrades to back-to-back runs
instead of piling up.

Deliberately not APScheduler: fewer dependencies on the Pi, and the whole
thing fits on a screen.
"""

from __future__ import annotations

import threading
import time

from . import db, eventlog, registry
from .. import config


class Scheduler:
    def __init__(self, features: list[registry.Feature] | None = None):
        self.features = features if features is not None else registry.load_enabled()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.last_run: dict[str, dict] = {}
        self._lock = threading.Lock()

    # -- state the portal reads -------------------------------------------

    def status(self) -> list[dict]:
        out = []
        with self._lock:
            for f in self.features:
                last = self.last_run.get(f.name, {})
                out.append({
                    "name": f.name,
                    "title": f.title,
                    "interval_s": f.interval_s,
                    "last_ts": last.get("ts"),
                    "last_ok": last.get("ok"),
                    "last_summary": last.get("summary", ""),
                    "last_error": last.get("error", ""),
                    "next_in_s": last.get("next_in"),
                })
        return out

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        eventlog.emit("service.start", actor="service:scheduler", feature="core",
                      data={"features": [f.name for f in self.features],
                            "intervals": {f.name: f.interval_s for f in self.features}})
        for f in self.features:
            t = threading.Thread(target=self._loop, args=(f,),
                                 name=f"feat-{f.name}", daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        eventlog.emit("service.stop", actor="service:scheduler", feature="core")

    def _loop(self, feature: registry.Feature) -> None:
        if not config.RUN_FEATURES_ON_STARTUP:
            if self._stop.wait(feature.interval_s):
                return
        while not self._stop.is_set():
            self._run(feature)
            # Interval measured from the end of the run, so a long cycle does
            # not queue up behind itself.
            if self._stop.wait(feature.interval_s):
                return

    def _run(self, feature: registry.Feature) -> None:
        entry = {"ts": db.now(), "ok": None, "summary": "", "error": "",
                 "next_in": feature.interval_s}
        try:
            res = feature.run_once(actor="scheduler")
            entry["ok"] = True
            entry["summary"] = res.summary
        except Exception as exc:
            # run_once already logged it and raised a finding. Keeping the
            # thread alive matters more than the individual failure: a
            # collector that dies on one bad poll stops observing entirely,
            # and nothing in the system would say so.
            entry["ok"] = False
            entry["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                self.last_run[feature.name] = entry

    def run_all_once(self, actor: str = "manual") -> dict[str, dict]:
        """Synchronous single pass over every feature. Used by tests and the portal."""
        out = {}
        for f in self.features:
            t0 = time.time()
            try:
                res = f.run_once(actor=actor)
                out[f.name] = {"ok": True, "summary": res.summary,
                               "counts": res.counts,
                               "duration_s": round(time.time() - t0, 3)}
            except Exception as exc:
                out[f.name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                               "duration_s": round(time.time() - t0, 3)}
            with self._lock:
                self.last_run[f.name] = {
                    "ts": db.now(), "ok": out[f.name]["ok"],
                    "summary": out[f.name].get("summary", ""),
                    "error": out[f.name].get("error", ""),
                    "next_in": f.interval_s}
        return out

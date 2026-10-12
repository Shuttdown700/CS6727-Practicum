"""
core/registry.py -- how features are found, and the contract they implement.

Adding a feature:
    1. drop a module into features/ that defines a Feature subclass
    2. add its `name` to config.ENABLED_FEATURES
    3. give it an interval in config.FEATURE_INTERVALS_S

Removing one: take it out of ENABLED_FEATURES. The module can stay.

Discovery is by import of the module whose filename matches the feature name,
so there is no registration decorator to forget and no import-order problem.
"""

from __future__ import annotations

import importlib
import time
import traceback
from abc import ABC, abstractmethod

from .. import config
from . import db, eventlog


class FeatureResult:
    """What one collection cycle produced. Printed by standalone runs."""

    def __init__(self, summary: str = "", counts: dict | None = None,
                 findings: int = 0, detail: dict | None = None):
        self.summary = summary
        self.counts = counts or {}
        self.findings = findings
        self.detail = detail or {}

    def as_dict(self) -> dict:
        return {"summary": self.summary, "counts": self.counts,
                "findings": self.findings, "detail": self.detail}


class Feature(ABC):
    """
    One collector. Implement collect(); everything else is handled here.

    A feature must be safe to run on its own, with no scheduler and no portal,
    because that is how it gets tested:

        python3 -m fabguard.features.<name>
    """

    name: str = "unnamed"
    title: str = "Unnamed feature"
    description: str = ""

    @property
    def interval_s(self) -> int:
        return int(config.FEATURE_INTERVALS_S.get(self.name, 300))

    @abstractmethod
    def collect(self) -> FeatureResult:
        """Do one cycle. Raise on failure; the runner records it."""

    # -- plumbing ----------------------------------------------------------

    def emit(self, kind: str, *, subject: str = "", data: dict | None = None,
             actor: str | None = None):
        return eventlog.emit(kind, actor=actor or f"service:{self.name}",
                             feature=self.name, subject=subject, data=data or {})

    def finding(self, severity: str, kind: str, subject: str, summary: str,
                detail: dict | None = None, dedup_key: str | None = None) -> bool:
        """
        Raise a finding and mirror it into the event log. Returns True if it
        was new. Duplicates (same dedup_key) are dropped silently so a
        30-second poll does not produce 2,880 identical rows a day.
        """
        rid = db.add_finding(self.name, severity, kind, subject, summary,
                             detail, dedup_key)
        if rid is None:
            return False
        self.emit("finding.raised", subject=subject,
                  data={"severity": severity, "kind": kind, "summary": summary,
                        "finding_id": rid, **(detail or {})})
        return True

    def run_once(self, actor: str = "scheduler") -> FeatureResult:
        """Run collect() with timing, event-log bookends and error capture."""
        started = db.now()
        t0 = time.time()
        self.emit("feature.run.start", subject=self.name, actor=f"service:{actor}")
        try:
            result = self.collect()
            dt = time.time() - t0
            db.record_run(self.name, started, dt, True, result.summary)
            self.emit("feature.run.ok", subject=self.name,
                      data={"duration_s": round(dt, 3), "summary": result.summary,
                            **result.counts})
            return result
        except Exception as exc:
            dt = time.time() - t0
            tb = traceback.format_exc(limit=6)
            db.record_run(self.name, started, dt, False, "", f"{exc}")
            self.emit("feature.run.error", subject=self.name,
                      data={"duration_s": round(dt, 3), "error": str(exc),
                            "type": type(exc).__name__})
            # A collector that cannot reach its target is a finding in its own
            # right -- silence from a monitoring service is indistinguishable
            # from "nothing happened", which is the failure mode the whole
            # architecture is meant to remove.
            self.finding("WARNING", "collector.failed", self.name,
                         f"{self.title} failed: {exc}",
                         {"traceback": tb},
                         dedup_key=f"collector-failed:{self.name}:{type(exc).__name__}")
            raise


def load(name: str) -> Feature:
    """Import features/<name>.py and return its Feature subclass, instantiated."""
    mod = importlib.import_module(f"..features.{name}", __package__)
    candidates = [v for v in vars(mod).values()
                  if isinstance(v, type) and issubclass(v, Feature) and v is not Feature]
    if not candidates:
        raise SystemExit(f"features/{name}.py defines no Feature subclass")
    if len(candidates) > 1:
        exact = [c for c in candidates if getattr(c, "name", None) == name]
        if len(exact) != 1:
            raise SystemExit(
                f"features/{name}.py defines {len(candidates)} Feature subclasses; "
                f"exactly one must have name == '{name}'")
        candidates = exact
    return candidates[0]()


def load_enabled() -> list[Feature]:
    out = []
    for name in config.ENABLED_FEATURES:
        try:
            out.append(load(name))
        except Exception as exc:
            # One broken feature must not stop the others from running.
            eventlog.emit("feature.load.error", feature=name, subject=name,
                          data={"error": str(exc)})
            print(f"[registry] could not load feature '{name}': {exc}")
    return out


def standalone(feature_cls: type[Feature]) -> None:
    """
    Entry point for `python3 -m fabguard.features.<name>`.

    Runs exactly one cycle against the real configuration, prints the result
    as JSON, and exits non-zero on failure so it is usable from a shell test.
    """
    import json
    import sys

    f = feature_cls()
    print(f"[{f.name}] {f.title}")
    print(f"[{f.name}] interval {f.interval_s}s   db {config.DB_PATH}")
    try:
        res = f.run_once(actor="standalone")
    except Exception as exc:
        print(f"[{f.name}] FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
    print(json.dumps(res.as_dict(), indent=2, default=str))
    sys.exit(0)

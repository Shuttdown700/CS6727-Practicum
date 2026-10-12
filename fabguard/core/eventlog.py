"""
core/eventlog.py -- Append-Only Event Logging  [FEATURE 5]

Every service transaction is written here as one JSON object per line, and
each record carries the hash of the record before it. Removing, reordering or
editing any record breaks every link after it, so the log is tamper-evident
without needing anything the Pi does not already have.

    record = {
      "seq":   monotonic integer, starting at 1
      "ts":    RFC3339 UTC
      "actor": who caused this -- an operator name, or "service:<feature>"
      "feature": which feature emitted it
      "kind":  short machine-readable event type
      "subject": what it is about (printer id, repo path, user name...)
      "data":  arbitrary JSON payload
      "prev":  hash of the preceding record
      "hash":  sha256 over the canonical form of everything above
    }

The log is the record of what the service DID. Findings and state live in
SQLite, which is rebuildable; this file is not. Keep them on separate media
for anything beyond a prototype, which is the point of "retained
independently of the artifacts themselves".

Standalone:
    python3 -m fabguard.core.eventlog          # verify the chain, print a summary
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from .. import config

_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical(obj) -> bytes:
    """Stable serialisation, so the same record always hashes the same."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def _hash_record(rec: dict) -> str:
    body = {k: rec[k] for k in
            ("seq", "ts", "actor", "feature", "kind", "subject", "data", "prev")}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _tail() -> tuple[int, str]:
    """(last seq, last hash). Genesis is (0, sha256 of the configured anchor)."""
    genesis = hashlib.sha256(config.EVENT_LOG_ANCHOR.encode()).hexdigest()
    path = config.EVENT_LOG_PATH
    if not path.exists() or path.stat().st_size == 0:
        return 0, genesis
    last = None
    with path.open("rb") as fh:
        for line in fh:
            line = line.strip()
            if line:
                last = line
    if last is None:
        return 0, genesis
    try:
        rec = json.loads(last)
        return int(rec["seq"]), str(rec["hash"])
    except Exception:
        # A truncated final line (power loss mid-write) must not silently
        # restart the chain -- that is exactly the situation the chain exists
        # to make visible.
        raise SystemExit(
            f"event log {path} ends in an unparseable record.\n"
            "The chain cannot be continued safely. Inspect the last line; to "
            "start a fresh chain, move the file aside -- do not edit it."
        )


def emit(kind: str, *, actor: str = "service", feature: str = "core",
         subject: str = "", data: dict | None = None) -> dict:
    """Append one record. Returns it, including its seq and hash."""
    config.EVENT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        seq, prev = _tail()
        rec = {
            "seq": seq + 1,
            "ts": _now(),
            "actor": actor,
            "feature": feature,
            "kind": kind,
            "subject": subject,
            "data": data or {},
            "prev": prev,
        }
        rec["hash"] = _hash_record(rec)
        line = json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str)
        # O_APPEND so concurrent writers cannot interleave a partial line, and
        # fsync so a record that was reported written survives a power cut --
        # a log that loses its tail on reboot is not an audit log.
        fd = os.open(config.EVENT_LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
    return rec


def read_all(limit: int | None = None, newest_first: bool = False) -> list[dict]:
    path = config.EVENT_LOG_PATH
    if not path.exists():
        return []
    out = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"seq": None, "ts": None, "kind": "UNPARSEABLE",
                            "actor": "", "feature": "", "subject": "",
                            "data": {"raw": line[:400]}, "prev": "", "hash": ""})
    if newest_first:
        out.reverse()
    return out[:limit] if limit else out


def verify() -> dict:
    """
    Walk the chain. Returns a verdict dict:
        ok, count, first_bad_seq, reason
    A clean result means no record was altered, removed or reordered since it
    was written -- it does NOT mean the contents were true when written.
    """
    genesis = hashlib.sha256(config.EVENT_LOG_ANCHOR.encode()).hexdigest()
    prev = genesis
    expect_seq = 1
    n = 0
    for rec in read_all():
        n += 1
        if rec.get("kind") == "UNPARSEABLE":
            return {"ok": False, "count": n, "first_bad_seq": expect_seq,
                    "reason": "unparseable record"}
        if rec.get("seq") != expect_seq:
            return {"ok": False, "count": n, "first_bad_seq": rec.get("seq"),
                    "reason": f"sequence gap: expected {expect_seq}, found {rec.get('seq')}"}
        if rec.get("prev") != prev:
            return {"ok": False, "count": n, "first_bad_seq": rec.get("seq"),
                    "reason": "broken link: prev does not match the preceding record's hash"}
        if _hash_record(rec) != rec.get("hash"):
            return {"ok": False, "count": n, "first_bad_seq": rec.get("seq"),
                    "reason": "record hash does not match its contents"}
        prev = rec["hash"]
        expect_seq += 1
    return {"ok": True, "count": n, "first_bad_seq": None,
            "reason": "chain intact" if n else "log is empty"}


def stats() -> dict:
    recs = read_all()
    kinds, actors, features = {}, {}, {}
    for r in recs:
        kinds[r.get("kind", "?")] = kinds.get(r.get("kind", "?"), 0) + 1
        actors[r.get("actor", "?")] = actors.get(r.get("actor", "?"), 0) + 1
        features[r.get("feature", "?")] = features.get(r.get("feature", "?"), 0) + 1
    return {
        "count": len(recs),
        "first_ts": recs[0]["ts"] if recs else None,
        "last_ts": recs[-1]["ts"] if recs else None,
        "by_kind": dict(sorted(kinds.items(), key=lambda kv: -kv[1])),
        "by_actor": dict(sorted(actors.items(), key=lambda kv: -kv[1])),
        "by_feature": dict(sorted(features.items(), key=lambda kv: -kv[1])),
        "path": str(config.EVENT_LOG_PATH),
        "append_only_flag": _has_append_only_flag(),
    }


def _has_append_only_flag() -> bool | None:
    """True if the kernel append-only attribute is set (chattr +a). None if unknown."""
    try:
        import subprocess
        r = subprocess.run(["lsattr", "-l", str(config.EVENT_LOG_PATH)],
                           capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            return None
        return "Append_Only" in r.stdout or "append only" in r.stdout.lower()
    except Exception:
        return None


if __name__ == "__main__":
    v = verify()
    s = stats()
    print(f"event log : {s['path']}")
    print(f"records   : {s['count']}")
    print(f"span      : {s['first_ts']} -> {s['last_ts']}")
    flag = s["append_only_flag"]
    print(f"chattr +a : {'yes' if flag else ('no' if flag is False else 'unknown')}")
    print(f"chain     : {'OK -- ' if v['ok'] else 'FAILED -- '}{v['reason']}")
    if not v["ok"]:
        print(f"            first bad record: seq {v['first_bad_seq']}")
    for title, d in (("by feature", s["by_feature"]), ("by kind", s["by_kind"]),
                     ("by actor", s["by_actor"])):
        if d:
            print(f"\n{title}")
            for k, n in d.items():
                print(f"  {n:>6}  {k}")

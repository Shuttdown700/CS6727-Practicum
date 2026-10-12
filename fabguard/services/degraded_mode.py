"""
services/degraded_mode.py -- Degraded-Mode Operation  [M]

When the mediating service cannot do its job, fabrication continues under a
logged, time-limited, reported exception rather than halting. Availability is
treated as a security property here because a control that stops
mission-essential work gets deliberately bypassed, and a bypass nobody
designed is a bypass nobody records.

THE DESIGN ADMITS ITS OWN AWKWARDNESS
    "When the service is unavailable" and "the service records an exception"
    cannot both be fully true at once. A service that is down cannot log
    anything. So the exception has two honest entry points:

        PROSPECTIVE   the operator sees trouble coming -- equipment
                      unreachable, share down, deadline inside the support
                      window -- and opens the window while the portal still
                      works. The normal case.

        RETROSPECTIVE opened after the fact, covering a stated window, when
                      the service was genuinely down. The record says it was
                      opened retrospectively and when, because a
                      retrospective exception is weaker evidence than a
                      prospective one and the log should not blur them.

    A prototype that only supported the first would be pretending the hard
    case away.

TIME-LIMITED IS NOT DECORATION
    An exception with no expiry is a disabled control with a nicer name.
    Every window has an explicit expiry, the open_exceptions check raises a
    finding once one is overdue, and closing requires a human.

RECONCILIATION AFTERWARDS
    Jobs observed during a window are still unauthorized -- the exception
    does not authorize them, it accounts for them. Fabrication Job
    Reconciliation tags them with the exception id, and closing the window
    asks the operator to confirm what happened. The point is that the audit
    record is continuous across the gap, not that the gap is pretended away.

Standalone:
    python3 -m solution.services.degraded_mode
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .. import config
from ..core import db
from ..core.services import Actor, Service, ServiceError


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class DegradedModeOperation(Service):
    name = "degraded_mode"
    title = "Degraded-Mode Operation"
    description = ("Break-glass: fabrication continues under a logged, time-limited, "
                   "reported exception when the mediated path is unavailable.")

    # -- opening and closing -----------------------------------------------

    def open(self, actor: Actor, reason: str, detail: str = "",
             minutes: int | None = None, retrospective_from: str | None = None) -> dict:
        self.require_mediated()
        if not reason:
            raise ServiceError("a reason is required")
        minutes = int(minutes or config.DEGRADED_DEFAULT_MINUTES)
        if minutes < 1 or minutes > config.DEGRADED_MAX_MINUTES:
            raise ServiceError(
                f"window must be between 1 and {config.DEGRADED_MAX_MINUTES} minutes")

        existing = self.open_exceptions()
        if existing:
            raise ServiceError(
                f"exception #{existing[0]['id']} is already open (expires "
                f"{existing[0]['expires_ts']}). Close or extend it rather than "
                f"opening a second overlapping window.")

        opened = _parse(retrospective_from) if retrospective_from else datetime.now(timezone.utc)
        now = datetime.now(timezone.utc)
        if opened > now:
            raise ServiceError("a retrospective window cannot start in the future")
        expires = opened + timedelta(minutes=minutes)

        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO degraded_exception"
                "(opened_ts, opened_by, device, reason, detail, expires_ts)"
                " VALUES (?,?,?,?,?,?)",
                (_fmt(opened), actor.operator, actor.device, reason,
                 detail + ("  [opened retrospectively at " + _fmt(now) + "]"
                           if retrospective_from else ""),
                 _fmt(expires)))
            eid = cur.lastrowid

        self.emit("degraded.opened", actor, subject=f"exception-{eid}",
                  data={"exception_id": eid, "reason": reason, "detail": detail,
                        "opened_ts": _fmt(opened), "expires_ts": _fmt(expires),
                        "minutes": minutes,
                        "retrospective": bool(retrospective_from)})
        # Reported, not merely logged: the feature says exceptions are
        # reported, so one shows up where a human is already looking.
        self.finding(
            "WARNING", "degraded.opened", f"exception-{eid}",
            f"{actor.operator} opened a break-glass exception: {reason} "
            f"(expires {_fmt(expires)})",
            {"exception_id": eid, "reason": reason, "detail": detail,
             "operator": actor.operator, "device": actor.device,
             "retrospective": bool(retrospective_from),
             "note": "Fabrication during this window is unmediated. Jobs observed "
                     "will be tagged to this exception and must be reconciled on close."},
            dedup_key=f"degraded-open:{eid}")
        return self.get(eid)

    def extend(self, actor: Actor, exception_id: int, minutes: int,
               reason: str = "") -> dict:
        ex = self.get(exception_id)
        if ex["closed_ts"]:
            raise ServiceError("that exception is already closed")
        total = int((_parse(ex["expires_ts"]) - _parse(ex["opened_ts"])).total_seconds() // 60)
        if total + minutes > config.DEGRADED_MAX_MINUTES:
            raise ServiceError(
                f"extending by {minutes} would take the window to {total + minutes} "
                f"minutes, over the {config.DEGRADED_MAX_MINUTES} minute maximum. "
                f"Close it and open a new one, so the extension is a decision rather "
                f"than a drift.")
        new_expiry = _parse(ex["expires_ts"]) + timedelta(minutes=minutes)
        with db.tx() as c:
            c.execute("UPDATE degraded_exception SET expires_ts=?,"
                      " detail=COALESCE(detail,'')||? WHERE id=?",
                      (_fmt(new_expiry),
                       f"  [extended {minutes}m by {actor.operator}: {reason}]",
                       exception_id))
        self.emit("degraded.extended", actor, subject=f"exception-{exception_id}",
                  data={"exception_id": exception_id, "minutes": minutes,
                        "new_expires_ts": _fmt(new_expiry), "reason": reason})
        return self.get(exception_id)

    def close(self, actor: Actor, exception_id: int, note: str = "",
              reconciled: bool = False) -> dict:
        ex = self.get(exception_id)
        if ex["closed_ts"]:
            raise ServiceError("already closed")
        jobs = self.jobs_during(exception_id)

        with db.tx() as c:
            c.execute("UPDATE degraded_exception SET closed_ts=?, closed_by=?,"
                      " close_note=?, jobs_observed=?, reported=1,"
                      " reconciled_ts=CASE WHEN ? THEN ? ELSE NULL END,"
                      " reconciled_by=CASE WHEN ? THEN ? ELSE NULL END"
                      " WHERE id=?",
                      (db.now(), actor.operator, note, len(jobs),
                       1 if reconciled else 0, db.now(),
                       1 if reconciled else 0, actor.operator, exception_id))

        self.emit("degraded.closed", actor, subject=f"exception-{exception_id}",
                  data={"exception_id": exception_id, "note": note,
                        "jobs_observed": len(jobs), "reconciled": reconciled,
                        "job_keys": [j["job_key"] for j in jobs]})

        if jobs and not reconciled:
            self.finding(
                "WARNING", "degraded.unreconciled", f"exception-{exception_id}",
                f"Exception #{exception_id} closed with {len(jobs)} fabrication job(s) "
                f"observed during the window and not yet reconciled",
                {"exception_id": exception_id, "jobs": [j["job_key"] for j in jobs],
                 "closed_by": actor.operator,
                 "note": "The exception accounts for these jobs; it does not authorize "
                         "them. Confirm what was made and why."},
                dedup_key=f"degraded-unreconciled:{exception_id}")
        return self.get(exception_id)

    def reconcile(self, actor: Actor, exception_id: int, note: str = "") -> dict:
        ex = self.get(exception_id)
        if not ex["closed_ts"]:
            raise ServiceError("close the exception before reconciling it")
        with db.tx() as c:
            c.execute("UPDATE degraded_exception SET reconciled_ts=?, reconciled_by=?,"
                      " close_note=COALESCE(close_note,'')||? WHERE id=?",
                      (db.now(), actor.operator,
                       f"  [reconciled by {actor.operator}: {note}]", exception_id))
        self.emit("degraded.reconciled", actor, subject=f"exception-{exception_id}",
                  data={"exception_id": exception_id, "note": note,
                        "jobs_observed": ex["jobs_observed"]})
        return self.get(exception_id)

    # -- state -------------------------------------------------------------

    def active(self) -> dict | None:
        """The exception covering right now, if any. None when mediation is in force."""
        now = db.now()
        row = db.q1(
            "SELECT * FROM degraded_exception WHERE closed_ts IS NULL"
            " AND opened_ts <= ? AND expires_ts >= ? ORDER BY id DESC LIMIT 1",
            (now, now))
        return dict(row) if row else None

    def covering(self, ts: str) -> dict | None:
        """
        The exception covering a given instant, open or closed.

        Reconciliation uses this: a job observed at 14:05 is covered by a
        window that ran 14:00-16:00 even if that window has since been closed.
        """
        row = db.q1(
            "SELECT * FROM degraded_exception WHERE opened_ts <= ?"
            " AND (expires_ts >= ? OR (closed_ts IS NOT NULL AND closed_ts >= ?))"
            " ORDER BY id DESC LIMIT 1", (ts, ts, ts))
        return dict(row) if row else None

    def open_exceptions(self) -> list[dict]:
        return [dict(r) for r in db.q(
            "SELECT * FROM degraded_exception WHERE closed_ts IS NULL ORDER BY id DESC")]

    def overdue(self) -> list[dict]:
        cutoff = _fmt(datetime.now(timezone.utc)
                      - timedelta(minutes=config.DEGRADED_OVERDUE_GRACE_MINUTES))
        return [dict(r) for r in db.q(
            "SELECT * FROM degraded_exception WHERE closed_ts IS NULL AND expires_ts < ?"
            " ORDER BY id", (cutoff,))]

    def check_overdue(self) -> int:
        """
        Raise a finding for each window left open past its expiry.

        Called by the reconciliation collector, so an exception somebody
        forgot about surfaces on its own rather than waiting for a human to
        notice. An expired-but-open window is the failure mode that turns
        break-glass into a permanently disabled control.
        """
        n = 0
        for ex in self.overdue():
            if self.finding(
                    "CRITICAL", "degraded.overdue", f"exception-{ex['id']}",
                    f"Break-glass exception #{ex['id']} expired at {ex['expires_ts']} "
                    f"and is still open. Opened by {ex['opened_by']}: {ex['reason']}",
                    {"exception_id": ex["id"], "opened_by": ex["opened_by"],
                     "opened_ts": ex["opened_ts"], "expires_ts": ex["expires_ts"],
                     "note": "An exception that does not expire is a disabled control. "
                             "Close it, or extend it deliberately."},
                    dedup_key=f"degraded-overdue:{ex['id']}"):
                n += 1
        return n

    def jobs_during(self, exception_id: int) -> list[dict]:
        ex = self.get(exception_id)
        end = ex["closed_ts"] or ex["expires_ts"]
        return [dict(r) for r in db.q(
            "SELECT * FROM fabrication_job WHERE first_seen_ts >= ?"
            " AND first_seen_ts <= ? ORDER BY id", (ex["opened_ts"], end))]

    def get(self, exception_id: int) -> dict:
        row = db.q1("SELECT * FROM degraded_exception WHERE id=?", (exception_id,))
        if not row:
            raise ServiceError(f"no exception {exception_id}")
        return dict(row)

    def recent(self, limit: int = 50) -> list[dict]:
        return [dict(r) for r in db.q(
            "SELECT * FROM degraded_exception ORDER BY id DESC LIMIT ?", (limit,))]


def demo() -> int:
    from ..core import db as _db
    _db.connect()
    svc = DegradedModeOperation()
    alice = Actor("alice", "ws-01")

    print(f"active exception at start: {svc.active()}")

    ex = svc.open(alice, "Mediating service unavailable",
                  "Pi lost power; deadline is inside the support window", minutes=120)
    print(f"\nopened #{ex['id']}  {ex['opened_ts']} -> {ex['expires_ts']}")
    print(f"active now: #{svc.active()['id']}")

    print("\nopening a second overlapping window:")
    try:
        svc.open(alice, "Other (describe)", "second window", minutes=30)
        print("  allowed -- bug")
        return 1
    except ServiceError as exc:
        print(f"  refused: {exc}")

    print("\nextending past the maximum:")
    try:
        svc.extend(alice, ex["id"], config.DEGRADED_MAX_MINUTES, "need longer")
        print("  allowed -- bug")
        return 1
    except ServiceError as exc:
        print(f"  refused: {str(exc)[:120]}")

    svc.extend(alice, ex["id"], 60, "still waiting on the replacement PSU")
    print(f"\nextended to {svc.get(ex['id'])['expires_ts']}")

    # a job observed during the window
    with _db.tx() as c:
        c.execute("INSERT INTO fabrication_job(printer_id, job_key, job_id, file_name,"
                  " first_seen_ts, last_seen_ts) VALUES (?,?,?,?,?,?)",
                  ("sim-01", "sim-01:1:urgent.bgcode", "1", "urgent.bgcode",
                   _db.now(), _db.now()))
    print(f"jobs observed during the window: {len(svc.jobs_during(ex['id']))}")

    closed = svc.close(alice, ex["id"], "service restored, PSU replaced")
    print(f"\nclosed. jobs_observed={closed['jobs_observed']}, "
          f"reconciled={bool(closed['reconciled_ts'])}")
    svc.reconcile(alice, ex["id"], "one urgent bracket, confirmed with the requester")
    print(f"reconciled by {svc.get(ex['id'])['reconciled_by']}")

    # an overdue window
    past = _fmt(datetime.now(timezone.utc) - timedelta(hours=6))
    with _db.tx() as c:
        c.execute("INSERT INTO degraded_exception(opened_ts, opened_by, reason,"
                  " expires_ts) VALUES (?,?,?,?)",
                  (past, "bob", "Network partition to equipment",
                   _fmt(datetime.now(timezone.utc) - timedelta(hours=4))))
    print(f"\noverdue windows: {len(svc.overdue())}  -> raised "
          f"{svc.check_overdue()} finding(s)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(demo())

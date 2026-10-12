"""
features/fabrication_activity.py -- Fabrication Activity Recording  [FEATURE 1]

Polls each machine at a fixed interval and records what it was doing. There is
no job history on a Prusa MK4 and none at the enterprise layer, so the history
this builds is the only one that exists. Everything else in the architecture
that reasons about what was fabricated reads from here.

WHAT IT RECORDS
    activity_sample   one row per poll worth keeping
    fabrication_job   one row per observed job, opened on first sighting and
                      closed when the machine stops reporting it

THE RECONCILIATION PRIMITIVE
    A machine reporting active fabrication with no corresponding authorization
    record is an unauthorized fabrication event. The check depends only on
    observable machine state, so it survives the operator pulling the USB
    stick afterwards -- which is the whole point.

    In the OBSERVATIONAL variant there is no authorization path, so the
    `authorizations` source is empty and every job is unreconciled. That is
    the correct result, not a bug: the observational variant can see that
    something was made and cannot say whether it was allowed. In the MEDIATED
    variant, Fabrication Job Authorization populates that source and only the
    bypass jobs stay unreconciled.

DETECTION IS INTERVAL-BOUND
    A print that starts and finishes between two polls is never observed.
    Detection probability is a function of poll interval against print
    duration, so config.FEATURE_INTERVALS_S["fabrication_activity"] is the
    independent variable for that part of the evaluation. The gap is a
    measured property of the design, not something to paper over.

Standalone:
    python3 -m fabguard.features.fabrication_activity
"""

from __future__ import annotations

from .. import adapters, config
from ..core import db
from ..core.registry import Feature, FeatureResult, standalone

# Machine states that mean material is being committed.
ACTIVE_STATES = {"PRINTING", "PAUSED"}
# Terminal states worth recording as the end of a job.
END_STATES = {"FINISHED", "STOPPED", "ERROR", "IDLE", "READY"}


class FabricationActivityRecording(Feature):
    name = "fabrication_activity"
    title = "Fabrication Activity Recording"
    description = ("Polls fabrication equipment and records observed events and "
                   "on-device technical data. The only source of fabrication-layer "
                   "history at any level.")

    def collect(self) -> FeatureResult:
        counts = {"polled": 0, "unreachable": 0, "samples": 0,
                  "jobs_opened": 0, "jobs_closed": 0, "unreconciled": 0}
        detail = {}

        for printer in adapters.all_printers():
            try:
                snap = printer.snapshot()
            except Exception as exc:
                counts["unreachable"] += 1
                detail[printer.id] = f"unreachable: {exc}"
                # Silence from a machine is itself an observation: during an
                # outage the service cannot say the machine was idle, only
                # that it could not see it.
                self.finding("WARNING", "equipment.unreachable", printer.id,
                             f"{printer.label} did not answer a status poll",
                             {"error": str(exc)},
                             dedup_key=f"unreachable:{printer.id}")
                self.emit("equipment.poll.failed", subject=printer.id,
                          data={"error": str(exc)})
                continue

            counts["polled"] += 1
            prev = self._previous_sample(printer.id)
            changed = self._is_interesting(prev, snap)
            if changed or self._heartbeat_due(printer.id):
                self._store_sample(snap)
                counts["samples"] += 1

            if changed:
                self.emit("equipment.state", subject=printer.id,
                          data={"state": snap["state"], "job_id": snap["job_id"],
                                "file": snap["file_name"],
                                "progress": snap["progress"],
                                "previous_state": (prev or {}).get("state")})

            state = (snap.get("state") or "").upper()
            if state in ACTIVE_STATES and snap.get("job_id"):
                opened, unrec = self._open_or_touch_job(printer, snap)
                counts["jobs_opened"] += 1 if opened else 0
                counts["unreconciled"] += 1 if unrec else 0
            else:
                counts["jobs_closed"] += self._close_open_jobs(printer.id, state)

            detail[printer.id] = {"state": snap.get("state"),
                                  "job": snap.get("file_name"),
                                  "progress": snap.get("progress")}

        summary = (f"polled {counts['polled']}, {counts['samples']} sample(s), "
                   f"{counts['jobs_opened']} job(s) opened, "
                   f"{counts['unreconciled']} unreconciled")
        return FeatureResult(summary, counts, counts["unreconciled"], detail)

    # -- samples -----------------------------------------------------------

    def _previous_sample(self, printer_id: str) -> dict | None:
        row = db.q1("SELECT * FROM activity_sample WHERE printer_id=?"
                    " ORDER BY id DESC LIMIT 1", (printer_id,))
        return dict(row) if row else None

    def _is_interesting(self, prev: dict | None, snap: dict) -> bool:
        """
        Worth a row? Only when something a human would care about moved.
        Temperature drifting by a tenth of a degree is not a fabrication event
        and storing it every 30 seconds buries the events that are.
        """
        if prev is None:
            return True
        if (prev.get("state") or "") != (snap.get("state") or ""):
            return True
        if (prev.get("job_id") or "") != (snap.get("job_id") or ""):
            return True
        if (prev.get("job_file") or "") != (snap.get("file_name") or ""):
            return True
        p_old, p_new = prev.get("progress"), snap.get("progress")
        if p_old is not None and p_new is not None and abs(p_new - p_old) >= 5.0:
            return True
        return False

    def _heartbeat_due(self, printer_id: str) -> bool:
        """Write a sample every Nth poll regardless, so the log shows liveness."""
        n = db.q1("SELECT COUNT(*) AS n FROM activity_sample WHERE printer_id=?",
                  (printer_id,))["n"]
        every = max(1, int(config.ACTIVITY_HEARTBEAT_EVERY_N_POLLS))
        return n % every == 0

    def _store_sample(self, snap: dict) -> None:
        with db.tx() as c:
            c.execute(
                "INSERT INTO activity_sample"
                "(ts, printer_id, state, job_id, job_file, progress, time_printing,"
                " time_remaining, temp_nozzle, temp_bed, raw)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (db.now(), snap["printer_id"], snap.get("state"), snap.get("job_id"),
                 snap.get("file_name"), snap.get("progress"), snap.get("time_printing"),
                 snap.get("time_remaining"), snap.get("temp_nozzle"),
                 snap.get("temp_bed"), db.jdump(snap.get("raw"))))

    # -- jobs --------------------------------------------------------------

    def _job_key(self, printer_id: str, snap: dict) -> str:
        # The printer reuses job ids across power cycles, so the key folds in
        # the file as well; two different files cannot collapse into one job.
        return f"{printer_id}:{snap.get('job_id')}:{snap.get('file_path') or snap.get('file_name')}"

    def _open_or_touch_job(self, printer, snap: dict) -> tuple[bool, bool]:
        key = self._job_key(printer.id, snap)
        existing = db.q1("SELECT * FROM fabrication_job WHERE job_key=?", (key,))
        if existing:
            with db.tx() as c:
                c.execute("UPDATE fabrication_job SET last_seen_ts=? WHERE job_key=?",
                          (db.now(), key))
            return False, False

        authorized, ref = self._lookup_authorization(printer.id, snap)
        with db.tx() as c:
            c.execute(
                "INSERT INTO fabrication_job"
                "(printer_id, job_key, job_id, file_name, file_path, file_size,"
                " file_m_timestamp, first_seen_ts, last_seen_ts, authorized,"
                " authorization_ref, reconciled)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,0)",
                (printer.id, key, snap.get("job_id"), snap.get("file_name"),
                 snap.get("file_path"), snap.get("file_size"),
                 snap.get("file_m_timestamp"), db.now(), db.now(),
                 1 if authorized else 0, ref))
            # reconciled stays 0 even on a provisional match: Fabrication Job
            # Reconciliation owns the authoritative comparison and filters on
            # exactly this column. Marking it here would hide the job from the
            # feature whose job it is to check it against a content hash.

        self.emit("fabrication.job.observed", subject=printer.id,
                  data={"job_key": key, "job_id": snap.get("job_id"),
                        "file": snap.get("file_name"),
                        "path": snap.get("file_path"),
                        "size": snap.get("file_size"),
                        "provisionally_authorized": authorized,
                        "authorization_ref": ref})

        if authorized:
            return True, False

        if config.MEDIATED:
            # Reconciliation raises the finding, once, after checking content
            # hashes and break-glass windows. Raising one here too would
            # double-report every unauthorized job and get the severity wrong
            # for anything covered by an exception.
            return True, True

        self.finding(
            "CRITICAL", "fabrication.unauthorized", printer.id,
            f"{printer.label} began fabricating '{snap.get('file_name')}' with no "
            f"authorization record",
            {"job_key": key, "job_id": snap.get("job_id"),
             "file_path": snap.get("file_path"), "file_size": snap.get("file_size"),
             "note": ("The observational variant has no authorization source, so every "
                      "job reads as unreconciled. It can see that something was "
                      "fabricated; it cannot say whether it was allowed.")},
            dedup_key=f"unauthorized-job:{key}")
        return True, True

    def _lookup_authorization(self, printer_id: str, snap: dict) -> tuple[bool, str | None]:
        """
        Is there an authorization record for this job, at the moment it was
        first observed?

        OBSERVATIONAL: no authorization source exists, so the answer is always
        no and every job is unreconciled. Correct, and the point: the variant
        can see that something was made and cannot say it was allowed.

        MEDIATED: Fabrication Job Authorization has a record or it does not.

        This is a first-pass check only. Fabrication Job Reconciliation does
        the authoritative comparison later, because at first sighting the
        content on the machine has usually not been hashed yet -- so matching
        here can only go on filename, and a filename match is exactly what
        content substitution under an approved name produces. Anything matched
        here is left for reconciliation to confirm against a hash.
        """
        if not config.MEDIATED:
            return False, None
        try:
            from ..services.job_authorization import FabricationJobAuthorization
            match = FabricationJobAuthorization.find_authorization(
                printer_id, file_name=snap.get("file_name"))
        except Exception:
            # Never let the mediated lookup break the observational core: this
            # collector runs in both variants and recording the observation
            # matters more than classifying it.
            return False, None
        if not match:
            return False, None
        return True, f"auth:{match['id']}:{match.get('match_basis', '?')}:provisional"

    def _close_open_jobs(self, printer_id: str, state: str) -> int:
        rows = db.q("SELECT * FROM fabrication_job WHERE printer_id=? AND end_state IS NULL",
                    (printer_id,))
        for r in rows:
            with db.tx() as c:
                c.execute("UPDATE fabrication_job SET end_state=?, last_seen_ts=?"
                          " WHERE id=?", (state or "UNKNOWN", db.now(), r["id"]))
            self.emit("fabrication.job.ended", subject=printer_id,
                      data={"job_key": r["job_key"], "file": r["file_name"],
                            "end_state": state,
                            "authorized": bool(r["authorized"])})
        return len(rows)


if __name__ == "__main__":
    standalone(FabricationActivityRecording)

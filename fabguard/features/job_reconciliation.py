"""
features/job_reconciliation.py -- Fabrication Job Reconciliation  [M]

Compares what the machines were observed doing against what was authorized. A
machine reporting fabrication with no corresponding authorization record is an
unauthorized fabrication event.

The detection depends on OBSERVABLE MACHINE STATE, not on records the
equipment keeps. That distinction is the whole reason this works: removable
media gets swapped between machines and repurposed, so anything written to
the stick cannot reliably be tied to the machine that ran it afterwards. What
the machine was seen doing, by a service polling it, survives the stick being
pulled.

THREE OUTCOMES PER OBSERVED JOB
    RECONCILED      an authorization matches. The normal case under mediation.
    EXCEPTION       no authorization, but the job falls inside a break-glass
                    window. Still unauthorized -- the exception accounts for
                    it rather than permitting it -- but expected, and tied to
                    the operator who opened the window.
    UNAUTHORIZED    no authorization and no exception. This is the finding the
                    architecture exists to produce.

MATCH BASIS MATTERS AND IS RECORDED
    A match on content hash means the authorized bytes are the bytes that
    ran. A match on filename only means something with the right name ran,
    which is a much weaker claim -- it is exactly what an attacker
    substituting content under an approved name would produce. Both are
    recorded, and a name-only match raises its own finding rather than
    being quietly counted as reconciled.

THIS FEATURE IS THE OTHER HALF OF THE OBSERVATIONAL VARIANT'S LIMITATION
    In the observational variant it does not run, because there is nothing
    to reconcile against. The comparison between variants is therefore not
    "mediated detects more" -- both detect the same fabrication events -- but
    "mediated can say which ones were allowed". That is the claim to make.

Standalone:
    python3 -m solution.features.job_reconciliation
"""

from __future__ import annotations

from ..core import db
from ..core.registry import Feature, FeatureResult, standalone


class FabricationJobReconciliation(Feature):
    name = "job_reconciliation"
    title = "Fabrication Job Reconciliation"
    description = ("Compares observed fabrication activity against authorization "
                   "records; a job with neither an authorization nor a break-glass "
                   "exception is an unauthorized fabrication event.")

    def collect(self) -> FeatureResult:
        from ..services.degraded_mode import DegradedModeOperation
        from ..services.job_authorization import FabricationJobAuthorization

        auth_svc = FabricationJobAuthorization()
        degraded = DegradedModeOperation()

        counts = {"examined": 0, "reconciled": 0, "by_hash": 0, "by_name": 0,
                  "exception": 0, "unauthorized": 0, "overdue_exceptions": 0,
                  "orphan_authorizations": 0}
        detail: dict = {"unauthorized": [], "name_only": []}

        for row in db.q("SELECT * FROM fabrication_job WHERE reconciled=0 ORDER BY id"):
            counts["examined"] += 1
            job = dict(row)

            sha = self._observed_hash(job)
            match = auth_svc.find_authorization(
                job["printer_id"], sha256=sha, file_name=job["file_name"])

            if match:
                basis = match.get("match_basis", "?")
                counts["reconciled"] += 1
                counts["by_hash" if basis == "hash" else "by_name"] += 1
                self._mark_reconciled(job, match, basis)

                if basis == "name":
                    detail["name_only"].append(job["job_key"])
                    self.finding(
                        "WARNING", "job.name_only_match", job["printer_id"],
                        f"'{job['file_name']}' on {job['printer_id']} matched an "
                        f"authorization by FILENAME ONLY -- the content running on the "
                        f"machine was not confirmed to be the content authorized",
                        {"job_key": job["job_key"], "authorization_id": match["id"],
                         "authorized_sha256": match["sha256"],
                         "observed_sha256": sha,
                         "note": "Exactly what substituting content under an approved "
                                 "name would look like. Artifact Verification will "
                                 "hash the media on its next pass."},
                        dedup_key=f"name-match:{job['job_key']}")
                continue

            exception = degraded.covering(job["first_seen_ts"])
            if exception:
                counts["exception"] += 1
                self._mark_exception(job, exception)
                self.finding(
                    "NOTICE", "job.during_exception", job["printer_id"],
                    f"'{job['file_name']}' fabricated on {job['printer_id']} during "
                    f"break-glass exception #{exception['id']} opened by "
                    f"{exception['opened_by']}",
                    {"job_key": job["job_key"], "exception_id": exception["id"],
                     "opened_by": exception["opened_by"],
                     "reason": exception["reason"],
                     "note": "Accounted for, not authorized. Confirm on close."},
                    dedup_key=f"job-exception:{job['job_key']}")
                continue

            counts["unauthorized"] += 1
            detail["unauthorized"].append(job["job_key"])
            self.finding(
                "CRITICAL", "job.unauthorized", job["printer_id"],
                f"'{job['file_name']}' was fabricated on {job['printer_id']} with no "
                f"authorization record and no break-glass exception",
                {"job_key": job["job_key"], "file_path": job["file_path"],
                 "observed_sha256": sha, "first_seen_ts": job["first_seen_ts"],
                 "note": "Unauthorized fabrication: the machine was seen producing "
                         "something the service never authorized."},
                dedup_key=f"unauthorized-reconciled:{job['job_key']}")

            # Settle the verdict only once the job has ended. While it is
            # still running, more information can still arrive -- Artifact
            # Verification may hash the media and turn a no-match into a hash
            # match, or a retrospective break-glass window may be opened to
            # cover it. Marking it resolved at first sight would freeze the
            # worst reading of an incomplete picture.
            if job.get("end_state"):
                with db.tx() as c:
                    c.execute("UPDATE fabrication_job SET reconciled=1, authorized=0,"
                              " authorization_ref='unauthorized' WHERE id=?",
                              (job["id"],))
                counts["settled_unauthorized"] = counts.get("settled_unauthorized", 0) + 1
                self.emit("job.unauthorized_settled", subject=job["printer_id"],
                          data={"job_key": job["job_key"],
                                "end_state": job["end_state"],
                                "observed_sha256": sha})
            else:
                counts["pending"] = counts.get("pending", 0) + 1

        counts["overdue_exceptions"] = degraded.check_overdue()
        counts["orphan_authorizations"] = self._check_orphans()

        summary = (f"{counts['examined']} job(s): {counts['reconciled']} reconciled "
                   f"({counts['by_hash']} by hash, {counts['by_name']} by name), "
                   f"{counts['exception']} under exception, "
                   f"{counts['unauthorized']} UNAUTHORIZED")
        return FeatureResult(summary, counts,
                             counts["unauthorized"] + counts["by_name"], detail)

    # -- helpers -----------------------------------------------------------

    def _observed_hash(self, job: dict) -> str | None:
        """
        The hash of what actually ran, if Artifact Verification has seen it.

        Matched on the file path the machine reported. When verification has
        not yet hashed that path there is no hash to match on and the
        comparison falls back to the filename -- weaker, and recorded as such.
        """
        if not job.get("file_path"):
            return None
        row = db.q1(
            "SELECT sha256 FROM equipment_artifact WHERE printer_id=? AND path=?"
            " AND sha256 IS NOT NULL ORDER BY id DESC LIMIT 1",
            (job["printer_id"], job["file_path"]))
        return row["sha256"] if row else None

    def _mark_reconciled(self, job: dict, match: dict, basis: str) -> None:
        with db.tx() as c:
            c.execute("UPDATE fabrication_job SET reconciled=1, authorized=1,"
                      " authorization_ref=? WHERE id=?",
                      (f"auth:{match['id']}:{basis}", job["id"]))
            c.execute("UPDATE fabrication_authorization SET matched_job_id=?"
                      " WHERE id=?", (job["id"], match["id"]))
        self.emit("job.reconciled", subject=job["printer_id"],
                  data={"job_key": job["job_key"], "authorization_id": match["id"],
                        "match_basis": basis, "operator": match["operator"],
                        "device": match["device"], "file": job["file_name"]})

    def _mark_exception(self, job: dict, exception: dict) -> None:
        with db.tx() as c:
            # reconciled=1 means "accounted for", not "authorized" -- the
            # authorized flag stays 0, which is the honest record.
            c.execute("UPDATE fabrication_job SET reconciled=1, authorized=0,"
                      " exception_id=?, authorization_ref=? WHERE id=?",
                      (exception["id"], f"exception:{exception['id']}", job["id"]))
        self.emit("job.accounted_by_exception", subject=job["printer_id"],
                  data={"job_key": job["job_key"], "exception_id": exception["id"],
                        "opened_by": exception["opened_by"],
                        "reason": exception["reason"], "file": job["file_name"]})

    def _check_orphans(self) -> int:
        """
        Authorizations that were transferred but never observed running.

        Benign most of the time -- the operator changed their mind, or the
        print is queued. Worth surfacing anyway: a transfer that never
        produced an observed job can also mean the activity poll missed the
        whole print, which is the interval-bound blind spot showing up from
        the other direction and is useful evidence for the interval analysis.
        """
        rows = db.q(
            "SELECT * FROM fabrication_authorization WHERE status='TRANSFERRED'"
            " AND matched_job_id IS NULL AND transferred_ts < ?",
            (self._minutes_ago(60),))
        for r in rows:
            self.finding(
                "NOTICE", "job.authorized_never_observed", r["printer_id"],
                f"Authorization #{r['id']} for '{r['file_name']}' transferred over an "
                f"hour ago but no matching fabrication was ever observed",
                {"authorization_id": r["id"], "operator": r["operator"],
                 "transferred_ts": r["transferred_ts"], "sha256": r["sha256"],
                 "note": "Either it was never started, or the print began and ended "
                         "between two activity polls. The second case is the "
                         "interval-bound blind spot and is worth noting for the "
                         "detection-probability analysis."},
                dedup_key=f"auth-unobserved:{r['id']}")
        return len(rows)

    @staticmethod
    def _minutes_ago(minutes: int) -> str:
        from datetime import datetime, timedelta, timezone
        return (datetime.now(timezone.utc) - timedelta(minutes=minutes)) \
            .isoformat(timespec="seconds").replace("+00:00", "Z")


if __name__ == "__main__":
    standalone(FabricationJobReconciliation)

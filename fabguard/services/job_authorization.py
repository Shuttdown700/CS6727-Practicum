"""
services/job_authorization.py -- Fabrication Job Authorization  [M]

Fabrication jobs are submitted through the service. This authorizes the
request, records the artifact and its hash, transfers the job to the target
machine, and logs the transaction. It is the sole authorized mechanism for
putting work on a printer, which makes it both the authorization point and
the record that Fabrication Job Reconciliation measures observed machine
activity against.

THE AUTHORIZATION RECORD IS THE WHOLE PRODUCT
    Transferring the file is the easy part. The thing that did not exist
    before is a row saying: this operator, from this device, at this time,
    authorized this hash to be fabricated on this machine. Reconciliation
    reads exactly that, and in the observational variant -- where this
    service does not run -- there is nothing to read, which is why every
    observed job there is unreconciled.

WHAT IS CHECKED BEFORE A JOB IS AUTHORIZED
    1. the artifact is in the manifest and not revoked      (provenance)
    2. the hash is the CURRENT authoritative version        (version authority)
    3. the extension is fabricable                          (sanity)
    4. the machine is reachable                             (else break-glass)

    Check 2 is a warning rather than a refusal, and the operator may override
    it with a recorded reason. Fabricating a superseded design is sometimes
    correct -- reprinting a part for an already-fielded assembly, for
    instance -- and a control that forbids a legitimate action is a control
    that gets routed around. What matters is that the choice is deliberate
    and attributed.

ORDER OF OPERATIONS
    The authorization row is written BEFORE the transfer, with status
    AUTHORIZED, then updated to TRANSFERRED or FAILED. If the service dies
    mid-transfer the record of the attempt survives, so a job found on a
    machine with a matching AUTHORIZED row is explainable. The reverse order
    would leave exactly the gap the feature exists to close.

Standalone:
    python3 -m solution.services.job_authorization
"""

from __future__ import annotations

import posixpath
from pathlib import Path

from .. import adapters, config
from ..core import db
from ..core.services import (Actor, Service, ServiceError, ServiceUnavailable,
                             load_object, sha256_bytes)
from .repository_access import RepositoryAccessMediation
from .version_authority import VersionAuthority


class FabricationJobAuthorization(Service):
    name = "job_authorization"
    title = "Fabrication Job Authorization"
    description = ("Authorizes a fabrication request, records the artifact and its "
                   "hash, transfers the job to the machine, and logs the transaction.")

    def __init__(self):
        self.va = VersionAuthority()
        self.custody = RepositoryAccessMediation()

    # -- the operation -----------------------------------------------------

    def submit(self, actor: Actor, printer_id: str, *, version_id: int | None = None,
               sha256: str | None = None, data: bytes | None = None,
               file_name: str | None = None, note: str = "",
               allow_superseded: bool = False,
               print_after_upload: bool | None = None) -> dict:
        """
        Authorize and transfer one fabrication job.

        Supply either `version_id` (the normal path: fabricate a known
        version) or `data` + `file_name` (an artifact already in the manifest
        but not under version control, e.g. sliced output).
        """
        self.require_mediated()
        printer = self._printer(printer_id)

        version = design = None
        if version_id is not None:
            version = self.va.get_version(version_id)
            design = self.va.get_design(version["design_id"])
            data = load_object(version["sha256"])
            sha256 = version["sha256"]
            file_name = file_name or design["name"]
        elif data is not None:
            sha256 = sha256 or sha256_bytes(data)
            if not file_name:
                raise ServiceError("file_name is required when submitting raw content")
        else:
            raise ServiceError("supply either version_id or data + file_name")

        file_name = Path(file_name).name
        ext = Path(file_name).suffix.lower()
        if ext not in config.JOB_ALLOWED_EXTENSIONS:
            raise ServiceError(
                f"'{ext}' is not a fabricable format. Allowed: "
                f"{', '.join(sorted(config.JOB_ALLOWED_EXTENSIONS))}. Slice the design "
                f"first and submit the sliced output.")

        # 1. provenance
        entry = db.q1("SELECT * FROM manifest WHERE sha256=? AND revoked=0", (sha256,))
        if entry is None:
            revoked = db.q1("SELECT * FROM manifest WHERE sha256=?", (sha256,))
            raise ServiceError(
                f"{sha256[:12]} is {'revoked in' if revoked else 'not in'} the authorized "
                f"manifest. Technical data must pass through Ingest Mediation before it "
                f"can be fabricated.")

        # 2. version authority
        superseded_warning = None
        if version is not None:
            current = self.va.current_version(version["design_id"])
            if current and current["id"] != version["id"]:
                superseded_warning = (
                    f"v{version['version_no']} is superseded by v{current['version_no']}")
                if not allow_superseded:
                    raise ServiceError(
                        f"{superseded_warning}. Submit the current version, or "
                        f"re-submit with the superseded override and a reason -- the "
                        f"override is recorded against you.")

        # 3. authorization row, written before the transfer
        remote_path = posixpath.join(config.JOB_TARGET_DIR, file_name)
        storage = config.JOB_TARGET_STORAGE
        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO fabrication_authorization"
                "(ts, operator, device, printer_id, design_id, version_id, sha256,"
                " file_name, remote_path, storage, status, note)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,'AUTHORIZED',?)",
                (db.now(), actor.operator, actor.device, printer_id,
                 (design or {}).get("id"), (version or {}).get("id"), sha256,
                 file_name, remote_path, storage,
                 (note + (f" [superseded override: {superseded_warning}]"
                          if superseded_warning else "")).strip()))
            auth_id = cur.lastrowid

        self.emit("job.authorized", actor, subject=printer_id,
                  data={"authorization_id": auth_id, "sha256": sha256,
                        "file_name": file_name, "remote_path": remote_path,
                        "storage": storage, "version_id": (version or {}).get("id"),
                        "design_id": (design or {}).get("id"),
                        "superseded_override": superseded_warning, "note": note})

        if superseded_warning:
            self.finding(
                "WARNING", "job.superseded_authorized", printer_id,
                f"{actor.operator} authorized fabrication of a superseded version: "
                f"{superseded_warning}",
                {"authorization_id": auth_id, "operator": actor.operator,
                 "device": actor.device, "note": note, "sha256": sha256},
                dedup_key=f"superseded-job:{auth_id}")

        # 4. transfer
        print_after = (config.JOB_PRINT_AFTER_UPLOAD if print_after_upload is None
                       else print_after_upload)
        try:
            result = printer.upload(storage, remote_path, data,
                                    print_after=print_after, overwrite=True)
        except Exception as exc:
            with db.tx() as c:
                c.execute("UPDATE fabrication_authorization SET status='FAILED',"
                          " error=? WHERE id=?", (str(exc), auth_id))
            self.emit("job.transfer_failed", actor, subject=printer_id,
                      data={"authorization_id": auth_id, "error": str(exc)})
            raise ServiceUnavailable(
                f"Authorized, but the transfer to {printer.label} failed: {exc}. "
                f"The authorization is recorded as FAILED. If the machine is "
                f"unreachable and the job must go ahead, open a break-glass "
                f"exception so the gap is accounted for.") from exc

        with db.tx() as c:
            c.execute("UPDATE fabrication_authorization SET status='TRANSFERRED',"
                      " transferred_ts=? WHERE id=?", (db.now(), auth_id))

        self.custody.record_custody(
            actor, "SUBMIT", design_id=(design or {}).get("id"),
            version_id=(version or {}).get("id"), sha256=sha256, name=file_name,
            purpose=f"fabrication on {printer_id}" + (f": {note}" if note else ""))

        self.emit("job.transferred", actor, subject=printer_id,
                  data={"authorization_id": auth_id, "sha256": sha256,
                        "remote_path": remote_path, "storage": storage,
                        "print_after_upload": print_after,
                        "transfer_result": result})
        return self.get(auth_id)

    def cancel(self, actor: Actor, auth_id: int, reason: str = "") -> dict:
        row = self.get(auth_id)
        if row["status"] in ("CANCELLED",):
            raise ServiceError("already cancelled")
        with db.tx() as c:
            c.execute("UPDATE fabrication_authorization SET status='CANCELLED',"
                      " note=COALESCE(note,'')||? WHERE id=?",
                      (f" [cancelled by {actor.operator}: {reason}]", auth_id))
        self.emit("job.cancelled", actor, subject=row["printer_id"],
                  data={"authorization_id": auth_id, "reason": reason})
        return self.get(auth_id)

    # -- what reconciliation reads ----------------------------------------

    @staticmethod
    def find_authorization(printer_id: str, *, sha256: str | None = None,
                           file_name: str | None = None) -> dict | None:
        """
        Is there an authorization matching this observed job?

        Matched on hash first, because the hash is what was authorized. Name
        is a fallback for the common case where the machine reports a file
        name and the service has not yet hashed what is on the media -- it is
        weaker, and the caller records which basis matched.
        """
        if sha256:
            row = db.q1(
                "SELECT * FROM fabrication_authorization WHERE printer_id=? AND sha256=?"
                " AND status IN ('AUTHORIZED','TRANSFERRED')"
                " ORDER BY id DESC LIMIT 1", (printer_id, sha256))
            if row:
                return dict(row) | {"match_basis": "hash"}
        if file_name:
            base = Path(file_name).name
            row = db.q1(
                "SELECT * FROM fabrication_authorization WHERE printer_id=?"
                " AND (file_name=? OR remote_path LIKE ?)"
                " AND status IN ('AUTHORIZED','TRANSFERRED')"
                " ORDER BY id DESC LIMIT 1", (printer_id, base, f"%/{base}"))
            if row:
                return dict(row) | {"match_basis": "name"}
        return None

    # -- reads -------------------------------------------------------------

    def get(self, auth_id: int) -> dict:
        row = db.q1(
            "SELECT a.*, d.name AS design_name, d.repo_path, v.version_no"
            " FROM fabrication_authorization a"
            " LEFT JOIN design d ON d.id=a.design_id"
            " LEFT JOIN design_version v ON v.id=a.version_id WHERE a.id=?", (auth_id,))
        if not row:
            raise ServiceError(f"no authorization {auth_id}")
        return dict(row)

    def recent(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in db.q(
            "SELECT a.*, d.name AS design_name, v.version_no"
            " FROM fabrication_authorization a"
            " LEFT JOIN design d ON d.id=a.design_id"
            " LEFT JOIN design_version v ON v.id=a.version_id"
            " ORDER BY a.id DESC LIMIT ?", (limit,))]

    def _printer(self, printer_id: str):
        try:
            return adapters.get_printer(printer_id)
        except KeyError:
            raise ServiceError(f"no printer '{printer_id}' in config.PRINTERS")


def demo() -> int:
    from ..core import db as _db
    from ..adapters.printer_sim import SimulatedPrinter
    _db.connect()
    SimulatedPrinter.reset()
    config.PRINTERS = [{"id": "sim-01", "label": "Simulated", "driver": "simulator",
                        "scenario": "idle"}]

    va = VersionAuthority()
    svc = FabricationJobAuthorization()
    alice = Actor("alice", "ws-01")

    # a sliced artifact has to be in the manifest before it can be fabricated
    gcode_v1 = b"; sliced bracket v1\nG1 X0 Y0\n" + b"g" * 400
    gcode_v2 = b"; sliced bracket v2\nG1 X1 Y1\n" + b"g" * 400
    v1 = va.publish(alice, "projects/bracket.bgcode", gcode_v1, "first slice")
    v2 = va.publish(alice, "projects/bracket.bgcode", gcode_v2, "re-sliced")

    print("submitting without a manifest entry:")
    try:
        svc.submit(alice, "sim-01", version_id=v2["id"])
        print("  accepted -- bug")
        return 1
    except ServiceError as exc:
        print(f"  refused: {str(exc)[:110]}")

    for v, blob in ((v1, gcode_v1), (v2, gcode_v2)):
        with _db.tx() as c:
            c.execute("INSERT OR IGNORE INTO manifest(sha256,size,name,source_path,"
                      "note,approved_by,approved_ts) VALUES (?,?,?,?,?,?,?)",
                      (v["sha256"], len(blob), "bracket.bgcode", "demo", "",
                       "alice", _db.now()))

    print("\nsubmitting the superseded version:")
    try:
        svc.submit(alice, "sim-01", version_id=v1["id"])
        print("  accepted without override -- bug")
        return 1
    except ServiceError as exc:
        print(f"  refused: {str(exc)[:130]}")

    print("\nsubmitting the current version:")
    job = svc.submit(alice, "sim-01", version_id=v2["id"], note="test fit",
                     print_after_upload=True)
    print(f"  auth #{job['id']}  {job['status']}  -> {job['storage']}{job['remote_path']}")

    print("\nsubmitting the superseded version WITH an override:")
    job2 = svc.submit(alice, "sim-01", version_id=v1["id"], allow_superseded=True,
                      note="reprint for an already-fielded assembly")
    print(f"  auth #{job2['id']}  {job2['status']}  note: {job2['note']}")

    print("\nwhat reconciliation will see:")
    found = svc.find_authorization("sim-01", sha256=v2["sha256"])
    print(f"  lookup by hash   -> auth #{found['id']} ({found['match_basis']})")
    found = svc.find_authorization("sim-01", file_name="bracket.bgcode")
    print(f"  lookup by name   -> auth #{found['id']} ({found['match_basis']})")
    print(f"  unknown hash     -> {svc.find_authorization('sim-01', sha256='00'*32)}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(demo())

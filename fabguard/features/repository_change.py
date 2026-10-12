"""
features/repository_change.py -- Repository Change Detection  [FEATURE 3]

Snapshots the shared storage on an interval and records what was added,
modified or deleted since last time. In the OBSERVATIONAL variant this is the
version history -- the only record that a design file was overwritten, and the
only way to answer "what did this file used to be". In the MEDIATED variant it
also answers a narrower question: which changes happened outside the sanctioned
write path, because any change the service did not itself perform arrived some
other way.

WHAT IT CANNOT DO, AND THE WRITE-UP SHOULD SAY SO
  - It cannot attribute. A mounted CIFS share exposes no SMB audit trail, so
    a change is observed without an actor. That is precisely the attribution
    gap the architecture claims enterprise controls leave open, and this
    feature demonstrates the gap rather than closing it.
  - It is interval-bound. A file modified and restored between two snapshots
    is never seen. Same blind spot as the printer polling, same mitigation
    (shorter interval), same cost.
  - Deletion followed by re-creation with identical contents is recorded as
    DELETED then ADDED, which is honest but noisy.

Standalone:
    python3 -m fabguard.features.repository_change
"""

from __future__ import annotations

import time

from .. import config
from ..adapters.repository_fs import FilesystemRepository, diff
from ..core import db
from ..core.registry import Feature, FeatureResult, standalone

SEVERITY = {"ADDED": "INFO", "MODIFIED": "NOTICE", "DELETED": "WARNING"}


class RepositoryChangeDetection(Feature):
    name = "repository_change"
    title = "Repository Change Detection"
    description = ("Periodically snapshots shared storage and records artifact "
                   "additions, modifications and deletions, building the version "
                   "history the share itself does not keep.")

    def collect(self) -> FeatureResult:
        repo = FilesystemRepository()
        ok, why = repo.available()
        if not ok:
            # Distinguish an unmounted share from an empty one. Treating an
            # unreachable mount as "zero files" would record every artifact
            # in the repository as deleted, which is both wrong and alarming.
            self.finding("WARNING", "repository.unavailable", str(repo.root),
                         f"Shared storage is not readable: {why}",
                         {"root": str(repo.root),
                          "note": "Snapshot skipped. An unreadable mount is not an "
                                  "empty repository, so no deletions were recorded."},
                         dedup_key=f"repo-unavailable:{repo.root}")
            raise FileNotFoundError(why)

        previous = {r["path"]: dict(r) for r in db.q("SELECT * FROM repo_entry")}
        first_run = not previous

        t0 = time.time()
        scan = repo.scan(previous)
        duration = time.time() - t0

        changes = diff(previous, scan.files)
        tally = {"ADDED": 0, "MODIFIED": 0, "DELETED": 0}
        for ch in changes:
            tally[ch["change"]] += 1

        snapshot_id = self._write_snapshot(scan, tally, duration)
        if first_run:
            # Everything looks new on the first run. Recording 400 ADDED
            # findings on day one buries the one that matters on day two.
            self._seed(scan)
            self.emit("repository.baseline", subject=str(repo.root),
                      data={"files": len(scan.files), "bytes": scan.byte_count,
                            "snapshot_id": snapshot_id})
            summary = (f"baseline: {len(scan.files)} file(s), "
                       f"{scan.byte_count / 1e6:.1f} MB, {duration:.1f}s")
            return FeatureResult(summary,
                                 {"files": len(scan.files), "baseline": 1,
                                  "skipped_hash": len(scan.skipped),
                                  "errors": len(scan.errors)},
                                 0, {"root": str(repo.root)})

        self._record_changes(snapshot_id, changes)
        self._replace_entries(scan, [c["path"] for c in changes if c["change"] == "DELETED"])

        for ch in changes:
            self.emit(f"repository.{ch['change'].lower()}", subject=ch["path"],
                      data={k: ch[k] for k in
                            ("old_sha256", "new_sha256", "old_size", "new_size", "basis")})

        self._raise_findings(changes)

        counts = {"files": len(scan.files), **{k.lower(): v for k, v in tally.items()},
                  "skipped_hash": len(scan.skipped), "errors": len(scan.errors),
                  "duration_s": round(duration, 2)}
        summary = (f"{len(scan.files)} file(s); {tally['ADDED']} added, "
                   f"{tally['MODIFIED']} modified, {tally['DELETED']} deleted "
                   f"({duration:.1f}s)")
        return FeatureResult(summary, counts, len(changes),
                             {"root": str(repo.root),
                              "errors": scan.errors[:10]})

    # -- persistence -------------------------------------------------------

    def _write_snapshot(self, scan, tally: dict, duration: float) -> int:
        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO repo_snapshot"
                "(ts, root, file_count, byte_count, added, modified, deleted, duration_s)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (db.now(), scan.root, len(scan.files), scan.byte_count,
                 tally["ADDED"], tally["MODIFIED"], tally["DELETED"], duration))
            return cur.lastrowid

    def _seed(self, scan) -> None:
        now = db.now()
        with db.tx() as c:
            c.executemany(
                "INSERT INTO repo_entry(path, size, mtime, sha256, first_seen_ts, last_seen_ts)"
                " VALUES (?,?,?,?,?,?)",
                [(f.path, f.size, f.mtime, f.sha256, now, now)
                 for f in scan.files.values()])

    def _replace_entries(self, scan, deleted_paths: list[str]) -> None:
        """
        Bring repo_entry into line with the scan.

        Deletions come from the diff rather than a `NOT IN (...)` over every
        path: that would need one bound parameter per file and SQLite caps
        those, so a share with a few thousand artifacts would fail at exactly
        the size where this feature starts being useful.
        """
        now = db.now()
        with db.tx() as c:
            if deleted_paths:
                c.executemany("DELETE FROM repo_entry WHERE path=?",
                              [(p,) for p in deleted_paths])
            c.executemany(
                "INSERT INTO repo_entry(path, size, mtime, sha256, first_seen_ts, last_seen_ts)"
                " VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(path) DO UPDATE SET size=excluded.size,"
                "   mtime=excluded.mtime, sha256=excluded.sha256,"
                "   last_seen_ts=excluded.last_seen_ts",
                [(f.path, f.size, f.mtime, f.sha256, now, now)
                 for f in scan.files.values()])

    def _record_changes(self, snapshot_id: int, changes: list[dict]) -> None:
        if not changes:
            return
        now = db.now()
        with db.tx() as c:
            c.executemany(
                "INSERT INTO repo_change"
                "(snapshot_id, ts, path, change, old_sha256, new_sha256,"
                " old_size, new_size, sanctioned)"
                " VALUES (?,?,?,?,?,?,?,?,0)",
                [(snapshot_id, now, ch["path"], ch["change"], ch["old_sha256"],
                  ch["new_sha256"], ch["old_size"], ch["new_size"])
                 for ch in changes])

    # -- findings ----------------------------------------------------------

    def _raise_findings(self, changes: list[dict]) -> None:
        mods = [c for c in changes if c["change"] == "MODIFIED"]
        dels = [c for c in changes if c["change"] == "DELETED"]

        for ch in mods:
            self.finding(
                "NOTICE", "repository.modified", ch["path"],
                f"'{ch['path']}' was modified in shared storage",
                {"old_sha256": ch["old_sha256"], "new_sha256": ch["new_sha256"],
                 "old_size": ch["old_size"], "new_size": ch["new_size"],
                 "basis": ch["basis"],
                 "note": ("Observed by snapshot comparison. The mount exposes no SMB "
                          "audit trail, so this change has no attributable actor -- "
                          "which is the gap, not an omission.")},
                dedup_key=f"repo-mod:{ch['path']}:{ch['new_sha256'] or ch['new_size']}")

        for ch in dels:
            self.finding(
                "WARNING", "repository.deleted", ch["path"],
                f"'{ch['path']}' disappeared from shared storage",
                {"old_sha256": ch["old_sha256"], "old_size": ch["old_size"],
                 "note": "No prior version is retained by the share itself."},
                dedup_key=f"repo-del:{ch['path']}:{ch['old_sha256'] or ch['old_size']}")

        # A burst of deletions in one cycle looks different from one file
        # being tidied away, and is worth escalating on its own.
        if len(dels) >= 10:
            self.finding(
                "CRITICAL", "repository.mass_deletion", "repository",
                f"{len(dels)} artifacts disappeared from shared storage in a single "
                f"snapshot interval",
                {"count": len(dels), "sample": [c["path"] for c in dels[:20]]},
                dedup_key=f"repo-massdel:{db.now()[:13]}")


if __name__ == "__main__":
    standalone(RepositoryChangeDetection)

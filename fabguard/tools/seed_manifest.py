#!/usr/bin/env python3
"""
tools/seed_manifest.py -- approve everything currently in the repository into
the authorized data manifest, in one go.

    python3 -m fabguard.tools.seed_manifest

This is a bootstrap convenience for a demo, and it is the wrong thing to do in
practice: it approves whatever happens to be on the share right now, including
anything already altered. Approving through the portal, one artifact at a
time, with a named operator against each, is the real path. The event log
records which way it was done.
"""

import sys

from .. import config
from ..adapters.repository_fs import FilesystemRepository
from ..core import db, eventlog


def main() -> int:
    db.connect()
    repo = FilesystemRepository()
    ok, why = repo.available()
    if not ok:
        print(f"repository unavailable: {why}", file=sys.stderr)
        return 1

    actor = (input("approve as which operator? ").strip().lower() or "tools.seed_manifest")
    note = input("note (optional): ").strip() or "bulk-seeded from repository"

    scan = repo.scan()
    n = skipped = 0
    for rec in scan.files.values():
        if not rec.sha256:
            skipped += 1
            continue
        with db.tx() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO manifest"
                "(sha256, size, name, source_path, note, approved_by, approved_ts)"
                " VALUES (?,?,?,?,?,?,?)",
                (rec.sha256, rec.size, rec.path.rsplit("/", 1)[-1],
                 f"repository:{rec.path}", note, actor, db.now()))
            if cur.rowcount:
                n += 1
    eventlog.emit("manifest.bulk_seeded", actor=actor, feature="tools",
                  subject=str(config.REPOSITORY_PATH),
                  data={"approved": n, "skipped_unhashed": skipped,
                        "note": note, "root": scan.root})
    print(f"approved {n} artifact(s) into the manifest "
          f"({skipped} skipped for having no hash)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

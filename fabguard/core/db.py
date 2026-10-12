"""
core/db.py -- SQLite state.

Everything here is DERIVED and rebuildable by re-running the collectors. The
authoritative record of what the service did is the append-only event log;
this database exists so the portal can answer questions quickly and so each
feature can diff the current observation against the previous one.

One exception: the `manifest` table is operator-curated (an artifact is
approved by a named person through the portal) and the `users` table holds
credentials. Both are also written to the event log as they change, so the
database can be rebuilt from the log if it is lost.

Standalone:
    python3 -m fabguard.core.db       # create/migrate, then print a row count
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from .. import config

_LOCAL = threading.local()

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ---------------------------------------------------------------- identity
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL DEFAULT '',
    pw_salt       BLOB NOT NULL,
    pw_hash       BLOB NOT NULL,
    created_ts    TEXT NOT NULL,
    last_login_ts TEXT,
    disabled      INTEGER NOT NULL DEFAULT 0
);

-- ------------------------------------------- F1 fabrication activity
-- One row per poll in which something was worth keeping.
CREATE TABLE IF NOT EXISTS activity_sample (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    printer_id  TEXT NOT NULL,
    state       TEXT,
    job_id      TEXT,
    job_file    TEXT,
    progress    REAL,
    time_printing INTEGER,
    time_remaining INTEGER,
    temp_nozzle REAL,
    temp_bed    REAL,
    raw         TEXT                      -- full response, for anything not modelled
);
CREATE INDEX IF NOT EXISTS ix_activity_ts ON activity_sample(ts);
CREATE INDEX IF NOT EXISTS ix_activity_printer ON activity_sample(printer_id, ts);

-- One row per observed fabrication job, opened on first sighting.
CREATE TABLE IF NOT EXISTS fabrication_job (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    printer_id    TEXT NOT NULL,
    job_key       TEXT NOT NULL,          -- printer_id + job id (or file+start)
    job_id        TEXT,
    file_name     TEXT,
    file_path     TEXT,
    file_size     INTEGER,
    file_m_timestamp INTEGER,
    first_seen_ts TEXT NOT NULL,
    last_seen_ts  TEXT NOT NULL,
    end_state     TEXT,
    authorized    INTEGER NOT NULL DEFAULT 0,
    authorization_ref TEXT,
    reconciled    INTEGER NOT NULL DEFAULT 0,
    -- set by reconciliation when a job falls inside an open break-glass
    -- window: still unauthorized, but expected and accounted for
    exception_id  INTEGER,
    UNIQUE(job_key)
);

-- --------------------------------------- F2 fabrication artifact verification
-- What is currently sitting on equipment-attached media.
CREATE TABLE IF NOT EXISTS equipment_artifact (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    printer_id    TEXT NOT NULL,
    storage       TEXT NOT NULL,
    path          TEXT NOT NULL,
    name          TEXT,
    size          INTEGER,
    m_timestamp   INTEGER,
    sha256        TEXT,
    verdict       TEXT,                   -- AUTHORIZED | UNRECOGNIZED | ALTERED | UNVERIFIED
    manifest_id   INTEGER,
    first_seen_ts TEXT NOT NULL,
    last_seen_ts  TEXT NOT NULL,
    cached_copy   TEXT,
    UNIQUE(printer_id, storage, path)
);

-- Operator-approved technical data. The reference every verification is against.
CREATE TABLE IF NOT EXISTS manifest (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256       TEXT NOT NULL,
    size         INTEGER,
    name         TEXT,
    source_path  TEXT,
    note         TEXT,
    approved_by  TEXT NOT NULL,
    approved_ts  TEXT NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0,
    revoked_by   TEXT,
    revoked_ts   TEXT,
    UNIQUE(sha256)
);

-- ------------------------------------------ F3 repository change detection
CREATE TABLE IF NOT EXISTS repo_snapshot (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    root        TEXT NOT NULL,
    file_count  INTEGER NOT NULL,
    byte_count  INTEGER NOT NULL,
    added       INTEGER NOT NULL DEFAULT 0,
    modified    INTEGER NOT NULL DEFAULT 0,
    deleted     INTEGER NOT NULL DEFAULT 0,
    duration_s  REAL
);

-- Current state of the share, one row per path. Replaced each snapshot.
CREATE TABLE IF NOT EXISTS repo_entry (
    path        TEXT PRIMARY KEY,
    size        INTEGER,
    mtime       REAL,
    sha256      TEXT,
    first_seen_ts TEXT NOT NULL,
    last_seen_ts  TEXT NOT NULL
);

-- Version history, which is the point of the feature in the observational
-- variant: one row per observed change to a path.
CREATE TABLE IF NOT EXISTS repo_change (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    ts          TEXT NOT NULL,
    path        TEXT NOT NULL,
    change      TEXT NOT NULL,            -- ADDED | MODIFIED | DELETED
    old_sha256  TEXT,
    new_sha256  TEXT,
    old_size    INTEGER,
    new_size    INTEGER,
    sanctioned  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(snapshot_id) REFERENCES repo_snapshot(id)
);
CREATE INDEX IF NOT EXISTS ix_repo_change_ts ON repo_change(ts);
CREATE INDEX IF NOT EXISTS ix_repo_change_path ON repo_change(path);

-- ------------------------------------- F4 equipment configuration inventory
CREATE TABLE IF NOT EXISTS equipment (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL,
    mac           TEXT,
    hostname      TEXT,
    printer_id    TEXT,
    kind          TEXT,                   -- PRINTER | UNKNOWN_HOST
    first_seen_ts TEXT NOT NULL,
    last_seen_ts  TEXT NOT NULL,
    present       INTEGER NOT NULL DEFAULT 1,
    UNIQUE(ip)
);

-- Configuration over time: one row per observed change, never overwritten.
CREATE TABLE IF NOT EXISTS equipment_config (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    equipment_id INTEGER NOT NULL,
    ts           TEXT NOT NULL,
    firmware     TEXT,
    api_version  TEXT,
    serial       TEXT,
    nozzle       TEXT,
    open_ports   TEXT,
    raw          TEXT,
    config_hash  TEXT NOT NULL,
    FOREIGN KEY(equipment_id) REFERENCES equipment(id)
);
CREATE INDEX IF NOT EXISTS ix_eqcfg ON equipment_config(equipment_id, ts);

-- ------------------------------------------------------------- findings
-- Anything a human should look at. Features write here; the portal reads it.
CREATE TABLE IF NOT EXISTS finding (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    feature     TEXT NOT NULL,
    severity    TEXT NOT NULL,            -- INFO | NOTICE | WARNING | CRITICAL
    kind        TEXT NOT NULL,
    subject     TEXT NOT NULL,
    summary     TEXT NOT NULL,
    detail      TEXT,
    acknowledged_by TEXT,
    acknowledged_ts TEXT,
    dedup_key   TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS ix_finding_ts ON finding(ts);

-- ============================================================== MEDIATED ==
-- Everything below exists only in the mediated variant. The tables are
-- always created so the schema is one thing rather than two, but nothing
-- writes to them when config.VARIANT is "observational".

-- ---------------------------------------------------- [M] Ingest Mediation
-- One row per artifact presented to the governed workflow. The operator's
-- declared origin is recorded as a CLAIM attributed to them, not as a fact
-- the service verified.
CREATE TABLE IF NOT EXISTS ingest_record (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    operator       TEXT NOT NULL,
    device         TEXT,
    original_name  TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    size           INTEGER NOT NULL,
    declared_origin TEXT NOT NULL,
    declared_note  TEXT,
    extension      TEXT,
    verdict        TEXT NOT NULL,       -- ACCEPTED | REJECTED | QUARANTINED
    scan_result    TEXT,                -- JSON: what normalisation found
    quarantine_path TEXT,
    object_path    TEXT,                -- content-addressed store, once accepted
    manifest_id    INTEGER,
    FOREIGN KEY(manifest_id) REFERENCES manifest(id)
);
CREATE INDEX IF NOT EXISTS ix_ingest_ts ON ingest_record(ts);
CREATE INDEX IF NOT EXISTS ix_ingest_sha ON ingest_record(sha256);

-- ---------------------------------------------------- [M] Version Authority
-- A design is the logical artifact; a design_version is one immutable state
-- of it. Versions are never edited or deleted -- supersession is explicit and
-- reverting creates a NEW version whose content equals an older one, so the
-- history stays append-only and a revert is itself visible.
CREATE TABLE IF NOT EXISTS design (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    repo_path     TEXT NOT NULL,
    created_by    TEXT NOT NULL,
    created_ts    TEXT NOT NULL,
    current_version_id INTEGER,
    retired       INTEGER NOT NULL DEFAULT 0,
    UNIQUE(repo_path)
);

CREATE TABLE IF NOT EXISTS design_version (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    design_id     INTEGER NOT NULL,
    version_no    INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    size          INTEGER NOT NULL,
    object_path   TEXT NOT NULL,
    published_by  TEXT NOT NULL,
    published_ts  TEXT NOT NULL,
    note          TEXT,
    supersedes_id INTEGER,              -- the version this replaced
    reverted_from_id INTEGER,           -- set when this version restores an older one
    ingest_id     INTEGER,
    UNIQUE(design_id, version_no),
    FOREIGN KEY(design_id) REFERENCES design(id),
    FOREIGN KEY(ingest_id) REFERENCES ingest_record(id)
);
CREATE INDEX IF NOT EXISTS ix_dv_design ON design_version(design_id, version_no);
CREATE INDEX IF NOT EXISTS ix_dv_sha ON design_version(sha256);

-- -------------------------------------- [M] Artifact Custody Recording
-- Who took which version of what, and when. The record that makes an
-- artifact found outside the controlled environment traceable to a custody
-- event rather than to nothing at all.
CREATE TABLE IF NOT EXISTS custody_record (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    operator      TEXT NOT NULL,
    device        TEXT,
    action        TEXT NOT NULL,        -- RETRIEVE | PUBLISH | SUBMIT | STAGE
    design_id     INTEGER,
    version_id    INTEGER,
    sha256        TEXT,
    name          TEXT,
    purpose       TEXT,
    FOREIGN KEY(design_id) REFERENCES design(id),
    FOREIGN KEY(version_id) REFERENCES design_version(id)
);
CREATE INDEX IF NOT EXISTS ix_custody_ts ON custody_record(ts);
CREATE INDEX IF NOT EXISTS ix_custody_op ON custody_record(operator, ts);

-- ------------------------------------ [M] Fabrication Job Authorization
-- The authorization record that Fabrication Job Reconciliation matches
-- observed machine activity against. Without this table every observed job
-- is unreconciled, which is exactly the observational variant.
CREATE TABLE IF NOT EXISTS fabrication_authorization (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    operator      TEXT NOT NULL,
    device        TEXT,
    printer_id    TEXT NOT NULL,
    design_id     INTEGER,
    version_id    INTEGER,
    sha256        TEXT NOT NULL,
    file_name     TEXT NOT NULL,
    remote_path   TEXT,
    storage       TEXT,
    status        TEXT NOT NULL,        -- AUTHORIZED | TRANSFERRED | FAILED | CANCELLED
    transferred_ts TEXT,
    error         TEXT,
    note          TEXT,
    matched_job_id INTEGER,             -- set by reconciliation
    FOREIGN KEY(design_id) REFERENCES design(id),
    FOREIGN KEY(version_id) REFERENCES design_version(id),
    FOREIGN KEY(matched_job_id) REFERENCES fabrication_job(id)
);
CREATE INDEX IF NOT EXISTS ix_auth_printer ON fabrication_authorization(printer_id, ts);
CREATE INDEX IF NOT EXISTS ix_auth_status ON fabrication_authorization(status);

-- ---------------------------------------------------- [M] Firmware Staging
CREATE TABLE IF NOT EXISTS firmware_image (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256        TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    size          INTEGER NOT NULL,
    version_label TEXT,
    object_path   TEXT NOT NULL,
    recorded_by   TEXT NOT NULL,
    recorded_ts   TEXT NOT NULL,
    note          TEXT
);

CREATE TABLE IF NOT EXISTS firmware_event (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    operator      TEXT NOT NULL,
    device        TEXT,
    printer_id    TEXT NOT NULL,
    firmware_id   INTEGER NOT NULL,
    action        TEXT NOT NULL,        -- STAGED | VERIFIED | APPLY_DECLARED | FAILED
    result        TEXT,
    observed_firmware TEXT,             -- what the machine reported afterwards
    note          TEXT,
    FOREIGN KEY(firmware_id) REFERENCES firmware_image(id)
);
CREATE INDEX IF NOT EXISTS ix_fw_event ON firmware_event(printer_id, ts);

-- ----------------------------------------------- [M] Degraded-Mode Operation
-- A break-glass exception. Time-limited by design: an exception that never
-- expires is a disabled control wearing a different name.
CREATE TABLE IF NOT EXISTS degraded_exception (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    opened_ts     TEXT NOT NULL,
    opened_by     TEXT NOT NULL,
    device        TEXT,
    reason        TEXT NOT NULL,
    detail        TEXT,
    expires_ts    TEXT NOT NULL,
    closed_ts     TEXT,
    closed_by     TEXT,
    close_note    TEXT,
    reconciled_ts TEXT,
    reconciled_by TEXT,
    jobs_observed INTEGER NOT NULL DEFAULT 0,
    reported      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_degraded_open ON degraded_exception(closed_ts);

-- ------------------------------------------------------------- run history
CREATE TABLE IF NOT EXISTS feature_run (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    feature     TEXT NOT NULL,
    started_ts  TEXT NOT NULL,
    duration_s  REAL,
    ok          INTEGER NOT NULL,
    summary     TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS ix_run ON feature_run(feature, started_ts);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def connect() -> sqlite3.Connection:
    """One connection per thread; the scheduler and the portal both use this."""
    conn = getattr(_LOCAL, "conn", None)
    if conn is None:
        config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(config.DB_PATH, timeout=30.0,
                               detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.executescript(SCHEMA)
        _LOCAL.conn = conn
    return conn


@contextmanager
def tx():
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def q(sql: str, params=()) -> list[sqlite3.Row]:
    return connect().execute(sql, params).fetchall()


def q1(sql: str, params=()):
    return connect().execute(sql, params).fetchone()


def jdump(obj) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


def record_run(feature: str, started: str, duration: float, ok: bool,
               summary: str = "", error: str = "") -> None:
    with tx() as c:
        c.execute(
            "INSERT INTO feature_run(feature, started_ts, duration_s, ok, summary, error)"
            " VALUES (?,?,?,?,?,?)",
            (feature, started, duration, 1 if ok else 0, summary, error))


def add_finding(feature: str, severity: str, kind: str, subject: str,
                summary: str, detail: dict | None = None,
                dedup_key: str | None = None) -> int | None:
    """
    Insert a finding. dedup_key makes re-raising the same condition on every
    poll a no-op, which matters when a feature runs every 30 seconds -- a
    findings list that repeats itself is a findings list nobody reads.
    Returns the new row id, or None if it was a duplicate.
    """
    with tx() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO finding"
            "(ts, feature, severity, kind, subject, summary, detail, dedup_key)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (now(), feature, severity, kind, subject, summary,
             jdump(detail or {}), dedup_key))
        return cur.lastrowid if cur.rowcount else None


if __name__ == "__main__":
    connect()
    print(f"database: {config.DB_PATH}")
    tables = [r["name"] for r in q(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        " ORDER BY name")]
    for t in tables:
        n = q1(f"SELECT COUNT(*) AS n FROM {t}")["n"]
        print(f"  {n:>7}  {t}")

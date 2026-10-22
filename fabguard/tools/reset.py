"""
tools/reset.py -- return the service to a clean state between workflow trials.

Every burden trial has to start from the same place or the timings are not
comparable, and a leftover file on the printer or in the share turns the next
run's reconciliation into noise. This clears the service state, and optionally
the two stores that live outside it.

WHAT IT TOUCHES, AND WHAT IT DOES NOT

    service state   data/fabguard.sqlite3, data/events.jsonl, and the four
                    file stores under data/. Always cleared.

    shared storage  the published/ subdirectory of the Samba share, and
                    optionally the whole share. Off unless switched on below,
                    because that directory holds your synthetic artifact set.

    printer         files under JOB_TARGET_DIR on each configured storage.
                    On by default: a file left on the stick from the previous
                    trial is indistinguishable, to Artifact Verification, from
                    an unsanctioned introduction, and it will raise a finding
                    on the next run.

THE APPEND-ONLY LOG

    events.jsonl carries the kernel append-only attribute when the lab is set
    up properly, and an append-only file cannot be unlinked -- not even by
    root -- until the attribute is cleared. This clears it with `chattr -a`,
    removes the log, and sets it again afterwards, so the fresh log is as
    protected as the one it replaced. Clearing the attribute needs
    CAP_LINUX_IMMUTABLE, so run this with sudo on the Pi. If the attribute was
    never set, nothing here changes that.

    The new log is not empty. Its first record is this reset, so the chain
    always begins with an accounted-for event rather than appearing to have
    been quietly truncated.

Run:
    sudo python3 -m solution.tools.reset
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from .. import config
from ..core import db, eventlog, identity

# -- configuration ---------------------------------------------------------

DRY_RUN = False                  # True reports what would go, removes nothing
REQUIRE_CONFIRMATION = True      # type RESET at the prompt before anything runs

RESET_REPOSITORY_PUBLISHED = False   # clear <share>/published/
RESET_REPOSITORY_ALL = False         # clear the WHOLE share -- read the warning
RESET_PRINTER_JOB_DIR = True         # clear JOB_TARGET_DIR on each printer

SEED_BOOTSTRAP_USER = True       # recreate the config.py account after the wipe
RESET_ACTOR = "system:reset"

# Directories under DATA_DIR whose contents are cleared but which are kept.
FILE_STORES = [
    ("object store", config.OBJECT_STORE),
    ("quarantine", config.QUARANTINE_DIR),
    ("artifact cache", config.ARTIFACT_CACHE),
    ("firmware store", config.FIRMWARE_STORE),
]

# --------------------------------------------------------------------------

removed = {"files": 0, "dirs": 0, "printer_files": 0, "errors": 0}


def say(msg: str) -> None:
    print(f"  {msg}")


def warn(msg: str) -> None:
    print(f"  ! {msg}", file=sys.stderr)
    removed["errors"] += 1


def rm_file(path: Path, label: str) -> None:
    if not path.exists():
        say(f"{label}: already absent")
        return
    if DRY_RUN:
        say(f"{label}: would remove {path}")
        return
    try:
        path.unlink()
        removed["files"] += 1
        say(f"{label}: removed")
    except PermissionError:
        warn(f"{label}: permission denied removing {path} -- run with sudo")
    except OSError as exc:
        warn(f"{label}: {exc}")


def clear_dir(path: Path, label: str, *, keep_root: bool = True) -> None:
    """Remove everything inside path. The directory itself is kept."""
    if not path.exists():
        say(f"{label}: not present")
        if not DRY_RUN and keep_root:
            path.mkdir(parents=True, exist_ok=True)
        return
    entries = list(path.iterdir())
    if not entries:
        say(f"{label}: already empty")
        return
    if DRY_RUN:
        say(f"{label}: would remove {len(entries)} entr"
            f"{'y' if len(entries) == 1 else 'ies'} from {path}")
        return
    n_f = n_d = 0
    for entry in entries:
        try:
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
                n_d += 1
            else:
                entry.unlink()
                n_f += 1
        except OSError as exc:
            warn(f"{label}: could not remove {entry.name}: {exc}")
    removed["files"] += n_f
    removed["dirs"] += n_d
    say(f"{label}: removed {n_f} file(s), {n_d} director(y/ies)")


# -- append-only handling --------------------------------------------------


def chattr(flag: str, path: Path) -> bool:
    try:
        r = subprocess.run(["chattr", flag, str(path)],
                           capture_output=True, text=True, timeout=5)
    except FileNotFoundError:
        warn("chattr not available on this host")
        return False
    except subprocess.SubprocessError as exc:
        warn(f"chattr {flag} failed: {exc}")
        return False
    if r.returncode != 0:
        warn(f"chattr {flag} {path} failed: {r.stderr.strip() or r.returncode}")
        return False
    return True


def reset_event_log() -> bool:
    """Remove the log, returning whether the append-only flag had been set."""
    path = config.EVENT_LOG_PATH
    was_append_only = bool(eventlog._has_append_only_flag())

    if was_append_only:
        say("event log: append-only attribute is set")
        if DRY_RUN:
            say("event log: would clear the attribute, remove, and set it again")
        elif chattr("-a", path):
            say("event log: attribute cleared")
        else:
            warn("event log: could not clear the append-only attribute. "
                 "The log cannot be removed until it is. Run with sudo.")
            return was_append_only

    rm_file(path, "event log")
    return was_append_only


def drop_db_connection() -> None:
    """
    Forget the cached connection to the database we just deleted.

    db.connect() memoises one connection per thread. If this process ever
    opened the database before the reset -- the selftest harness does, and so
    would any caller that imports this module rather than running it -- that
    cached handle still points at the unlinked inode, and every write made
    afterwards would land in a file with no directory entry. The schema and
    the seeded account would appear to be created and would not exist.
    """
    conn = getattr(db._LOCAL, "conn", None)
    if conn is None:
        return
    try:
        conn.close()
    except Exception:
        pass
    db._LOCAL.__dict__.pop("conn", None)
    say("database: dropped the stale connection handle")


def write_reset_record() -> None:
    """
    Start the new chain with this reset.

    Called before the bootstrap account is seeded, so that the first record in
    the fresh log is the reset rather than the user.created that seeding
    emits. A log whose first entry is an account creation looks like a log
    that was quietly truncated.
    """
    if DRY_RUN:
        return
    eventlog.emit(
        "service.reset", actor=RESET_ACTOR, feature="reset",
        subject="service state",
        data={"scope": {
            "service_state": True,
            "repository_published": RESET_REPOSITORY_PUBLISHED,
            "repository_all": RESET_REPOSITORY_ALL,
            "printer_job_dir": RESET_PRINTER_JOB_DIR},
            "note": "State cleared for a fresh workflow trial. Records "
                    "preceding this point are in the retired log, if it was "
                    "archived, and are otherwise gone."})
    say("event log: fresh chain started, first record is this reset")


def relock_event_log(was_append_only: bool) -> None:
    """Reinstate the append-only attribute, once everything has been written."""
    if DRY_RUN or not was_append_only:
        return
    if chattr("+a", config.EVENT_LOG_PATH):
        say("event log: append-only attribute restored")


# -- shared storage --------------------------------------------------------


def reset_repository() -> None:
    root = config.REPOSITORY_PATH
    if not (RESET_REPOSITORY_PUBLISHED or RESET_REPOSITORY_ALL):
        say("shared storage: skipped (both switches off)")
        return
    if not root.is_dir():
        warn(f"shared storage: {root} is not a directory -- is the share mounted?")
        return

    if RESET_REPOSITORY_ALL:
        clear_dir(root, f"shared storage {root}")
        return

    sub = (config.REPOSITORY_PUBLISH_SUBDIR or "").strip("/")
    if not sub:
        warn("shared storage: REPOSITORY_PUBLISH_SUBDIR is empty; refusing to "
             "treat the share root as the publish directory")
        return
    target = (root / sub).resolve()
    if root.resolve() not in target.parents and target != root.resolve():
        warn(f"shared storage: {target} resolves outside {root}; refusing")
        return
    if target == root.resolve():
        warn("shared storage: publish directory resolves to the share root; "
             "refusing. Set RESET_REPOSITORY_ALL if that is what you want.")
        return
    clear_dir(target, f"shared storage {target}")


# -- printer ---------------------------------------------------------------


def reset_printer_job_dir() -> None:
    if not RESET_PRINTER_JOB_DIR:
        say("printer: skipped (switch off)")
        return

    from .. import adapters

    prefix = "/" + config.JOB_TARGET_DIR.strip("/")
    for spec in config.PRINTERS:
        pid = spec.get("id", "?")
        try:
            printer = adapters.build_printer(spec)
        except SystemExit as exc:
            warn(f"printer {pid}: {exc}")
            continue

        try:
            if not printer.ping():
                say(f"printer {pid}: unreachable, skipped")
                continue
        except Exception as exc:
            say(f"printer {pid}: unreachable ({exc}), skipped")
            continue

        for storage in spec.get("storages", ["usb"]):
            try:
                entries = printer.walk(storage, prefix)
            except Exception as exc:
                say(f"printer {pid}/{storage}: nothing under {prefix} ({exc})")
                continue

            files = [e for e in entries if not e.get("is_dir")]
            if not files:
                say(f"printer {pid}/{storage}: {prefix} already clear")
                continue
            if DRY_RUN:
                say(f"printer {pid}/{storage}: would delete {len(files)} "
                    f"file(s) under {prefix}")
                continue

            ok = 0
            for entry in files:
                path = entry.get("path")
                if not path:
                    continue
                try:
                    printer.delete_file(storage, path)
                    ok += 1
                except Exception as exc:
                    warn(f"printer {pid}/{storage}: {path}: {exc}")
            removed["printer_files"] += ok
            say(f"printer {pid}/{storage}: deleted {ok} of {len(files)} "
                f"file(s) under {prefix}")


# -- driver ----------------------------------------------------------------


def scope_summary() -> list[str]:
    lines = [
        f"service database   {config.DB_PATH}",
        f"event log          {config.EVENT_LOG_PATH}",
    ]
    lines += [f"{label:<18} {path}" for label, path in FILE_STORES]
    if RESET_REPOSITORY_ALL:
        lines.append(f"shared storage     {config.REPOSITORY_PATH}  "
                     f"** ENTIRE SHARE **")
    elif RESET_REPOSITORY_PUBLISHED:
        lines.append(f"shared storage     {config.REPOSITORY_PATH}/"
                     f"{config.REPOSITORY_PUBLISH_SUBDIR}")
    if RESET_PRINTER_JOB_DIR:
        ids = ", ".join(p.get("id", "?") for p in config.PRINTERS)
        lines.append(f"printer job dir    {config.JOB_TARGET_DIR}  on: {ids}")
    return lines


def confirm() -> bool:
    if DRY_RUN or not REQUIRE_CONFIRMATION:
        return True
    try:
        return input("\nType RESET to proceed: ").strip() == "RESET"
    except (EOFError, KeyboardInterrupt):
        return False


def main() -> int:
    print("fabguard reset" + ("  [DRY RUN -- nothing will be removed]"
                              if DRY_RUN else ""))
    print("\nin scope:")
    for line in scope_summary():
        print(f"  {line}")
    if RESET_REPOSITORY_ALL:
        print("\n  WARNING: RESET_REPOSITORY_ALL clears every file in the "
              "share,\n           including your synthetic artifact set.")

    if not confirm():
        print("\naborted; nothing was changed.")
        return 1

    print("\nservice state")
    was_append_only = reset_event_log()
    rm_file(config.DB_PATH, "database")
    drop_db_connection()
    for label, path in FILE_STORES:
        clear_dir(path, label)

    print("\nshared storage")
    reset_repository()

    print("\nprinter")
    reset_printer_job_dir()

    if not DRY_RUN:
        print("\nreinitialise")
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        write_reset_record()          # before seeding, so it is record one
        db.connect()
        say("database: schema recreated")
        if SEED_BOOTSTRAP_USER:
            if identity.ensure_bootstrap_user():
                say(f"users: seeded '{config.BOOTSTRAP_USER}' "
                    f"with the config.py password")
            else:
                say("users: bootstrap not needed")
        relock_event_log(was_append_only)   # last: appends still work under +a

    print(f"\n{'would remove' if DRY_RUN else 'removed'}: "
          f"{removed['files']} file(s), {removed['dirs']} director(y/ies), "
          f"{removed['printer_files']} printer file(s)")
    if removed["errors"]:
        print(f"{removed['errors']} problem(s) above -- state may be partial.")
        return 2
    if not DRY_RUN:
        print("clean. Restart the service before the next trial.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
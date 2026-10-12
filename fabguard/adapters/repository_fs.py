"""
adapters/repository_fs.py -- the shared storage, as a filesystem path.

The Samba share on the second Pi is mounted with cifs-utils and this adapter
walks the mountpoint. Deliberately filesystem-based rather than speaking SMB
directly:

  - no extra dependency on the Pi
  - the same code runs against a local directory for bench testing
  - swapping in a native SMB backend later means implementing walk() and
    read_bytes() against smbprotocol and nothing else changes

Mount it read-only for the observational variant. A service that attests to
the integrity of a share it can also write to is asserting something it
cannot support.

What a mounted CIFS share does NOT give you, and the write-up should say so:
  - no SMB audit trail -- who wrote a file is invisible from the mount, which
    is exactly the attribution gap the architecture is about
  - mtime resolution and timezone depend on the server and mount options
  - a file modified and restored between two snapshots is not observed, the
    same interval-bound blind spot the printer polling has
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from .. import config


@dataclass
class RepoFile:
    path: str                 # relative to the root, forward slashes
    size: int
    mtime: float
    sha256: str | None = None
    hashed: bool = False
    error: str = ""

    def as_dict(self) -> dict:
        return {"path": self.path, "size": self.size, "mtime": self.mtime,
                "sha256": self.sha256, "hashed": self.hashed, "error": self.error}


@dataclass
class RepoScan:
    root: str
    files: dict[str, RepoFile] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def byte_count(self) -> int:
        return sum(f.size for f in self.files.values())


class FilesystemRepository:
    def __init__(self, root: Path | str | None = None):
        self.root = Path(root or config.REPOSITORY_PATH)

    def available(self) -> tuple[bool, str]:
        if not self.root.exists():
            return False, f"{self.root} does not exist (is the share mounted?)"
        if not self.root.is_dir():
            return False, f"{self.root} is not a directory"
        try:
            next(os.scandir(self.root), None)
        except PermissionError as exc:
            return False, f"{self.root} is not readable: {exc}"
        except OSError as exc:
            return False, f"{self.root} is not usable: {exc}"
        return True, "ok"

    def _ignored(self, name: str) -> bool:
        if name in config.REPOSITORY_IGNORE_NAMES:
            return True
        return any(name.startswith(p) for p in config.REPOSITORY_IGNORE_NAMES
                   if p.endswith("$") or p.startswith("~"))

    def _should_hash(self, path: Path, size: int) -> bool:
        if size > config.REPOSITORY_MAX_HASH_BYTES:
            return False
        return path.suffix.lower() in config.REPOSITORY_HASH_EXTENSIONS

    @staticmethod
    def sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def scan(self, previous: dict[str, dict] | None = None) -> RepoScan:
        """
        Walk the share.

        `previous` is the last snapshot keyed by path. A file whose size and
        mtime are unchanged keeps its previous hash instead of being re-read,
        which is what makes a snapshot over SMB finish in seconds rather than
        minutes. Set config.REPOSITORY_FORCE_REHASH to defeat that and catch
        a content change that preserved the timestamp.
        """
        ok, why = self.available()
        if not ok:
            raise FileNotFoundError(why)

        prev = previous or {}
        scan = RepoScan(root=str(self.root))

        for dirpath, dirnames, filenames in os.walk(self.root, onerror=lambda e: scan.errors.append(str(e))):
            dirnames[:] = [d for d in dirnames if not self._ignored(d)]
            for fn in filenames:
                if self._ignored(fn):
                    continue
                full = Path(dirpath) / fn
                try:
                    st = full.stat()
                except OSError as exc:
                    scan.errors.append(f"{full}: {exc}")
                    continue
                rel = full.relative_to(self.root).as_posix()
                rec = RepoFile(path=rel, size=st.st_size, mtime=st.st_mtime)

                old = prev.get(rel)
                unchanged = (old and not config.REPOSITORY_FORCE_REHASH
                             and old.get("size") == rec.size
                             and old.get("mtime") is not None
                             and abs(float(old["mtime"]) - rec.mtime) < 1e-6
                             and old.get("sha256"))
                if unchanged:
                    rec.sha256 = old["sha256"]
                    rec.hashed = True
                elif self._should_hash(full, rec.size):
                    try:
                        rec.sha256 = self.sha256_file(full)
                        rec.hashed = True
                    except OSError as exc:
                        rec.error = str(exc)
                        scan.errors.append(f"{rel}: {exc}")
                else:
                    scan.skipped.append(rel)

                scan.files[rel] = rec
        return scan

    def _safe(self, rel_path: str) -> Path:
        """
        Resolve a relative path inside the share, refusing to escape it.

        A symlink on the share pointing at /etc, or a path containing '..',
        is otherwise a read or write primitive against the service host. The
        share is written to by people the service does not control, so this
        check is load-bearing rather than defensive habit.
        """
        rel = str(rel_path).replace("\\", "/").lstrip("/")
        root = self.root.resolve()
        full = (root / rel).resolve()
        if full != root and root not in full.parents:
            raise PermissionError(f"{rel_path} resolves outside the repository root")
        return full

    def read_bytes(self, rel_path: str, max_bytes: int) -> bytes:
        full = self._safe(rel_path)
        if full.stat().st_size > max_bytes:
            raise ValueError(f"{rel_path} exceeds the {max_bytes} byte cap")
        return full.read_bytes()

    # -- writes: the mediated variant's sanctioned path -------------------

    def writable(self) -> tuple[bool, str]:
        ok, why = self.available()
        if not ok:
            return False, why
        probe = self.root / ".fabguard-write-probe"
        try:
            probe.write_bytes(b"")
            probe.unlink()
        except OSError as exc:
            return False, (f"{self.root} is not writable: {exc}. The mediated variant "
                           f"publishes through the service, so the share must be "
                           f"mounted rw (drop `ro` from the mount options).")
        return True, "ok"

    def write_bytes(self, rel_path: str, content: bytes, *,
                    overwrite: bool = False) -> Path:
        """
        Write through the sanctioned path.

        Writes to a temporary file in the same directory and renames it into
        place, so a reader on the share never sees a half-written artifact
        and a snapshot taken mid-write does not record a torn file as a
        modification.
        """
        full = self._safe(rel_path)
        if full.exists() and not overwrite:
            raise FileExistsError(f"{rel_path} already exists")
        full.parent.mkdir(parents=True, exist_ok=True)
        tmp = full.with_name(full.name + ".fabguard-tmp")
        try:
            tmp.write_bytes(content)
            os.replace(tmp, full)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
        return full

    def exists(self, rel_path: str) -> bool:
        try:
            return self._safe(rel_path).exists()
        except PermissionError:
            return False


def diff(old: dict[str, dict], new: dict[str, RepoFile]) -> list[dict]:
    """
    Compare two snapshots.

    A path is MODIFIED when its hash moved, or -- for files that were never
    hashed, because of size or extension -- when size or mtime moved. Hash
    comparison is the real test; the size/mtime fallback is explicitly weaker
    and the change record says which was used.
    """
    changes = []
    for path, rec in new.items():
        prior = old.get(path)
        if prior is None:
            changes.append({"path": path, "change": "ADDED",
                            "old_sha256": None, "new_sha256": rec.sha256,
                            "old_size": None, "new_size": rec.size,
                            "basis": "hash" if rec.sha256 else "metadata"})
            continue
        if rec.sha256 and prior.get("sha256"):
            if rec.sha256 != prior["sha256"]:
                changes.append({"path": path, "change": "MODIFIED",
                                "old_sha256": prior["sha256"], "new_sha256": rec.sha256,
                                "old_size": prior.get("size"), "new_size": rec.size,
                                "basis": "hash"})
            continue
        if (prior.get("size") != rec.size
                or (prior.get("mtime") is not None
                    and abs(float(prior["mtime"]) - rec.mtime) > 1.0)):
            changes.append({"path": path, "change": "MODIFIED",
                            "old_sha256": prior.get("sha256"), "new_sha256": rec.sha256,
                            "old_size": prior.get("size"), "new_size": rec.size,
                            "basis": "metadata"})
    for path, prior in old.items():
        if path not in new:
            changes.append({"path": path, "change": "DELETED",
                            "old_sha256": prior.get("sha256"), "new_sha256": None,
                            "old_size": prior.get("size"), "new_size": None,
                            "basis": "absence"})
    return changes

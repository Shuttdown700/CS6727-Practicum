"""
core/services.py -- the contract for request-driven mediation.

Two kinds of module do work in this service, and conflating them makes both
worse:

    features/   SCHEDULED COLLECTORS. A thread runs collect() on an interval.
                Nobody asked; the service is watching. Base class: Feature.

    services/   REQUEST-DRIVEN MEDIATION. An operator does something and a
                method runs once, synchronously, attributed to them. Base
                class: Service (here).

Every mediated feature in the architecture except Fabrication Job
Reconciliation is request-driven, which is why they are services. Collecting
them under Feature would mean inventing a meaningless collect() for each.

ATTRIBUTION IS THE WHOLE POINT
    A Service method takes an `Actor` -- a claimed operator identity on top of
    a device identity -- and records it. Never a bare username string: the
    architecture's claim is specifically that attribution resolves to a person
    *and* the device they used, and a function signature that can only carry
    one of those makes the weaker claim by accident.

Standalone testing: each service module ends with a demo() that exercises it
against a scratch database, so

    python3 -m solution.services.<name>

does something meaningful with no portal and no scheduler.
"""

from __future__ import annotations

import importlib
from abc import ABC
from dataclasses import dataclass

from .. import config
from . import db, eventlog


@dataclass(frozen=True)
class Actor:
    """
    Who did this.

    `operator` is a claimed identity: the portal login. It is NOT
    authenticated against an enterprise identity plane, because in this
    environment there isn't one that reaches these workstations -- which is
    the limitation the Operator Attribution feature exists to work around,
    and it should be described that way rather than as authentication.

    `device` is where the claim came from: client address, and hostname when
    it resolves. Together they are "operator X, working from device Y".
    """
    operator: str
    device: str = ""

    def __str__(self) -> str:
        return f"{self.operator}@{self.device}" if self.device else self.operator

    @property
    def log_actor(self) -> str:
        return self.operator

    def as_dict(self) -> dict:
        return {"operator": self.operator, "device": self.device}


SYSTEM = Actor("system", "localhost")


class ServiceError(RuntimeError):
    """A mediation decision that refused. The message is shown to the operator."""


class ServiceUnavailable(ServiceError):
    """
    A dependency the mediated path needs is not reachable.

    Distinct from ServiceError because this is the condition Degraded-Mode
    Operation exists for: the operator cannot proceed through the service and
    needs the break-glass path, rather than having done something wrong.
    """


class Service(ABC):
    name: str = "unnamed"
    title: str = "Unnamed service"
    description: str = ""
    variant: str = "mediated"       # every service here is mediated-only

    # -- plumbing ----------------------------------------------------------

    def emit(self, kind: str, actor: Actor, *, subject: str = "",
             data: dict | None = None):
        payload = dict(data or {})
        if config.ATTRIBUTION_RECORD_DEVICE and actor.device:
            payload.setdefault("device", actor.device)
        return eventlog.emit(kind, actor=actor.log_actor, feature=self.name,
                             subject=subject, data=payload)

    def finding(self, severity: str, kind: str, subject: str, summary: str,
                detail: dict | None = None, dedup_key: str | None = None) -> bool:
        rid = db.add_finding(self.name, severity, kind, subject, summary,
                             detail, dedup_key)
        if rid is None:
            return False
        eventlog.emit("finding.raised", actor=f"service:{self.name}",
                      feature=self.name, subject=subject,
                      data={"severity": severity, "kind": kind,
                            "summary": summary, "finding_id": rid,
                            **(detail or {})})
        return True

    def require_mediated(self) -> None:
        if not config.MEDIATED:
            raise ServiceError(
                f"{self.title} is a mediated-variant feature and "
                f"config.VARIANT is '{config.VARIANT}'.")


def load(name: str) -> Service:
    mod = importlib.import_module(f"..services.{name}", __package__)
    candidates = [v for v in vars(mod).values()
                  if isinstance(v, type) and issubclass(v, Service) and v is not Service]
    if not candidates:
        raise SystemExit(f"services/{name}.py defines no Service subclass")
    if len(candidates) > 1:
        exact = [c for c in candidates if getattr(c, "name", None) == name]
        if len(exact) != 1:
            raise SystemExit(
                f"services/{name}.py defines {len(candidates)} Service subclasses; "
                f"exactly one must have name == '{name}'")
        candidates = exact
    return candidates[0]()


def load_enabled() -> dict[str, Service]:
    out = {}
    for name in config.ENABLED_SERVICES:
        try:
            out[name] = load(name)
        except Exception as exc:
            eventlog.emit("service.load.error", feature=name, subject=name,
                          data={"error": str(exc)})
            print(f"[services] could not load '{name}': {exc}")
    return out


def available(name: str) -> bool:
    return name in config.ENABLED_SERVICES


# -- helpers shared by several services -----------------------------------

def sha256_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def store_object(data: bytes, digest: str | None = None) -> tuple[str, str]:
    """
    Put bytes in the content-addressed object store.

    Returns (sha256, path). Content-addressed because the identity of an
    artifact is its content, not the name somebody gave it -- which is the
    same reason verification compares hashes rather than filenames.
    Writing the same bytes twice is a no-op.
    """
    digest = digest or sha256_bytes(data)
    root = config.OBJECT_STORE / digest[:2]
    root.mkdir(parents=True, exist_ok=True)
    dest = root / digest
    if not dest.exists():
        tmp = dest.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(dest)
    return digest, str(dest)


def load_object(digest: str) -> bytes:
    path = config.OBJECT_STORE / digest[:2] / digest
    if not path.exists():
        raise ServiceError(f"object {digest[:12]} is not in the store")
    data = path.read_bytes()
    actual = sha256_bytes(data)
    if actual != digest:
        # The store is the service's own copy. If it does not match, the
        # thing that went wrong is on this host, and silently serving the
        # wrong bytes would undermine every downstream verification.
        raise ServiceError(
            f"object store corruption: {path} hashes to {actual[:12]}, "
            f"expected {digest[:12]}")
    return data

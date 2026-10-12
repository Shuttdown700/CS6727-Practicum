"""
adapters/__init__.py -- driver selection.

A printer entry in config.PRINTERS names a driver; this maps the name to a
class. Adding support for another machine (an Octoprint host, a Bambu
printer) means writing a class with the same methods and adding one line to
DRIVERS -- nothing in features/ changes.

The interface a printer driver must provide:

    ping()        -> bool
    version()     -> dict          legacy version endpoint
    info()        -> dict          identity / configuration
    status()      -> dict          raw status
    job()         -> dict | None   current job, None when idle
    storage()     -> list[dict]
    walk(storage) -> list[dict]    flattened file records with composed paths
    download(storage, path, max_bytes) -> bytes
    snapshot()    -> dict          normalised single poll (what F1 stores)
    identity()    -> dict          normalised configuration (what F4 stores)
"""

from __future__ import annotations

from .. import config
from .printer_prusalink import PrusaLinkPrinter
from .printer_sim import SimulatedPrinter

DRIVERS = {
    "prusalink": PrusaLinkPrinter,
    "simulator": SimulatedPrinter,
}


def build_printer(spec: dict):
    driver = spec.get("driver", "prusalink")
    cls = DRIVERS.get(driver)
    if cls is None:
        raise SystemExit(
            f"printer {spec.get('id')!r} names unknown driver {driver!r}; "
            f"available: {', '.join(sorted(DRIVERS))}")
    return cls(spec)


def all_printers() -> list:
    return [build_printer(s) for s in config.PRINTERS]


def get_printer(printer_id: str):
    for s in config.PRINTERS:
        if s["id"] == printer_id:
            return build_printer(s)
    raise KeyError(printer_id)

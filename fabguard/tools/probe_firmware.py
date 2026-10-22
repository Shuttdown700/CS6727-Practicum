"""
Probe: can PrusaLink SEE and READ BACK a .bbf placed on the stick by hand,
even though it refuses to accept one by upload?

Run it only AFTER physically copying the .bbf onto the USB drive and
re-inserting the drive in the printer.

    python3 -m fabguard.tools.probe_firmware

Storages come from config.PRINTERS, so it will not ask the machine for one it
does not have.
"""
import hashlib

from .. import adapters, config

PRINTER_ID = "mk4-01"

spec = next(s for s in config.PRINTERS if s["id"] == PRINTER_ID)
p = adapters.get_printer(PRINTER_ID)
print(f"{PRINTER_ID} reachable: {p.ping()}")

# What the printer itself says it has, rather than what config assumes.
try:
    reported = [s.get("name") or s.get("path") for s in p.storage()]
    print(f"storages reported by printer : {reported}")
except Exception as exc:
    print(f"storage query failed: {exc}")
print(f"storages in config           : {spec.get('storages', ['usb'])}\n")

for storage in spec.get("storages", ["usb"]):
    try:
        entries = p.walk(storage, "/")
    except Exception as exc:
        print(f"{storage}: walk failed -- {exc}")
        continue

    bbf = [e for e in entries if str(e.get("name", "")).lower().endswith(".bbf")]
    types = sorted({str(e.get("type")) for e in entries})
    print(f"{storage}: {len(entries)} entr(y/ies), types seen {types}, "
          f"{len(bbf)} .bbf")

    if not bbf:
        print(f"  no .bbf listed. Either it is not on the drive, or PrusaLink "
              f"filters non-printable files out of the listing.")
        print(f"  first few names: "
              f"{[e.get('name') for e in entries[:5]]}")
        continue

    for e in bbf:
        print(f"  name={e.get('name')}  path={e.get('path')}  "
              f"type={e.get('type')}  size={e.get('size')}")
        try:
            data = p.download(storage, e["path"], config.FIRMWARE_MAX_BYTES)
            print(f"  READ-BACK OK: {len(data)} bytes, "
                  f"sha256 {hashlib.sha256(data).hexdigest()[:16]}")
        except Exception as exc:
            print(f"  read-back FAILED: {exc}")
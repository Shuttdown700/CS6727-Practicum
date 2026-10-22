"""
Probe: can PrusaLink SEE and READ BACK a .bbf that was placed on the stick
by hand, even though it refuses to accept one by upload?

Put the .bbf on the USB drive physically, insert it in the printer, then:
    python3 -m solution.tools.probe_firmware        (or run this file directly)
"""
import sys
sys.path.insert(0, "/home/bshutt3/CS6727-Practicum")   # adjust to your repo root

from fabguard import adapters, config

p = adapters.get_printer("mk4-01")
print("reachable:", p.ping())

for storage in ("usb", "local"):
    try:
        entries = p.walk(storage, "/")
    except Exception as exc:
        print(f"{storage}: walk failed -- {exc}")
        continue
    bbf = [e for e in entries if str(e.get("name", "")).lower().endswith(".bbf")]
    print(f"\n{storage}: {len(entries)} entr(y/ies), {len(bbf)} .bbf")
    for e in bbf:
        print(f"   name={e.get('name')}  path={e.get('path')}  "
              f"type={e.get('type')}  size={e.get('size')}")
        try:
            data = p.download(storage, e["path"], config.FIRMWARE_MAX_BYTES)
            import hashlib
            print(f"   READ-BACK OK: {len(data)} bytes, "
                  f"sha256 {hashlib.sha256(data).hexdigest()[:16]}")
        except Exception as exc:
            print(f"   read-back FAILED: {exc}")
"""
adapters/printer_sim.py -- a scripted fake printer.

Same interface as PrusaLinkPrinter, so every feature can be exercised end to
end before the MK4 is on the bench, and so a demo can reproduce a specific
scenario on demand instead of waiting for one to happen.

Scenarios
    idle                     never prints; the quiet baseline
    authorized_print         prints a file that is in the manifest
    unauthorized_usb_print   prints a file that appeared on USB and is in no
                             manifest -- the case the architecture exists to
                             catch, and the one that currently leaves no trace
    altered_artifact         media holds a file whose name matches a manifest
                             entry but whose contents do not

State advances on each poll rather than on a wall clock, so a test can step
through a whole print in a few calls and the result is deterministic.
"""

from __future__ import annotations

import hashlib
import time

SCENARIOS = ("idle", "authorized_print", "unauthorized_usb_print", "altered_artifact")

# Files that "exist" on the simulated USB stick. Contents are generated so
# their hashes are stable across runs.
_MEDIA = {
    "authorized_print": [
        ("/bracket_v3.bgcode", b"AUTHORIZED-BRACKET-V3-" + b"g" * 2048),
    ],
    "unauthorized_usb_print": [
        ("/bracket_v3.bgcode", b"AUTHORIZED-BRACKET-V3-" + b"g" * 2048),
        ("/antenna_mount_thingiverse.bgcode", b"UNSANCTIONED-DOWNLOAD-" + b"x" * 4096),
    ],
    "altered_artifact": [
        ("/bracket_v3.bgcode", b"TAMPERED-BRACKET-V3-" + b"z" * 2048),
    ],
    "idle": [],
}

_PRINT_FILE = {
    "authorized_print": "/bracket_v3.bgcode",
    "unauthorized_usb_print": "/antenna_mount_thingiverse.bgcode",
    "altered_artifact": "/bracket_v3.bgcode",
    "idle": None,
}


class SimulatedPrinter:
    driver = "simulator"

    # Files uploaded through the mediated path, keyed by printer id so they
    # survive the adapter being rebuilt on each poll (features construct a
    # fresh printer object every cycle, exactly as they do for a real one).
    _UPLOADED: dict[str, dict[str, bytes]] = {}
    _STARTED: dict[str, str] = {}

    def __init__(self, spec: dict):
        self.id = spec["id"]
        self.label = spec.get("label", spec["id"])
        self.scenario = spec.get("scenario", "idle")
        if self.scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {self.scenario!r}; pick one of {SCENARIOS}")
        self.storages = list(spec.get("storages", ["usb"]))
        self.host = spec.get("host", "127.0.0.1")
        self.poll_count = 0
        self.job_length_polls = int(spec.get("job_length_polls", 4))
        self._started = time.time()
        self._UPLOADED.setdefault(self.id, {})

    @classmethod
    def reset(cls, printer_id: str | None = None) -> None:
        """Clear uploaded state. For tests that need a clean machine."""
        if printer_id:
            cls._UPLOADED.pop(printer_id, None)
            cls._STARTED.pop(printer_id, None)
        else:
            cls._UPLOADED.clear()
            cls._STARTED.clear()

    # -- media -------------------------------------------------------------

    def _media(self) -> list[tuple[str, bytes]]:
        """Scenario media plus anything uploaded through the mediated path."""
        return list(_MEDIA.get(self.scenario, [])) + \
            sorted(self._UPLOADED.get(self.id, {}).items())

    def _content(self, path: str) -> bytes | None:
        for p, data in self._media():
            if p == path:
                return data
        return None

    # -- probes ------------------------------------------------------------

    def ping(self) -> bool:
        return True

    def version(self) -> dict:
        return {"api": "2.0.0", "server": "2.1.2",
                "firmware": "6.1.3+simulated", "text": "PrusaLink (simulated)",
                "hostname": f"{self.id}.local"}

    def info(self) -> dict:
        return {"name": self.label, "serial": f"SIM-{self.id.upper()}",
                "hostname": f"{self.id}.local", "nozzle_diameter": 0.4,
                "sd_ready": True, "location": "bench", "farm_mode": False,
                "mmu": False}

    def storage(self) -> list[dict]:
        return [{"name": "usb", "path": "/usb/", "read_only": False,
                 "free_space": 7_000_000_000, "available": True}]

    def status(self) -> dict:
        job = self._current_job()
        printer = {
            "state": "PRINTING" if job else "IDLE",
            "temp_nozzle": 215.0 if job else 24.5,
            "target_nozzle": 215.0 if job else 0.0,
            "temp_bed": 60.0 if job else 23.8,
            "target_bed": 60.0 if job else 0.0,
            "axis_z": 4.2 if job else 0.0,
            "flow": 100, "speed": 100,
            "status_printer": {"ok": True, "message": "OK"},
            "status_connect": {"ok": False, "message": "Disabled"},
        }
        out = {"printer": printer}
        if job:
            out["job"] = {"id": job["id"], "progress": job["progress"],
                          "time_remaining": job["time_remaining"],
                          "time_printing": job["time_printing"]}
        return out

    def job(self) -> dict | None:
        return self._current_job()

    def _current_job(self) -> dict | None:
        # A print started through the mediated path takes precedence over the
        # scenario's scripted one: that is how an authorize -> upload -> start
        # -> observe -> reconcile round trip gets exercised end to end.
        started = self._STARTED.get(self.id)
        if started:
            data = self._content(started) or b""
            return {
                "id": 9001, "state": "PRINTING", "progress": 50.0,
                "time_printing": 600, "time_remaining": 600,
                "inaccurate_estimates": False,
                "file": {"name": started.lstrip("/").split("/")[-1],
                         "display_name": started.lstrip("/"),
                         "path": started, "display_path": started,
                         "size": len(data),
                         "m_timestamp": int(self._started),
                         "refs": {"download": f"/api/v1/files/usb{started}"}},
            }

        path = _PRINT_FILE.get(self.scenario)
        if not path:
            return None
        # Poll 1 is idle, then the job runs for job_length_polls, then idle
        # again -- so a test can observe a start, a middle and an end.
        n = self.poll_count
        if n < 1 or n > self.job_length_polls:
            return None
        frac = n / float(self.job_length_polls)
        data = self._content(path) or b""
        return {
            "id": 4711,
            "state": "PRINTING",
            "progress": round(frac * 100.0, 1),
            "time_printing": int(frac * 3600),
            "time_remaining": int((1 - frac) * 3600),
            "inaccurate_estimates": False,
            "file": {
                "name": path.lstrip("/"),
                "display_name": path.lstrip("/"),
                "path": path,
                "display_path": path,
                "size": len(data),
                "m_timestamp": int(self._started) - 600,
                "refs": {"download": f"/api/v1/files/usb{path}"},
            },
        }

    # -- files -------------------------------------------------------------

    def list_dir(self, storage: str, path: str = "/") -> dict:
        kids = []
        for p, data in self._media():
            kids.append({"name": p.lstrip("/"), "type": "PRINT_FILE",
                         "size": len(data), "m_timestamp": int(self._started) - 600,
                         "read_only": False,
                         "refs": {"download": f"/api/v1/files/{storage}{p}"}})
        return {"name": storage, "type": "FOLDER", "read_only": False,
                "children": kids}

    def walk(self, storage: str, path: str = "/", max_depth: int = 6) -> list[dict]:
        out = []
        for p, data in self._media():
            out.append({"storage": storage, "path": p, "name": p.lstrip("/"),
                        "display_name": p.lstrip("/"), "type": "PRINT_FILE",
                        "size": len(data),
                        "m_timestamp": int(self._started) - 600,
                        "read_only": False,
                        "download_ref": f"/api/v1/files/{storage}{p}"})
        return out

    def download(self, storage: str, path: str, max_bytes: int) -> bytes:
        data = self._content(path)
        if data is None:
            raise FileNotFoundError(f"{self.id}: no such file {path}")
        if len(data) > max_bytes:
            raise RuntimeError(f"{self.id}: {path} over the download cap")
        return data

    # -- writes ------------------------------------------------------------

    def upload(self, storage: str, path: str, content: bytes, *,
               print_after: bool = False, overwrite: bool = False) -> dict:
        p = path if path.startswith("/") else "/" + path
        store = self._UPLOADED.setdefault(self.id, {})
        if p in store and not overwrite:
            raise RuntimeError(f"{self.id}: {p} already exists and overwrite is off")
        store[p] = content
        if print_after:
            self._STARTED[self.id] = p
        return {"status_code": 201, "storage": storage, "path": p,
                "size": len(content), "print_after": print_after, "simulated": True}

    def start_print(self, storage: str, path: str) -> dict:
        p = path if path.startswith("/") else "/" + path
        if self._content(p) is None:
            raise FileNotFoundError(f"{self.id}: no such file {p}")
        self._STARTED[self.id] = p
        return {"status_code": 204, "storage": storage, "path": p, "simulated": True}

    def delete_file(self, storage: str, path: str) -> dict:
        p = path if path.startswith("/") else "/" + path
        self._UPLOADED.get(self.id, {}).pop(p, None)
        return {"status_code": 204, "storage": storage, "path": p, "simulated": True}

    def head_file(self, storage: str, path: str) -> dict | None:
        p = path if path.startswith("/") else "/" + path
        data = self._content(p)
        return None if data is None else {"status_code": 200, "size": len(data)}

    # -- normalised view ---------------------------------------------------

    def snapshot(self) -> dict:
        self.poll_count += 1
        st = self.status()
        job = self._current_job()
        printer = st["printer"]
        jf = (job or {}).get("file") or {}
        return {
            "printer_id": self.id,
            "state": printer["state"],
            "temp_nozzle": printer["temp_nozzle"],
            "target_nozzle": printer["target_nozzle"],
            "temp_bed": printer["temp_bed"],
            "target_bed": printer["target_bed"],
            "axis_z": printer["axis_z"],
            "flow": printer["flow"],
            "speed": printer["speed"],
            "job_id": str(job["id"]) if job else None,
            "job_state": (job or {}).get("state"),
            "progress": (job or {}).get("progress"),
            "time_printing": (job or {}).get("time_printing"),
            "time_remaining": (job or {}).get("time_remaining"),
            "file_name": jf.get("name"),
            "file_path": jf.get("path"),
            "file_size": jf.get("size"),
            "file_m_timestamp": jf.get("m_timestamp"),
            "raw": {"status": st, "job": job, "simulated": True,
                    "scenario": self.scenario, "poll": self.poll_count},
        }

    def identity(self) -> dict:
        v, i = self.version(), self.info()
        return {"printer_id": self.id, "host": self.host,
                "api_version": v["api"], "firmware": v["firmware"],
                "prusalink_version": v["server"], "name": i["name"],
                "serial": i["serial"], "hostname": i["hostname"],
                "nozzle": i["nozzle_diameter"], "sd_ready": i["sd_ready"],
                "location": i["location"], "farm_mode": i["farm_mode"],
                "raw_version": v, "raw_info": i, "simulated": True}

    @staticmethod
    def expected_hashes(scenario: str) -> dict[str, str]:
        """Hashes of the simulated media, so tests can assert against them."""
        return {p: hashlib.sha256(d).hexdigest() for p, d in _MEDIA.get(scenario, [])}

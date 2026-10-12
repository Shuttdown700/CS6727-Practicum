# fabguard — mediating-service prototype

A mediating-service prototype for Army makerspace fabrication workflows.
All fourteen architecture features, in both operating variants. Python, runs
on a Raspberry Pi 5, bare-bones web portal with operator authentication.

One switch picks the variant:

```python
# config.py
VARIANT = "mediated"        # or "observational"
```

Everything downstream follows from it — which collectors load, which portal
routes exist, whether a job can be reconciled at all. That is the comparison
the evaluation is built on, so it is one line rather than two deployments.

This is a **prototype to demonstrate functionality**, not a production
service. The limitations section is not boilerplate — it is the part the
write-up needs.

---

## The fourteen features

**Shared by both variants (M/O)**

| Feature | Module | Does |
|---|---|---|
| Fabrication Activity Recording | `features/fabrication_activity.py` | Polls equipment, records observed events and on-device technical data |
| Fabrication Artifact Verification | `features/artifact_verification.py` | Enumerates files on equipment media, hash-compares against the manifest |
| Repository Change Detection | `features/repository_change.py` | Snapshots shared storage; records additions, modifications, deletions |
| Equipment Configuration Inventory | `features/equipment_inventory.py` | Equipment on the network, firmware, network configuration over time |
| Append-Only Event Logging | `core/eventlog.py` | Hash-chained log of every service transaction, retained independently |

**Mediated variant only (M)**

| Feature | Module | Does |
|---|---|---|
| Ingest Mediation | `services/ingest.py` | Quarantines, checks, hashes, records with an operator-declared origin |
| Repository Access Mediation | `services/repository_access.py` | The sanctioned path to shared storage, both directions |
| Artifact Custody Recording | `services/repository_access.py` | Who took which version of what, and when |
| Version Authority | `services/version_authority.py` | Immutable versions, explicit supersession, revertability |
| Fabrication Job Authorization | `services/job_authorization.py` | Authorizes, records, transfers, logs — the sole path to a machine |
| Fabrication Job Reconciliation | `features/job_reconciliation.py` | Observed activity against authorization records |
| Firmware Staging | `services/firmware_staging.py` | Records, stages with read-back verification, logs declared application |
| Operator Attribution | `core/identity.py`, `core/services.py` | Claimed operator identity on top of device identity |
| Degraded-Mode Operation | `services/degraded_mode.py` | Logged, time-limited, reported break-glass exceptions |

Custody Recording shares a module with Repository Access Mediation because
they are one mechanism seen twice: mediating the path is what makes custody
recordable, and the custody record is the reason to mediate the path.

Event logging is in `core/` rather than `features/` because it is not a
collector: every other feature writes through it. Operator Attribution is
likewise not a module of its own — it is the `Actor` type that every
mediation call takes, so the device identity cannot be left out by accident.

### Two kinds of module, deliberately

```
features/   SCHEDULED COLLECTORS. A thread runs collect() on an interval.
            Nobody asked; the service is watching.      Base: Feature

services/   REQUEST-DRIVEN MEDIATION. An operator does something and a
            method runs once, attributed to them.       Base: Service
```

Every mediated feature except Fabrication Job Reconciliation is
request-driven. Forcing them into the collector shape would have meant
inventing a meaningless `collect()` for each.

---

## Layout

```
fabguard/
├── config.py              EVERY tunable. No CLI args, no env vars.
├── run.py                 start collectors + portal
├── core/
│   ├── eventlog.py        [F5] append-only hash-chained log
│   ├── db.py              SQLite schema and helpers
│   ├── registry.py        Feature base class + discovery
│   ├── scheduler.py       one thread per feature
│   └── identity.py        operators, scrypt hashes, attribution
├── adapters/
│   ├── printer_prusalink.py   Prusa MK4 over the LAN
│   ├── printer_sim.py         scripted fake printer, no hardware
│   └── repository_fs.py       the Samba share, as a mounted path
├── features/              one module per collector
├── web/                   Flask portal + templates
└── tools/
    ├── adduser.py         create an operator / change a password
    ├── seed_manifest.py   bulk-approve the current repository
    └── selftest.py        46 checks, no hardware needed
```

### Running one feature on its own

Each collector runs standalone with no scheduler and no portal, which is how
to test one in isolation:

```bash
python3 -m solution.features.fabrication_activity
python3 -m solution.features.artifact_verification
python3 -m solution.features.repository_change
python3 -m solution.features.equipment_inventory
```

Each does one collection cycle, prints its result as JSON, and exits non-zero
on failure. Core services are the same:

```bash
python3 -m solution.core.eventlog     # verify the chain, print a summary
python3 -m solution.core.db           # create/migrate, print row counts
python3 -m solution.core.identity     # list operators
```

Each mediation service has a standalone demonstration too — it exercises the
feature against a scratch database with no portal and no scheduler, and
prints what happened:

```bash
python3 -m solution.services.ingest              # incl. the CVE-2023-47268 refusal
python3 -m solution.services.version_authority   # publish, supersede, revert
python3 -m solution.services.repository_access   # publish, retrieve, custody
python3 -m solution.services.job_authorization   # manifest + version checks
python3 -m solution.services.firmware_staging    # record, stage, verify
python3 -m solution.services.degraded_mode       # open, extend, close, overdue
```

### Adding a feature

1. Drop a module in `features/` defining one `Feature` subclass with a
   `name`, a `title`, and a `collect()` returning a `FeatureResult`.
2. Add the name to `config.ENABLED_FEATURES`.
3. Add an interval to `config.FEATURE_INTERVALS_S`.

End the module with `standalone(YourClass)` under `if __name__ == "__main__"`
and it is independently runnable for free. Removing a feature means taking it
out of `ENABLED_FEATURES`; the module can stay. A feature that fails to import
is logged and skipped rather than stopping the others.

### Adding another machine

Write a class with the same methods as `PrusaLinkPrinter` (the contract is
listed at the top of `adapters/__init__.py`), add it to `DRIVERS`, and point a
`config.PRINTERS` entry at it. Nothing in `features/` changes.

---

## Setting it up on the Pi 5

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv cifs-utils
python3 -m venv ~/venv && source ~/venv/bin/activate
pip install flask requests

git clone <your repo> ~/fabguard-src     # or copy the tree
cd ~/fabguard-src
python3 -m solution.tools.selftest       # 96 checks, no hardware
```

### Mount the Samba share

**Observational:** mount read-only (`ro` below). A service that attests to
the integrity of a share it can also write to is asserting something it
cannot support.

**Mediated:** drop the `ro`. The service is the sanctioned write path, so it
needs to write — and workstation write access should be removed at the Samba
ACL, which is what makes "sole path" true in fact rather than only in policy.
Until that is done the service is the *sanctioned* path rather than the only
one, and Repository Change Detection exists to catch the difference. Say
which of the two is true of the lab when you report results.

```bash
sudo tee /etc/fabguard-smb.cred >/dev/null <<'EOF'
username=fabguard
password=...
domain=WORKGROUP
EOF
sudo chmod 600 /etc/fabguard-smb.cred

sudo mkdir -p /mnt/makerspace
echo '//192.168.50.20/designs /mnt/makerspace cifs credentials=/etc/fabguard-smb.cred,uid=1000,gid=1000,vers=3.1.1,ro,_netdev,nofail 0 0' \
  | sudo tee -a /etc/fstab
sudo mount -a
```

### Point it at the MK4

On the printer: **Settings → Network → PrusaLink**. Note the username
(default `maker`) and password, and enable the API.

In `config.py`:

```python
PRINTERS = [
    {"id": "mk4-01", "label": "Prusa MK4 (bay 1)", "driver": "prusalink",
     "host": "192.168.50.31", "port": 80,
     "username": "maker", "password": "<PrusaLink password>",
     "storages": ["usb"], "timeout_s": 8.0},
]
```

**Authentication is HTTP Digest, and that is all you need.** The PrusaLink
OpenAPI spec defines one security scheme and applies it to every operation,
including `/api/version`: HTTP Digest with the PrusaLink username and
password. No API key is required over the LAN. `api_key` in a printer spec is
optional and only sent if present, for the legacy `/api/*` endpoints on older
firmware — omit it unless something 401s.

### Run it

```bash
python3 -m solution.run        # collectors + portal on :8080
```

Before anything leaves the bench: change `SECRET_KEY` in `config.py`
(`python3 -c "import secrets; print(secrets.token_hex(32))"`), then change the
seeded operator password with `python3 -m solution.tools.adduser`. The portal
shows a banner until you do.

### As a service

```ini
# /etc/systemd/system/fabguard.service
[Unit]
Description=fabguard fabrication monitoring prototype
After=network-online.target remote-fs.target
Wants=network-online.target

[Service]
Type=simple
User=fabguard
WorkingDirectory=/home/fabguard/fabguard-src
ExecStart=/home/fabguard/venv/bin/python3 -m solution.run
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now fabguard
```

### Make the event log actually append-only

The hash chain makes tampering *detectable*. The kernel flag makes in-place
rewriting *fail*:

```bash
sudo chattr +a data/events.jsonl
```

After that even root cannot rewrite the file without clearing the flag, and
clearing it is itself an auditable act. The portal shows whether the flag is
set. Worth doing for the demo — it is a one-line change that materially
strengthens the claim.

---

## Testing without hardware

`config.PRINTERS` ships with a simulator entry. Scenarios:

| Scenario | Produces |
|---|---|
| `idle` | nothing; the quiet baseline |
| `authorized_print` | a print of a file that is in the manifest |
| `unauthorized_usb_print` | a print of a file that appeared on USB and is in no manifest |
| `altered_artifact` | media holding a file whose name matches a manifest entry but whose contents do not |

State advances per poll rather than per wall-clock second, so a whole print
steps through in a few calls and the result is deterministic.

`tools/selftest.py` goes further — 96 checks, no hardware. It stands up a mock
PrusaLink server that enforces HTTP Digest and answers with the shapes from
the published OpenAPI spec, including PUT uploads, so the *real* adapter is
exercised rather than the simulator. It then drives a complete mediated round
trip — ingest, publish, supersede, revert, retrieve, authorize, transfer,
observe, verify, reconcile by content hash — tampers with the event log to
confirm verification catches both an edited and a deleted record, and finally
flips `VARIANT` to observational and checks the mediated routes are *absent*
rather than present-and-disabled.

---

## What this demonstrates, and what it does not

These belong in the limitations section, stated rather than discovered by a
reviewer.

**Detection is interval-bound.** A print that starts and finishes between two
polls is never observed. Detection probability is a function of poll interval
against print duration — which makes
`FEATURE_INTERVALS_S["fabrication_activity"]` the independent variable for
that part of the evaluation. The same applies to repository snapshots: a file
modified and restored between two passes leaves no trace. This is a measured
property of the design, not a defect to work around.

**The observational variant cannot authorize, only observe.** There is no
authorization source in this build, so every observed job reads as
unreconciled. That is the correct result: the variant can see that something
was fabricated and cannot say whether it was allowed. Fabrication Job
Authorization is a mediated-variant feature; `_lookup_authorization()` in
`fabrication_activity.py` is the single seam where it plugs in.

**Repository changes have no actor.** A mounted CIFS share exposes no SMB
audit trail, so a detected change cannot be attributed to a person. That
missing actor *is* the attribution gap the architecture argues enterprise
controls leave open — this feature demonstrates the gap rather than closing
it.

**Artifact verification re-reads lazily.** A file whose size and timestamp are
unchanged keeps its previous verdict rather than being re-downloaded every
cycle. A file swapped for another of identical size with a preserved timestamp
is therefore not re-checked until something else moves.

**The network sweep is partial.** TCP connect against a short port list, so it
runs unprivileged on the Pi and misses any device with those ports closed. It
is not an exhaustive inventory and should not be described as one.

**The chain proves integrity, not truth.** A clean verification means no
record was altered, removed or reordered since it was written. It says nothing
about whether what was written was accurate when written.

**Portal security is prototype-grade.** Signed session cookies, scrypt
password hashes, a per-session CSRF token. No TLS, no password policy, no
lockout, no MFA, no rate limiting. Lab segment only.

---

## Mediated-variant limitations, specifically

The shared-feature limitations above still apply. These are the ones the
mediated features add, and they belong in the write-up stated rather than
discovered.

**"Format normalization" is three checks, not normalization.** Ingest runs a
3MF `post_process` scan (CVE-2023-47268), a container-sanity check, and an
extension allow-list. A production implementation would re-serialise each
format through a trusted parser. Describe what it does, not what the feature
name suggests.

**The declared origin is unverifiable by design.** The operator says where an
artifact came from; the service records who said it. That is attribution, not
authentication, and its value is that a named person is attached to the claim
if it later proves wrong.

**"Sole path" is an ACL property, not a code property.** Nothing in the
service stops a workstation writing to the share directly. That has to be
enforced where the share is served.

**Firmware verification is integrity, not authenticity.** The staged image is
hash-checked against the image an operator recorded, not against a vendor
signature — Prusa's `.bbf` signing is not a published interface this
prototype can check.

**The service does not flash printers, and should not.** Applying firmware is
a physical act at the panel. "Applied" is an operator's claim plus the
version the machine reports afterwards; a disagreement is a finding.

**A break-glass exception accounts for jobs, it does not authorize them.**
Jobs during a window stay unauthorized and get tagged to the exception. The
retrospective path exists because "the service is down" and "the service
records an exception" cannot both be fully true at once — and a window opened
after the fact is marked as such, because it is weaker evidence.

**Reconciliation by filename is much weaker than by content hash.** A name
match is exactly what substituting content under an approved name produces,
so it reconciles the job *and* raises its own finding. The match basis is
recorded on every reconciliation; report the two separately.

**Device identity is context, not proof.** Addresses are forgeable. The claim
the architecture makes is "a claimed operator identity on top of a device
identity", and neither half is attribution on its own.

---

## The comparison the two variants produce

Both variants observe the same fabrication events. The difference is not that
the mediated variant detects more — it is that the mediated variant can say
which events were *allowed*:

| | Observational | Mediated |
|---|---|---|
| Fabrication observed | yes | yes |
| Artifact hashed against a manifest | yes | yes |
| Repository changes recorded | yes | yes |
| Who published a version | no | yes |
| Who retrieved an artifact | no | yes |
| Whether a job was authorized | **cannot say** | yes |
| Which changes arrived outside the sanctioned path | no | yes |

In the observational variant every observed job reads as unreconciled, and
that is the correct result rather than a gap in the implementation.

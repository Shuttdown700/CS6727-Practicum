"""
config.py -- every tunable in the prototype, hardcoded.

No command-line arguments, no environment variables. Edit this file.

The one exception is FABGUARD_DATA_DIR, which the self-test sets so a test run
cannot scribble on a live database. Normal operation ignores it.
"""

import os
from pathlib import Path

# =============================================================================
# VARIANT
# =============================================================================
# "observational"  -- watch only. Shared features run; nothing is mediated and
#                     the repository is mounted read-only.
# "mediated"       -- the service is the path. Ingest, repository access,
#                     version authority, job authorization and firmware
#                     staging are live, and the repository must be writable.
#
# This single switch is what the evaluation varies. Everything downstream --
# which features load, which portal routes exist, whether a job can be
# reconciled -- follows from it.

VARIANT = "mediated"

MEDIATED = VARIANT == "mediated"


# =============================================================================
# PATHS
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("FABGUARD_DATA_DIR", BASE_DIR / "data"))

DB_PATH = DATA_DIR / "fabguard.sqlite3"
EVENT_LOG_PATH = DATA_DIR / "events.jsonl"      # append-only, hash-chained
ARTIFACT_CACHE = DATA_DIR / "artifact_cache"    # files pulled off the printer
QUARANTINE_DIR = DATA_DIR / "quarantine"        # ingest holding area
OBJECT_STORE = DATA_DIR / "objects"             # content-addressed artifacts
FIRMWARE_STORE = DATA_DIR / "firmware"          # recorded firmware images


# =============================================================================
# REPOSITORY (the Samba share on the second Pi)
# =============================================================================
#   sudo apt install cifs-utils
#   sudo mkdir -p /mnt/makerspace
#   sudo mount -t cifs //192.168.50.20/designs /mnt/makerspace \
#        -o credentials=/etc/fabguard-smb.cred,uid=fabguard,gid=fabguard,vers=3.1.1
#
# OBSERVATIONAL: mount read-only (add `ro`). A service that attests to the
# integrity of a share it can also write to is asserting something it cannot
# support.
# MEDIATED: mount read-write. The service is the sole sanctioned write path,
# so it needs to write; workstation access to the share should be removed at
# the share's own ACL, which is what makes the service "sole path" in fact
# rather than only in policy.

REPOSITORY_PATH = Path("/mnt/makerspace")

REPOSITORY_HASH_EXTENSIONS = {
    ".3mf", ".stl", ".step", ".stp", ".gcode", ".bgcode", ".obj",
    ".amf", ".f3d", ".scad", ".ini", ".json", ".txt", ".md", ".pdf",
}
REPOSITORY_MAX_HASH_BYTES = 512 * 1024 * 1024
REPOSITORY_IGNORE_NAMES = {
    ".DS_Store", "Thumbs.db", "desktop.ini", ".fseventsd",
    ".Trashes", ".TemporaryItems", "~$",
}
REPOSITORY_FORCE_REHASH = False

# Where the mediated variant publishes. Everything the service writes lands
# under this subdirectory of the share, so a snapshot can tell sanctioned
# writes from everything else by location as well as by record.
REPOSITORY_PUBLISH_SUBDIR = "published"


# =============================================================================
# FABRICATION EQUIPMENT
# =============================================================================
# PrusaLink over the LAN authenticates with HTTP Digest: the PrusaLink
# username and password from the printer's Settings -> Network -> PrusaLink.
# That is all you need. `api_key` is optional and only exists for the legacy
# /api/* endpoints on older firmware; leave it out unless something 401s.

PRINTERS = [
    {
        "id": "mk4-01",
        "label": "Prusa MK4 (bay 1)",
        "driver": "prusalink",
        "host": "192.168.50.31",
        "port": 80,
        "username": "maker",
        "password": "CHANGE-ME",
        "storages": ["usb"],      # also "local" on printers with internal flash
        "timeout_s": 8.0,
        "upload_timeout_s": 180.0,
    },
    {
        "id": "sim-01",
        "label": "Simulated printer (bench)",
        "driver": "simulator",
        "scenario": "unauthorized_usb_print",
    },
]


# =============================================================================
# FEATURES (scheduled collectors)
# =============================================================================
# Comment a line out to disable. Dropping a module into features/ and adding
# its name here is the whole process for adding one.
#
# Intervals are short for a demo. Detection probability for an unobserved
# print is a function of poll interval against print duration, so
# FABRICATION_ACTIVITY_INTERVAL is the independent variable for that part of
# the evaluation.

_SHARED_FEATURES = [
    "fabrication_activity",
    "artifact_verification",
    "repository_change",
    "equipment_inventory",
]
_MEDIATED_FEATURES = [
    "job_reconciliation",
]

ENABLED_FEATURES = _SHARED_FEATURES + (_MEDIATED_FEATURES if MEDIATED else [])

FEATURE_INTERVALS_S = {
    "fabrication_activity": 30,
    "artifact_verification": 300,
    "repository_change": 120,
    "equipment_inventory": 900,
    "job_reconciliation": 60,
}

RUN_FEATURES_ON_STARTUP = True


# =============================================================================
# SERVICES (request-driven mediation, invoked from the portal)
# =============================================================================
# Not collectors: these run when an operator does something. Listed here so
# the portal knows which workflows to expose, and so a single switch turns
# the whole mediated path off for an observational run.

_MEDIATED_SERVICES = [
    "ingest",
    "repository_access",
    "version_authority",
    "job_authorization",
    "firmware_staging",
    "degraded_mode",
]

ENABLED_SERVICES = _MEDIATED_SERVICES if MEDIATED else []


# =============================================================================
# INGEST MEDIATION
# =============================================================================
INGEST_MAX_BYTES = 512 * 1024 * 1024
INGEST_ALLOWED_EXTENSIONS = {
    ".3mf", ".stl", ".step", ".stp", ".obj", ".amf",
    ".gcode", ".bgcode", ".ini", ".json", ".txt", ".md", ".pdf", ".zip",
}

# CVE-2023-47268: PrusaSlicer <= 2.6.1 executes the `post_process` directive
# found in Metadata/Slic3r_PE.config inside a 3MF, during slicing. A 3MF
# downloaded from a public model repository is therefore a code-execution
# vector against the workstation that opens it. Ingest refuses any 3MF
# carrying that directive.
#
# This is the one normalisation check that earns its place in a prototype:
# it is a real, published vector against exactly the workflow being modelled.
INGEST_SCAN_3MF_POST_PROCESS = True
INGEST_REJECT_ON_SCAN_HIT = True

# Declared-origin values offered in the portal. Free text is allowed too; the
# point is that SOMEONE claimed where it came from, and that claim is theirs.
INGEST_ORIGIN_CHOICES = [
    "Authored in-house",
    "Vendor-supplied",
    "Public model repository",
    "Received by email",
    "Removable media",
    "Other unit / transferred",
]


# =============================================================================
# FABRICATION JOB AUTHORIZATION
# =============================================================================
# Storage and directory the service uploads jobs into on the printer.
JOB_TARGET_STORAGE = "usb"
JOB_TARGET_DIR = "/fabguard"
# Start the print on upload. False stages the file and leaves an operator to
# press Print at the machine, which is the safer demo default: it keeps a
# human at the printer when it starts moving.
JOB_PRINT_AFTER_UPLOAD = False
JOB_ALLOWED_EXTENSIONS = {".gcode", ".bgcode"}


# =============================================================================
# FIRMWARE STAGING
# =============================================================================
FIRMWARE_TARGET_STORAGE = "usb"
FIRMWARE_EXTENSIONS = {".bbf"}
FIRMWARE_MAX_BYTES = 64 * 1024 * 1024
# Applying firmware is a physical act at the printer's panel. The service
# stages and verifies the image and records that an operator said they
# applied it; it does not and should not trigger the flash itself.
FIRMWARE_SERVICE_CAN_APPLY = False


# =============================================================================
# DEGRADED-MODE OPERATION
# =============================================================================
# A break-glass exception is time-limited by design: an exception that never
# expires is just a disabled control.
DEGRADED_DEFAULT_MINUTES = 120
DEGRADED_MAX_MINUTES = 480
# Warn once an exception has been open this long past expiry.
DEGRADED_OVERDUE_GRACE_MINUTES = 15
DEGRADED_REASON_CHOICES = [
    "Mediating service unavailable",
    "Network partition to equipment",
    "Shared storage unreachable",
    "Deadline within support window",
    "Other (describe)",
]


# =============================================================================
# WEB PORTAL
# =============================================================================
WEB_HOST = "0.0.0.0"
WEB_PORT = 8080

# Replace before running anywhere but a bench.
#   python3 -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY = "dev-only-change-me-0000000000000000000000000000000000000000000000"

SESSION_IDLE_TIMEOUT_S = 30 * 60
MAX_UPLOAD_BYTES = 512 * 1024 * 1024

BOOTSTRAP_USER = "operator"
BOOTSTRAP_PASSWORD = "changeme"
BOOTSTRAP_DISPLAY_NAME = "Bench Operator"

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1

# Operator Attribution: record the device an action came from alongside the
# operator who claimed it. Claimed operator identity on top of device
# identity is the whole point -- neither alone is attribution.
ATTRIBUTION_RECORD_DEVICE = True
ATTRIBUTION_TRUST_FORWARDED_FOR = False     # no reverse proxy in front: do not trust it


# =============================================================================
# EVENT LOG
# =============================================================================
# Records are hash-chained: each carries the hash of its predecessor, so
# removing or editing one breaks every link after it.
#
# To make the kernel enforce append-only as well:
#   sudo chattr +a data/events.jsonl

EVENT_LOG_ANCHOR = "fabguard-v0"
ACTIVITY_HEARTBEAT_EVERY_N_POLLS = 20


# =============================================================================
# ARTIFACT VERIFICATION
# =============================================================================
ARTIFACT_MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
ARTIFACT_VERIFY_EXTENSIONS = {".gcode", ".bgcode", ".3mf", ".stl"}
ARTIFACT_RETAIN_COPIES = True


# =============================================================================
# EQUIPMENT CONFIGURATION INVENTORY
# =============================================================================
INVENTORY_SUBNETS = ["192.168.50.0/24"]
INVENTORY_PROBE_PORTS = [80, 443, 8080, 631, 9100, 22, 445]
INVENTORY_PROBE_TIMEOUT_S = 0.35
INVENTORY_MAX_WORKERS = 64
INVENTORY_ENABLE_SWEEP = True

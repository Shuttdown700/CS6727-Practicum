#!/usr/bin/env bash
# mount_capture_store.sh — mount the home NAS share used for capture storage
#
#   //10.0.0.213/Appo  ->  /mnt/appo
#
# The Pi's own traffic uses the OUTPUT hook, not FORWARD, so this reaches the
# home LAN regardless of which lab_segment.sh variant is active. Lab clients
# still cannot: the block lists only govern forwarded traffic.
#
# Usage:
#   sudo ./mount_capture_store.sh --list                 # enumerate shares first
#   sudo SMB_USER=bshutt3 ./mount_capture_store.sh
#   sudo ./mount_capture_store.sh --remove
#
# Safe to rerun.

set -euo pipefail

SERVER="${SERVER:-10.0.0.213}"
SHARE="${SHARE:-Appo}"
MOUNTPOINT="${MOUNTPOINT:-/mnt/appo}"
SMB_USER="${SMB_USER:-${SUDO_USER:-}}"
SMB_PASS="${SMB_PASS:-}"
SMB_DOMAIN="${SMB_DOMAIN:-}"                 # set if the NAS is domain-joined
LOCAL_USER="${LOCAL_USER:-${SUDO_USER:-}}"
CRED_FILE="${CRED_FILE:-/etc/samba/creds/$(tr '[:upper:]' '[:lower:]' <<<"${SHARE}")}"

log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
export DEBIAN_FRONTEND=noninteractive

unit_name() { systemd-escape -p --suffix=automount "$MOUNTPOINT"; }

# ---- removal ------------------------------------------------------------------
if [[ ${1:-} == --remove ]]; then
  log "Removing ${MOUNTPOINT}"
  umount -l "$MOUNTPOINT" 2>/dev/null || true
  systemctl stop "$(unit_name)" 2>/dev/null || true
  sed -i "\#[[:space:]]${MOUNTPOINT}[[:space:]]#d" /etc/fstab
  systemctl daemon-reload
  rm -f "$CRED_FILE"
  rmdir "$MOUNTPOINT" 2>/dev/null || true
  log "Done — fstab entry and credentials removed."
  exit 0
fi

[[ -n $SMB_USER ]] || die "Set SMB_USER=<NAS login>."
if [[ -z $SMB_PASS ]]; then
  read -rsp "Password for ${SMB_USER}@${SERVER}: " SMB_PASS; echo
fi

apt-get -y install cifs-utils smbclient >/dev/null

# ---- share enumeration --------------------------------------------------------
# Windows shows the share's display name, which is usually but not always the
# name the server exports. Confirm before mounting.
if [[ ${1:-} == --list ]]; then
  log "Shares on ${SERVER}:"
  smbclient -L "//${SERVER}" -U "${SMB_USER}%${SMB_PASS}" ${SMB_DOMAIN:+-W "$SMB_DOMAIN"} -m SMB3 2>/dev/null \
    | sed -n '/Sharename/,/^$/p' || die "Could not list shares. Check credentials and that ${SERVER} is up."
  exit 0
fi

# ---- reachability -------------------------------------------------------------
timeout 5 bash -c ">/dev/tcp/${SERVER}/445" 2>/dev/null \
  || die "TCP 445 on ${SERVER} is not reachable from this Pi."

if ! smbclient -L "//${SERVER}" -U "${SMB_USER}%${SMB_PASS}" ${SMB_DOMAIN:+-W "$SMB_DOMAIN"} -m SMB3 2>/dev/null \
     | awk '$2=="Disk"{print $1}' | grep -qix "$SHARE"; then
  warn "Share '${SHARE}' was not found in the server's list. Continuing, but if the"
  warn "mount fails, run: sudo $0 --list   to see the exported names."
fi

# ---- credentials (root-only) --------------------------------------------------
install -d -m 700 -o root -g root "$(dirname "$CRED_FILE")"
umask 077
{
  echo "username=${SMB_USER}"
  echo "password=${SMB_PASS}"
  [[ -n $SMB_DOMAIN ]] && echo "domain=${SMB_DOMAIN}"
} > "$CRED_FILE"
umask 022
chown root:root "$CRED_FILE"; chmod 600 "$CRED_FILE"
log "Credentials at ${CRED_FILE} (root, 0600)"

mkdir -p "$MOUNTPOINT"

# ---- mount options ------------------------------------------------------------
# Capture files are written by root and read back for analysis, so map to the
# local user rather than leaving everything root-owned.
UID_N="$(id -u "${LOCAL_USER:-root}")"; GID_N="$(id -g "${LOCAL_USER:-root}")"
BASE="credentials=${CRED_FILE},uid=${UID_N},gid=${GID_N},file_mode=0664,dir_mode=0775,nofail,_netdev,cache=loose,rsize=1048576,wsize=1048576"

log "Testing mount"
umount "$MOUNTPOINT" 2>/dev/null || true
OPTS=""
for try in "vers=3.1.1,seal" "vers=3.1.1" "vers=3.0,seal" "vers=3.0" "vers=2.1"; do
  if mount -t cifs "//${SERVER}/${SHARE}" "$MOUNTPOINT" -o "${BASE},${try}" 2>/dev/null; then
    OPTS="${BASE},${try}"
    log "Mounted with ${try}"
    break
  fi
done
[[ -n $OPTS ]] || die "All mount attempts failed. Check: sudo dmesg | tail -20"
[[ $OPTS == *seal* ]] || warn "Server refused SMB encryption — capture data crosses the home LAN in the clear."

# quick write test, since a read-only share would fail silently later
if ! touch "${MOUNTPOINT}/.labcap-write-test" 2>/dev/null; then
  umount "$MOUNTPOINT"
  die "Share mounted but is not writable by ${SMB_USER}. Fix permissions on the NAS."
fi
rm -f "${MOUNTPOINT}/.labcap-write-test"
umount "$MOUNTPOINT"

# ---- persist as an on-demand automount ----------------------------------------
# noauto + x-systemd.automount: the Pi 5 is the lab router, so boot must never
# block waiting on the home NAS or the home Wi-Fi uplink.
ENTRY="//${SERVER}/${SHARE}  ${MOUNTPOINT}  cifs  ${OPTS},x-systemd.automount,x-systemd.idle-timeout=600,x-systemd.mount-timeout=20,noauto  0  0"
cp -n /etc/fstab /etc/fstab.bak.orig || true
sed -i "\#[[:space:]]${MOUNTPOINT}[[:space:]]#d" /etc/fstab
echo "$ENTRY" >> /etc/fstab
systemctl daemon-reload
systemctl restart "$(unit_name)"

sleep 1
ls "$MOUNTPOINT" >/dev/null || die "Automount did not trigger. Check: journalctl -xe | tail -20"
findmnt -T "$MOUNTPOINT"
df -h "$MOUNTPOINT" | tail -1

cat <<EOF

[+] //${SERVER}/${SHARE} is available at ${MOUNTPOINT}.
    Mounts on first access; unmounts after 10 min idle. Boot never waits on it.

    Status:  findmnt -T ${MOUNTPOINT}
    Free:    df -h ${MOUNTPOINT}
    Remove:  sudo $0 --remove

    Next: sudo ./labcap.sh start
EOF
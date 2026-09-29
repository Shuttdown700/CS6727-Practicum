#!/usr/bin/env bash
# mount_labnas.sh — mount the Pi 2 Samba share on the Pi 5 (router)
#
#   //172.16.0.2/labnas  ->  /mnt/labnas
#
# Uses a systemd automount unit generated from fstab: the mount is attempted on
# first access, not at boot. That matters here — the Pi 5 is the lab router, and
# a blocking CIFS mount at boot would stall the network if the Pi 2 is off.
#
# Usage:
#   sudo ./mount_labnas.sh                                  # prompts for password
#   sudo SMB_USER=bshutt3 SMB_PASS='...' ./mount_labnas.sh
#   sudo ./mount_labnas.sh --remove
#
# Safe to rerun.

set -euo pipefail

SERVER="${SERVER:-172.16.0.2}"
SHARE="${SHARE:-labnas}"
MOUNTPOINT="${MOUNTPOINT:-/mnt/labnas}"
SMB_USER="${SMB_USER:-${SUDO_USER:-}}"
SMB_PASS="${SMB_PASS:-}"
LOCAL_USER="${LOCAL_USER:-${SUDO_USER:-}}"
CRED_FILE="${CRED_FILE:-/etc/samba/creds/${SHARE}}"

log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."

# ---- removal ------------------------------------------------------------------
if [[ ${1:-} == --remove ]]; then
  log "Removing ${MOUNTPOINT}"
  umount -l "$MOUNTPOINT" 2>/dev/null || true
  systemctl stop "$(systemd-escape -p --suffix=automount "$MOUNTPOINT")" 2>/dev/null || true
  sed -i "\#[[:space:]]${MOUNTPOINT}[[:space:]]#d" /etc/fstab
  systemctl daemon-reload
  rm -f "$CRED_FILE"
  rmdir "$MOUNTPOINT" 2>/dev/null || true
  log "Done — credentials and fstab entry removed."
  exit 0
fi

[[ -n $SMB_USER   ]] || die "Set SMB_USER=<samba login>."
[[ -n $LOCAL_USER ]] || die "Set LOCAL_USER=<local login that owns the files>."
id "$LOCAL_USER" &>/dev/null || die "Local user '${LOCAL_USER}' does not exist."

if [[ -z $SMB_PASS ]]; then
  read -rsp "Samba password for ${SMB_USER}@${SERVER}: " SMB_PASS; echo
fi

export DEBIAN_FRONTEND=noninteractive
apt-get -y install cifs-utils >/dev/null

# ---- reachability -------------------------------------------------------------
ping -c1 -W3 "$SERVER" >/dev/null 2>&1 || warn "${SERVER} not answering ping; continuing anyway."
timeout 5 bash -c ">/dev/tcp/${SERVER}/445" 2>/dev/null \
  || die "TCP 445 on ${SERVER} is not reachable. Is smbd running and the wired link up?"

# ---- credentials (root-only) --------------------------------------------------
install -d -m 700 -o root -g root "$(dirname "$CRED_FILE")"
umask 077
cat > "$CRED_FILE" <<EOF
username=${SMB_USER}
password=${SMB_PASS}
EOF
chown root:root "$CRED_FILE"
chmod 600 "$CRED_FILE"
umask 022
log "Credentials at ${CRED_FILE} (root, 0600)"

mkdir -p "$MOUNTPOINT"

# ---- pick mount options: prefer encrypted (server sets 'smb encrypt = desired')
UID_N="$(id -u "$LOCAL_USER")"; GID_N="$(id -g "$LOCAL_USER")"
BASE="credentials=${CRED_FILE},vers=3.0,uid=${UID_N},gid=${GID_N},file_mode=0664,dir_mode=0775,nofail,_netdev"

log "Testing mount"
umount "$MOUNTPOINT" 2>/dev/null || true
if mount -t cifs "//${SERVER}/${SHARE}" "$MOUNTPOINT" -o "${BASE},seal"; then
  OPTS="${BASE},seal"
  log "Mounted with SMB3 encryption (seal)"
elif mount -t cifs "//${SERVER}/${SHARE}" "$MOUNTPOINT" -o "$BASE"; then
  OPTS="$BASE"
  warn "Server refused 'seal' — mounted unencrypted. Traffic is in the clear on the wire."
else
  die "Mount failed. Check: sudo dmesg | tail -20"
fi
umount "$MOUNTPOINT"

# ---- persist as an on-demand automount ----------------------------------------
# x-systemd.automount + noauto: systemd creates an .automount unit, so the share
# is mounted lazily on first access and boot never blocks on the Pi 2.
ENTRY="//${SERVER}/${SHARE}  ${MOUNTPOINT}  cifs  ${OPTS},x-systemd.automount,x-systemd.idle-timeout=300,x-systemd.mount-timeout=15,noauto  0  0"
cp -n /etc/fstab /etc/fstab.bak.orig || true
sed -i "\#[[:space:]]${MOUNTPOINT}[[:space:]]#d" /etc/fstab
echo "$ENTRY" >> /etc/fstab
log "fstab entry written"

systemctl daemon-reload
systemctl restart "$(systemd-escape -p --suffix=automount "$MOUNTPOINT")"

# ---- verify -------------------------------------------------------------------
sleep 1
ls "$MOUNTPOINT" >/dev/null || die "Automount did not trigger. Check: journalctl -xe | tail -20"
findmnt -T "$MOUNTPOINT" || die "Not mounted."

cat <<EOF

[+] //${SERVER}/${SHARE} is available at ${MOUNTPOINT}, owned by ${LOCAL_USER}.
    Mounts on first access; unmounts after 5 min idle. Boot never waits on it.

    Status:  findmnt -T ${MOUNTPOINT}
    Force:   sudo systemctl restart $(systemd-escape -p --suffix=automount "$MOUNTPOINT")
    Remove:  sudo $0 --remove

    Note: the Pi's own traffic is OUTPUT, not FORWARD, so this mount keeps
    working under every lab-segment.sh variant, including 'full'.
EOF
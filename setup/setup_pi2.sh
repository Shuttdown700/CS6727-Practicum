#!/usr/bin/env bash
# setup_pi2_nas.sh — Raspberry Pi 2 lab host: static eth0 + Samba share on the SD card
#   eth0 = 172.16.0.2/16, gateway + DNS = the Pi 5 router (172.16.0.1)
#   Share = /srv/lab-nas, authenticated (no guest), bound to eth0/lo only
#   Admin = SSH (key-based); optional VNC bound to loopback, reached over an SSH tunnel
#
# Usage:
#   sudo ./setup_pi2_nas.sh                          # prompts for the Samba password
#   sudo NAS_USER=bshutt3 SMB_PASS='...' ./setup_pi2_nas.sh
#   sudo ADMIN_PUBKEY="$(cat id_ed25519_admin.pub)" ./setup_pi2_nas.sh
#   sudo ENABLE_VNC=1 ./setup_pi2_nas.sh
#   sudo SKIP_UPGRADE=1 ./setup_pi2_nas.sh
#
# Handles both network stacks: NetworkManager (Bookworm) or dhcpcd (Bullseye/Legacy).
# Safe to rerun.

set -euo pipefail

# ---- config (override via env) ------------------------------------------------
WIRED_IF="${WIRED_IF:-eth0}"
WIRED_ADDR="${WIRED_ADDR:-172.16.0.2/16}"
GATEWAY="${GATEWAY:-172.16.0.1}"
DNS_SERVERS="${DNS_SERVERS:-172.16.0.1}"     # Pi 5 resolver
CON_NAME="${CON_NAME:-lab-wired}"
SHARE_NAME="${SHARE_NAME:-labnas}"
SHARE_PATH="${SHARE_PATH:-/srv/lab-nas}"
SHARE_GROUP="${SHARE_GROUP:-labnas}"
NAS_USER="${NAS_USER:-${SUDO_USER:-}}"
SMB_PASS="${SMB_PASS:-}"

# Service account for the mediating service on the Pi 5.
#
# This is what makes "the service is the sole write path" true rather than
# merely intended. Operator accounts get READ on the share; only this account
# can write. The firewall then does not have to block operator -> storage at
# all, so the service being down stops publication without also stopping
# people from opening a design.
#
# Set SVC_ENFORCE=0 to keep the old everyone-can-write share (baseline and
# observational runs, where unmediated writes are the behaviour being measured).
SVC_ENFORCE="${SVC_ENFORCE:-1}"
SVC_USER="${SVC_USER:-fabguard}"
SVC_GROUP="${SVC_GROUP:-labsvc}"
SMB_SVC_PASS="${SMB_SVC_PASS:-}"
ALLOW_HOSTS="${ALLOW_HOSTS:-127.0.0.1 172.16. 192.168.67.}"   # Samba prefix syntax
ADMIN_PUBKEY="${ADMIN_PUBKEY:-}"            # SSH public key to install for NAS_USER
ENABLE_VNC="${ENABLE_VNC:-0}"               # 1 = install VNC, loopback-only (SSH tunnel)
SKIP_UPGRADE="${SKIP_UPGRADE:-0}"

log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
[[ -e /sys/class/net/${WIRED_IF} ]] || die "Interface ${WIRED_IF} not present."
[[ -n $NAS_USER ]] || die "Set NAS_USER=<login> (no SUDO_USER detected)."
id "$NAS_USER" &>/dev/null || die "Linux user '${NAS_USER}' does not exist."

if [[ -z $SMB_PASS ]]; then
  read -rsp "Samba password for ${NAS_USER}: " SMB_PASS; echo
  read -rsp "Confirm: " p2; echo
  [[ $SMB_PASS == "$p2" ]] || die "Passwords do not match."
fi
(( ${#SMB_PASS} >= 8 )) || die "Use at least 8 characters."

if [[ $SVC_ENFORCE == 1 && -z $SMB_SVC_PASS ]]; then
  echo "Service account '${SVC_USER}' is the only account allowed to WRITE the share."
  echo "The Pi 5 mounts the share with these credentials."
  read -rsp "Samba password for ${SVC_USER}: " SMB_SVC_PASS; echo
  read -rsp "Confirm: " p2; echo
  [[ $SMB_SVC_PASS == "$p2" ]] || die "Passwords do not match."
fi
if [[ $SVC_ENFORCE == 1 ]]; then
  (( ${#SMB_SVC_PASS} >= 8 )) || die "Service password: use at least 8 characters."
  [[ $SMB_SVC_PASS != "$SMB_PASS" ]] || die \
    "The service password must differ from ${NAS_USER}'s. Sharing it would mean an \
operator holding write credentials, which is the thing this separation removes."
fi

# ---- 1. static network --------------------------------------------------------
if systemctl is-active --quiet NetworkManager; then
  log "NetworkManager detected — configuring '${CON_NAME}'"
  while nmcli con show id "$CON_NAME" &>/dev/null; do nmcli con delete id "$CON_NAME"; done
  nmcli con add type ethernet con-name "$CON_NAME" ifname "$WIRED_IF" autoconnect yes \
    ipv4.method manual ipv4.addresses "$WIRED_ADDR" ipv4.gateway "$GATEWAY" \
    ipv4.dns "$DNS_SERVERS" ipv4.ignore-auto-dns yes \
    ipv6.method disabled >/dev/null
  nmcli con up "$CON_NAME"
elif systemctl is-active --quiet dhcpcd; then
  log "dhcpcd detected — writing static block to /etc/dhcpcd.conf"
  cp -n /etc/dhcpcd.conf /etc/dhcpcd.conf.bak.orig || true
  # replace any previous block we wrote, keep the rest of the file intact
  sed -i '/# >>> lab-nas >>>/,/# <<< lab-nas <<</d' /etc/dhcpcd.conf
  cat >> /etc/dhcpcd.conf <<EOF
# >>> lab-nas >>>
interface ${WIRED_IF}
static ip_address=${WIRED_ADDR}
static routers=${GATEWAY}
static domain_name_servers=${DNS_SERVERS}
noipv6
# <<< lab-nas <<<
EOF
  systemctl restart dhcpcd
else
  die "Neither NetworkManager nor dhcpcd is active — configure ${WIRED_IF} manually."
fi

sleep 3
ip -4 -br addr show "$WIRED_IF"
ping -c1 -W3 "$GATEWAY" >/dev/null 2>&1 || warn "Cannot ping ${GATEWAY} — check the link before trusting DNS."

# ---- 2. updates + packages ----------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
log "apt update"
apt-get update
if [[ $SKIP_UPGRADE != 1 ]]; then
  log "apt full-upgrade (slow on a Pi 2 — expect several minutes)"
  apt-get -y full-upgrade
fi
apt-get -y install samba samba-common-bin

# ---- 3. share directory -------------------------------------------------------
log "Preparing ${SHARE_PATH}"
getent group "$SHARE_GROUP" >/dev/null || groupadd "$SHARE_GROUP"
id -nG "$NAS_USER" | tr ' ' '\n' | grep -qx "$SHARE_GROUP" || usermod -aG "$SHARE_GROUP" "$NAS_USER"
mkdir -p "$SHARE_PATH"
chown root:"$SHARE_GROUP" "$SHARE_PATH"
chmod 2770 "$SHARE_PATH"          # setgid: new files inherit the group

if [[ $SVC_ENFORCE == 1 ]]; then
  log "Preparing service account ${SVC_USER} (sole write path)"
  getent group "$SVC_GROUP" >/dev/null || groupadd "$SVC_GROUP"
  if ! id "$SVC_USER" &>/dev/null; then
    # No login, no home: this account exists to hold a Samba credential.
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --gid "$SVC_GROUP" "$SVC_USER"
    log "Created system user ${SVC_USER}"
  fi
  # SVC_GROUP drives the Samba write list; SHARE_GROUP gives POSIX write on
  # the directory, which is 2770 root:${SHARE_GROUP}.
  id -nG "$SVC_USER" | tr ' ' '\n' | grep -qx "$SVC_GROUP"   || usermod -aG "$SVC_GROUP" "$SVC_USER"
  id -nG "$SVC_USER" | tr ' ' '\n' | grep -qx "$SHARE_GROUP" || usermod -aG "$SHARE_GROUP" "$SVC_USER"
  # Operators must NOT be in the write list group.
  if id -nG "$NAS_USER" | tr ' ' '\n' | grep -qx "$SVC_GROUP"; then
    gpasswd -d "$NAS_USER" "$SVC_GROUP" >/dev/null
    warn "Removed ${NAS_USER} from ${SVC_GROUP}: operators must not hold write."
  fi
fi

# ---- 4. samba config ----------------------------------------------------------
[[ -f /etc/samba/smb.conf && ! -f /etc/samba/smb.conf.bak.orig ]] && cp /etc/samba/smb.conf /etc/samba/smb.conf.bak.orig
log "Writing /etc/samba/smb.conf"
cat > /etc/samba/smb.conf <<EOF
[global]
   workgroup = WORKGROUP
   server string = Lab NAS (Pi 2)
   server role = standalone server
   security = user
   map to guest = never
   server min protocol = SMB3_00
   smb encrypt = desired
   disable netbios = yes
   dns proxy = no
   load printers = no
   printing = bsd
   printcap name = /dev/null
   disable spoolss = yes
   bind interfaces only = yes
   interfaces = lo ${WIRED_IF}
   hosts allow = ${ALLOW_HOSTS}
   hosts deny = 0.0.0.0/0
   logging = file
   log file = /var/log/samba/log.%m
   max log size = 1000

[${SHARE_NAME}]
   comment = Lab NAS
   path = ${SHARE_PATH}
   browseable = yes
$(if [[ $SVC_ENFORCE == 1 ]]; then cat <<SVC
   # Write authority lives here, not in the firewall. Operators read; only the
   # service account writes. That is what lets the mediated variant permit
   # operator -> storage at L3 without giving up the sole-write-path claim --
   # and it means the service being down stops publication without also
   # stopping anyone from opening a design.
   read only = yes
   valid users = @${SHARE_GROUP} @${SVC_GROUP}
   write list = @${SVC_GROUP}
SVC
else cat <<SVC
   # SVC_ENFORCE=0: everyone with an account can write. This is the baseline
   # and observational behaviour -- unmediated writes are what those variants
   # are measuring, so do not "fix" it when running them.
   read only = no
   valid users = @${SHARE_GROUP}
SVC
fi)
   force group = ${SHARE_GROUP}
   create mask = 0660
   force create mode = 0660
   directory mask = 2770
   force directory mode = 2770
EOF

testparm -s /etc/samba/smb.conf >/dev/null || die "smb.conf failed validation."

log "Setting Samba password for ${NAS_USER}"
printf '%s\n%s\n' "$SMB_PASS" "$SMB_PASS" | smbpasswd -s -a "$NAS_USER" >/dev/null
smbpasswd -e "$NAS_USER" >/dev/null

if [[ $SVC_ENFORCE == 1 ]]; then
  log "Setting Samba password for ${SVC_USER}"
  printf '%s\n%s\n' "$SMB_SVC_PASS" "$SMB_SVC_PASS" | smbpasswd -s -a "$SVC_USER" >/dev/null
  smbpasswd -e "$SVC_USER" >/dev/null
fi

systemctl disable --now nmbd 2>/dev/null || true   # NetBIOS name service not used
systemctl enable --now smbd
systemctl restart smbd

# ---- 5. admin access: SSH (+ optional loopback VNC) ---------------------------
log "Enabling SSH"
apt-get -y install openssh-server >/dev/null
systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd

if [[ -n $ADMIN_PUBKEY ]]; then
  USER_HOME="$(getent passwd "$NAS_USER" | cut -d: -f6)"
  install -d -m 700 -o "$NAS_USER" -g "$NAS_USER" "${USER_HOME}/.ssh"
  touch "${USER_HOME}/.ssh/authorized_keys"
  grep -qxF "$ADMIN_PUBKEY" "${USER_HOME}/.ssh/authorized_keys" \
    || echo "$ADMIN_PUBKEY" >> "${USER_HOME}/.ssh/authorized_keys"
  chown "$NAS_USER":"$NAS_USER" "${USER_HOME}/.ssh/authorized_keys"
  chmod 600 "${USER_HOME}/.ssh/authorized_keys"
  log "Installed admin key; disabling password auth"
  cat > /etc/ssh/sshd_config.d/99-lab.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
  # Older sshd (Bullseye) may not read sshd_config.d — check and warn.
  grep -q '^Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config \
    || warn "sshd_config has no Include line; password auth is still enabled. Edit /etc/ssh/sshd_config directly."
  sshd -t || die "sshd config failed validation — not restarting."
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
else
  warn "No ADMIN_PUBKEY given — SSH password auth left as-is. Rerun with a key to harden."
fi

if [[ $ENABLE_VNC == 1 ]]; then
  if apt-get -y install realvnc-vnc-server >/dev/null 2>&1; then
    # Bind to loopback only: reachable solely through an SSH tunnel, never on the wire.
    mkdir -p /etc/vnc/config.d
    cat > /etc/vnc/config.d/common.custom <<'EOF'
IpClientAddresses=+127.0.0.1,-
Encryption=AlwaysOn
EOF
    systemctl enable --now vncserver-x11-serviced 2>/dev/null \
      || warn "vncserver-x11-serviced not available — is a desktop installed?"
    log "VNC installed, restricted to 127.0.0.1 (use an SSH tunnel)"
  else
    warn "realvnc-vnc-server unavailable (Lite image or unsupported release) — skipping VNC."
  fi
fi

# ---- 6. verify ----------------------------------------------------------------
sleep 2
echo
systemctl is-active smbd
ss -tlnp 2>/dev/null | grep -E ':445|:139' || warn "smbd is not listening on 445."
smbclient -L "//${WIRED_ADDR%/*}" -U "${NAS_USER}%${SMB_PASS}" -m SMB3 2>/dev/null | head -20 || \
  warn "smbclient enumeration failed — check: journalctl -u smbd -n50"

cat <<EOF

[+] Done. //${WIRED_ADDR%/*}/${SHARE_NAME} is serving ${SHARE_PATH}.
$(if [[ $SVC_ENFORCE == 1 ]]; then cat <<SVC
    WRITE  ${SVC_USER}   (the mediating service on the Pi 5, only)
    READ   ${NAS_USER}   (operators)

    Mount on the Pi 5 with the SERVICE credentials, or publication fails:
      sudo mount -t cifs //${WIRED_ADDR%/*}/${SHARE_NAME} /mnt/labnas \\
        -o username=${SVC_USER},vers=3.0,uid=\$(id -u),gid=\$(id -g)
    Operator workstation, read-only by ACL whatever options are given:
      sudo mount -t cifs //${WIRED_ADDR%/*}/${SHARE_NAME} /mnt/nas -o username=${NAS_USER},vers=3.0

    Verify the separation actually holds before trusting a mediated run:
      smbclient //${WIRED_ADDR%/*}/${SHARE_NAME} -U ${NAS_USER} -c 'put /etc/hostname t.txt'
        -> must FAIL with NT_STATUS_ACCESS_DENIED or MEDIA_WRITE_PROTECTED
      smbclient //${WIRED_ADDR%/*}/${SHARE_NAME} -U ${SVC_USER} -c 'put /etc/hostname t.txt; rm t.txt'
        -> must SUCCEED
    If the first one succeeds, the mediated variant's sole-write-path claim is
    false and Repository Change Detection is the only thing catching writes.
SVC
else cat <<SVC
    SVC_ENFORCE=0: every account with access can write (baseline / observational).
    Linux:    sudo mount -t cifs //${WIRED_ADDR%/*}/${SHARE_NAME} /mnt/nas -o username=${NAS_USER},vers=3.0
    Windows:  net use Z: \\\\${WIRED_ADDR%/*}\\${SHARE_NAME} /user:${NAS_USER}
SVC
fi)
    Logs:     journalctl -u smbd -f

    NOTE: ${NAS_USER} was added to '${SHARE_GROUP}' — log out and back in for local
    shell access to ${SHARE_PATH}. Samba itself already has the group.

    Admin from 10.0.0.89, via the Pi 5 as a jump host (no firewall holes needed):
      ssh -J <pi5-user>@<pi5-home-ip> ${NAS_USER}@${WIRED_ADDR%/*}
    VNC over that tunnel, then point the viewer at localhost:5901:
      ssh -J <pi5-user>@<pi5-home-ip> -L 5901:localhost:5900 ${NAS_USER}@${WIRED_ADDR%/*}
EOF
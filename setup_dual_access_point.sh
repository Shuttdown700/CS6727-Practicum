#!/usr/bin/env bash
# lab-ap-setup.sh — Raspberry Pi 5 lab Wi-Fi AP
#   Onboard Wi-Fi (SDIO)  = uplink to home network (client)
#   USB Wi-Fi dongle      = lab AP, NAT'd out the uplink via NM "shared" mode
#   Firewall              = lab clients may reach the Pi and the internet, but not
#                           private/home networks (NM dispatcher hook -> nftables)
#
# Usage:
#   sudo ./lab-ap-setup.sh                         # prompts for PSK
#   sudo LAB_PSK='Password-Lab1' ./lab-ap-setup.sh
#   sudo SKIP_UPGRADE=1 ./lab-ap-setup.sh          # skip apt full-upgrade (e.g. rerun after reboot)
#
# Prereqs: Pi OS Bookworm+ (NetworkManager), home Wi-Fi already configured
# (e.g. via Raspberry Pi Imager), USB dongle plugged in. Safe to rerun.

set -euo pipefail

# ---- config (override via env) ------------------------------------------------
LAB_SSID="${LAB_SSID:-LAB-NET}"
LAB_PSK="${LAB_PSK:-}"
LAB_ADDR="${LAB_ADDR:-192.168.67.1/24}"   # AP's own address; must be a host addr, not .0
LAB_BAND="${LAB_BAND:-bg}"                # bg = 2.4 GHz, a = 5 GHz
LAB_CHAN="${LAB_CHAN:-6}"
COUNTRY="${COUNTRY:-US}"
CON_NAME="${CON_NAME:-lab-ap}"
SKIP_UPGRADE="${SKIP_UPGRADE:-0}"
# Destinations lab clients may NOT be forwarded to. Default = all private/link-local/
# CGNAT space, so the home LAN stays blocked even if its DHCP subnet changes.
# Narrow to just the home subnet if preferred, e.g. BLOCK_NETS="192.168.1.0/24"
BLOCK_NETS="${BLOCK_NETS:-10.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10}"
FW_HOOK="/etc/NetworkManager/dispatcher.d/90-lab-ap-fw"

log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."

# ---- input validation ---------------------------------------------------------
if [[ -z $LAB_PSK ]]; then
  read -rsp "PSK for ${LAB_SSID} (8-63 chars): " LAB_PSK; echo
fi
(( ${#LAB_PSK} >= 8 && ${#LAB_PSK} <= 63 )) || die "PSK must be 8-63 characters."

host="${LAB_ADDR%/*}"
[[ ${host##*.} != 0 ]] || die "LAB_ADDR ${LAB_ADDR} is a network address; use a host address (e.g. 192.168.67.1/24)."

# ---- packages -----------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
log "apt update"
apt-get update
if [[ $SKIP_UPGRADE != 1 ]]; then
  log "apt full-upgrade"
  apt-get -y full-upgrade
fi
apt-get -y install iw ethtool usbutils rfkill tcpdump network-manager nftables

systemctl is-active --quiet NetworkManager || die "NetworkManager not active (Bookworm+ required)."

# ---- regulatory domain --------------------------------------------------------
log "Setting Wi-Fi country ${COUNTRY}"
raspi-config nonint do_wifi_country "$COUNTRY"
iw reg set "$COUNTRY" || true
rfkill unblock wifi || true

# ---- identify interfaces (USB bus = dongle, else onboard) ---------------------
UPLINK_IF=""; LAB_IF=""
for d in /sys/class/net/*; do
  [[ -e $d/phy80211 ]] || continue
  ifn="${d##*/}"
  if readlink -f "$d/device" | grep -q '/usb'; then
    if [[ -z $LAB_IF ]]; then LAB_IF="$ifn"; else warn "Multiple USB Wi-Fi adapters; using ${LAB_IF}, ignoring ${ifn}."; fi
  else
    UPLINK_IF="$ifn"
  fi
done

[[ -n $LAB_IF ]]    || die "No USB Wi-Fi adapter found. If the kernel was just upgraded, reboot and rerun with SKIP_UPGRADE=1."
[[ -n $UPLINK_IF ]] || die "No onboard Wi-Fi interface found."

LAB_MAC="$(tr '[:lower:]' '[:upper:]' < "/sys/class/net/${LAB_IF}/address")"
LAB_PHY="$(cat "/sys/class/net/${LAB_IF}/phy80211/name")"
LAB_DRV="$(basename "$(readlink -f "/sys/class/net/${LAB_IF}/device/driver")")"
log "Uplink: ${UPLINK_IF} | Lab: ${LAB_IF} (${LAB_PHY}, ${LAB_DRV}, ${LAB_MAC})"

iw phy "$LAB_PHY" info | sed -n '/Supported interface modes/,/Band/p' | grep -qE '\* AP$' \
  || die "${LAB_IF} (${LAB_DRV}) does not advertise AP mode."

# ---- pin all client Wi-Fi profiles to onboard radio ---------------------------
pinned=0
while IFS=: read -r uuid type; do
  [[ $type == 802-11-wireless ]] || continue
  [[ "$(nmcli -g 802-11-wireless.mode con show "$uuid")" == ap ]] && continue
  name="$(nmcli -g connection.id con show "$uuid")"
  log "Pinning client profile '${name}' to ${UPLINK_IF}"
  nmcli con modify "$uuid" connection.interface-name "$UPLINK_IF"
  pinned=$((pinned + 1))
done < <(nmcli -t -f UUID,TYPE con show)
(( pinned > 0 )) || warn "No client Wi-Fi profiles found; lab clients will have no upstream until ${UPLINK_IF} is connected."

nmcli dev disconnect "$LAB_IF" 2>/dev/null || true

# ---- lab -> home LAN firewall (NM dispatcher hook) ----------------------------
# Applied in pre-up (before clients can associate) with the interface name NM
# reports at that moment, so it survives wlan0/wlan1 renumbering. Traffic to the
# Pi itself (either of its IPs) hits the INPUT hook, not FORWARD, so it is
# unaffected — that is the Pi exception. Internet-bound traffic has a public
# daddr and passes to NM's NAT.
log "Installing firewall hook ${FW_HOOK}"
cat > "$FW_HOOK" <<EOF
#!/bin/sh
# Managed by lab-ap-setup.sh — blocks ${CON_NAME} clients from private/home networks.
IFACE="\$1"; ACTION="\$2"
[ "\$CONNECTION_ID" = "${CON_NAME}" ] || exit 0
case "\$ACTION" in
  pre-up|up)
    /usr/sbin/nft -f - <<NFT
table inet labfw
delete table inet labfw
table inet labfw {
  chain lab_forward {
    type filter hook forward priority -10; policy accept;
    iifname "\$IFACE" ip daddr { ${BLOCK_NETS} } counter reject with icmpx admin-prohibited
    iifname "\$IFACE" meta nfproto ipv6 counter drop
  }
}
NFT
    ;;
  pre-down|down)
    /usr/sbin/nft delete table inet labfw 2>/dev/null || true
    ;;
esac
EOF
chown root:root "$FW_HOOK"
chmod 0755 "$FW_HOOK"
mkdir -p /etc/NetworkManager/dispatcher.d/pre-up.d
ln -sf "$FW_HOOK" /etc/NetworkManager/dispatcher.d/pre-up.d/90-lab-ap-fw
systemctl enable --now NetworkManager-dispatcher.service >/dev/null 2>&1 || true

# ---- (re)create AP profile ----------------------------------------------------
while nmcli con show id "$CON_NAME" &>/dev/null; do
  log "Removing existing '${CON_NAME}' profile"
  nmcli con delete id "$CON_NAME"
done

log "Creating AP '${LAB_SSID}' on ${LAB_IF} (${LAB_ADDR}, band ${LAB_BAND}, ch ${LAB_CHAN})"
nmcli con add type wifi con-name "$CON_NAME" ifname '*' ssid "$LAB_SSID" autoconnect yes \
  802-11-wireless.mac-address "$LAB_MAC" \
  802-11-wireless.cloned-mac-address permanent \
  802-11-wireless.mode ap \
  802-11-wireless.band "$LAB_BAND" \
  802-11-wireless.channel "$LAB_CHAN" \
  ipv4.method shared ipv4.addresses "$LAB_ADDR" \
  ipv6.method disabled \
  wifi-sec.key-mgmt wpa-psk wifi-sec.proto rsn \
  wifi-sec.pairwise ccmp wifi-sec.group ccmp \
  wifi-sec.psk "$LAB_PSK" >/dev/null

nmcli con up "$CON_NAME"

# ---- verify -------------------------------------------------------------------
sleep 2
echo
nmcli dev status
echo
iw dev "$LAB_IF" info | grep -E 'ssid|type|channel'
[[ "$(iw dev "$LAB_IF" info | awk '/type/{print $2}')" == AP ]] || die "${LAB_IF} is not in AP mode."

nft list table inet labfw >/dev/null 2>&1 \
  || die "Firewall table inet labfw not loaded — lab clients are NOT isolated. Check: journalctl -u NetworkManager-dispatcher"
echo
nft list table inet labfw

cat <<EOF

[+] Done. ${LAB_SSID} is up on ${LAB_IF} (${LAB_ADDR}), NAT via ${UPLINK_IF}.
    Blocked:  lab -> { ${BLOCK_NETS} } (Pi itself + internet allowed)
    FW hits:  sudo nft list table inet labfw
    Clients:  iw dev ${LAB_IF} station dump
    Leases:   sudo cat /var/lib/NetworkManager/dnsmasq-${LAB_IF}.leases
    Capture:  sudo tcpdump -i ${LAB_IF} -nn -w lab-\$(date +%F_%H%M).pcap
EOF
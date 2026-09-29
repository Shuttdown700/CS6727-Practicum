#!/usr/bin/env bash
# lab-ap-setup.sh — Raspberry Pi 5 lab Wi-Fi APs (multi-dongle)
#   Onboard Wi-Fi (SDIO)  = uplink to home network (client)
#   Each USB dongle       = its own lab AP, NAT'd out the uplink via NM "shared" mode
#   Firewall              = lab clients may reach the Pi and the internet, but not
#                           the home LAN (NM dispatcher hook -> nftables, one table per AP)
#
# Usage:
#   sudo ./lab-ap-setup.sh                            # prompts for each AP's PSK
#   sudo AP_PSK_1='Password-Lab1' AP_PSK_2='Password-Lab2' ./lab-ap-setup.sh
#   sudo LAB_PSK='SameForBoth' ./lab-ap-setup.sh      # one PSK for every AP
#   sudo SKIP_UPGRADE=1 ./lab-ap-setup.sh             # skip apt full-upgrade
#   sudo ISOLATE_LAB_APS=1 ./lab-ap-setup.sh          # also block AP <-> AP traffic
#
# Prereqs: Pi OS Bookworm+ (NetworkManager), home Wi-Fi already configured,
# USB dongle(s) plugged in. Safe to rerun.

set -euo pipefail

# ---- AP definitions -----------------------------------------------------------
# Format: SSID|ADDR/CIDR|band|channel|MAC
#   band: bg = 2.4 GHz, a = 5 GHz
#   MAC:  pins the SSID to one physical dongle. Leave empty to auto-assign in
#         USB enumeration order (fine with one dongle, ambiguous with two).
# 2.4 GHz APs on the same radio space should use non-overlapping channels (1/6/11).
AP_SPECS=(
  "LAB-NET1|192.168.67.1/24|bg|6|98:48:27:E8:3E:ED"
  "LAB-NET2|192.168.68.1/24|bg|11|20:E1:5D:8D:78:A3"
)

# ---- config (override via env) ------------------------------------------------
COUNTRY="${COUNTRY:-US}"
SKIP_UPGRADE="${SKIP_UPGRADE:-0}"
ISOLATE_LAB_APS="${ISOLATE_LAB_APS:-0}"   # 1 = lab APs cannot reach each other
LAB_PSK="${LAB_PSK:-}"                    # fallback PSK for every AP
# Destinations lab clients may NOT be forwarded to. 10.0.0.0/8 covers the home LAN
# (10.0.0.0/24). 172.16/12 and 192.168/16 are intentionally NOT blocked so lab
# clients can reach the wired NAS and each other.
BLOCK_NETS="${BLOCK_NETS:-10.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10}"

log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."

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

# ---- enumerate radios: USB = lab dongles, onboard = uplink --------------------
UPLINK_IF=""
declare -a USB_IFS=()
for d in /sys/class/net/*; do
  [[ -e $d/phy80211 ]] || continue
  ifn="${d##*/}"
  if readlink -f "$d/device" | grep -q '/usb'; then
    USB_IFS+=("$ifn")
  else
    UPLINK_IF="$ifn"
  fi
done
[[ -n $UPLINK_IF ]]      || die "No onboard Wi-Fi interface found."
(( ${#USB_IFS[@]} > 0 )) || die "No USB Wi-Fi adapters found. If the kernel was just upgraded, reboot and rerun with SKIP_UPGRADE=1."

log "Uplink: ${UPLINK_IF} | USB radios: ${USB_IFS[*]}"
for i in "${USB_IFS[@]}"; do
  printf '      %-6s %s  %s\n' "$i" \
    "$(tr '[:lower:]' '[:upper:]' < "/sys/class/net/${i}/address")" \
    "$(basename "$(readlink -f "/sys/class/net/${i}/device/driver")")"
done

# ---- pin all client Wi-Fi profiles to the onboard radio -----------------------
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

# ---- collect every lab subnet (for optional AP <-> AP isolation) --------------
declare -a ALL_LAB_NETS=()
for spec in "${AP_SPECS[@]}"; do
  IFS='|' read -r _ssid addr _band _chan _mac <<<"$spec"
  IFS=. read -r o1 o2 o3 _o4 <<<"${addr%/*}"
  ALL_LAB_NETS+=("${o1}.${o2}.${o3}.0/${addr#*/}")
done

# ---- build each AP ------------------------------------------------------------
idx=0
for spec in "${AP_SPECS[@]}"; do
  idx=$((idx + 1))
  IFS='|' read -r SSID ADDR BAND CHAN MAC <<<"$spec"
  [[ -n $SSID && -n $ADDR && -n $BAND && -n $CHAN ]] || die "Malformed AP spec: ${spec}"

  host="${ADDR%/*}"
  [[ ${host##*.} != 0 ]] || die "${SSID}: ${ADDR} is a network address; use a host address (e.g. 192.168.68.1/24)."

  # connection name: first AP keeps the original 'lab-ap' name
  if (( idx == 1 )); then CON="lab-ap"; else CON="lab-ap${idx}"; fi
  TABLE="labfw_$(printf '%s' "$CON" | tr -c 'a-zA-Z0-9' '_')"
  FW_HOOK="/etc/NetworkManager/dispatcher.d/90-${CON}-fw"

  # ---- resolve the physical radio -------------------------------------------
  IF=""
  if [[ -n $MAC ]]; then
    want="$(tr '[:upper:]' '[:lower:]' <<<"$MAC")"
    for i in "${USB_IFS[@]}"; do
      [[ "$(cat "/sys/class/net/${i}/address")" == "$want" ]] && IF="$i" && break
    done
    [[ -n $IF ]] || die "${SSID}: no USB radio with MAC ${MAC}. Present: ${USB_IFS[*]}"
  else
    IF="${USB_IFS[$((idx - 1))]:-}"
    [[ -n $IF ]] || die "${SSID}: no USB radio available for AP #${idx}."
    MAC="$(tr '[:lower:]' '[:upper:]' < "/sys/class/net/${IF}/address")"
    warn "${SSID}: no MAC pinned — using ${IF} by enumeration order (may change on reboot)."
  fi

  PHY="$(cat "/sys/class/net/${IF}/phy80211/name")"
  DRV="$(basename "$(readlink -f "/sys/class/net/${IF}/device/driver")")"

  # ---- capability checks -----------------------------------------------------
  iw phy "$PHY" info | sed -n '/Supported interface modes/,/Band/p' | grep -qE '^[[:space:]]*\* AP$' \
    || die "${IF} (${DRV}) does not advertise AP mode."
  if [[ $BAND == a ]]; then
    iw phy "$PHY" info | grep -q '^[[:space:]]*Band 2:' \
      || die "${IF} (${DRV}) has no 5 GHz band; use band 'bg' for ${SSID}."
  fi

  # ---- PSK -------------------------------------------------------------------
  psk_var="AP_PSK_${idx}"
  PSK="${!psk_var:-$LAB_PSK}"
  if [[ -z $PSK ]]; then
    read -rsp "PSK for ${SSID} (8-63 chars): " PSK; echo
  fi
  (( ${#PSK} >= 8 && ${#PSK} <= 63 )) || die "${SSID}: PSK must be 8-63 characters."

  log "AP #${idx}: ${SSID} -> ${IF} (${PHY}, ${DRV}, ${MAC}) ${ADDR} band ${BAND} ch ${CHAN}"

  # ---- firewall hook (one nft table per AP, so APs don't clobber each other) --
  # Applied at pre-up with the interface name NM reports then, so it survives
  # wlanN renumbering. Traffic addressed to the Pi itself hits the INPUT hook,
  # not FORWARD, so the Pi stays reachable. Internet traffic has a public daddr.
  EXTRA_BLOCK=""
  if [[ $ISOLATE_LAB_APS == 1 ]]; then
    for n in "${ALL_LAB_NETS[@]}"; do
      [[ $n == "${host%.*}.0/${ADDR#*/}" ]] && continue      # skip own subnet
      EXTRA_BLOCK+="    iifname \"\$IFACE\" ip daddr ${n} counter reject with icmpx admin-prohibited"$'\n'
    done
  fi

  log "Installing firewall hook ${FW_HOOK}"
  cat > "$FW_HOOK" <<EOF
#!/bin/sh
# Managed by lab-ap-setup.sh — isolation for ${CON} (${SSID}).
IFACE="\$1"; ACTION="\$2"
[ "\$CONNECTION_ID" = "${CON}" ] || exit 0
case "\$ACTION" in
  pre-up|up)
    /usr/sbin/nft -f - <<NFT
table inet ${TABLE}
delete table inet ${TABLE}
table inet ${TABLE} {
  chain lab_forward {
    type filter hook forward priority -10; policy accept;
${EXTRA_BLOCK}    iifname "\$IFACE" ip daddr { ${BLOCK_NETS} } counter reject with icmpx admin-prohibited
    iifname "\$IFACE" meta nfproto ipv6 counter drop
  }
}
NFT
    ;;
  pre-down|down)
    /usr/sbin/nft delete table inet ${TABLE} 2>/dev/null || true
    ;;
esac
EOF
  chown root:root "$FW_HOOK"
  chmod 0755 "$FW_HOOK"
  mkdir -p /etc/NetworkManager/dispatcher.d/pre-up.d
  ln -sf "$FW_HOOK" "/etc/NetworkManager/dispatcher.d/pre-up.d/90-${CON}-fw"

  # ---- retire stale AP profiles bound to this radio ---------------------------
  # Another AP profile pinned to the same MAC would fight this one for the radio.
  while IFS=: read -r uuid ctype; do
    [[ $ctype == 802-11-wireless ]] || continue
    [[ "$(nmcli -g 802-11-wireless.mode con show "$uuid")" == ap ]] || continue
    nm="$(nmcli -g connection.id con show "$uuid")"
    [[ $nm == "$CON" ]] && continue
    pm="$(nmcli -g 802-11-wireless.mac-address con show "$uuid" | tr '[:lower:]' '[:upper:]')"
    [[ $pm == "$MAC" ]] || continue
    log "Removing stale AP profile '${nm}' bound to ${MAC}"
    nmcli con delete "$uuid" >/dev/null
  done < <(nmcli -t -f UUID,TYPE con show)

  while nmcli con show id "$CON" &>/dev/null; do
    log "Removing existing '${CON}' profile"
    nmcli con delete id "$CON" >/dev/null
  done

  # ---- create + activate ------------------------------------------------------
  nmcli con add type wifi con-name "$CON" ifname '*' ssid "$SSID" autoconnect yes \
    802-11-wireless.mac-address "$MAC" \
    802-11-wireless.cloned-mac-address permanent \
    802-11-wireless.mode ap \
    802-11-wireless.band "$BAND" \
    802-11-wireless.channel "$CHAN" \
    ipv4.method shared ipv4.addresses "$ADDR" \
    ipv6.method disabled \
    wifi-sec.key-mgmt wpa-psk wifi-sec.proto rsn \
    wifi-sec.pairwise ccmp wifi-sec.group ccmp \
    wifi-sec.psk "$PSK" >/dev/null

  nmcli con up "$CON"
  unset PSK
done

systemctl enable --now NetworkManager-dispatcher.service >/dev/null 2>&1 || true

# ---- verify -------------------------------------------------------------------
sleep 3
echo
nmcli dev status
echo

fail=0
idx=0
for spec in "${AP_SPECS[@]}"; do
  idx=$((idx + 1))
  IFS='|' read -r SSID ADDR _band _chan MAC <<<"$spec"
  if (( idx == 1 )); then CON="lab-ap"; else CON="lab-ap${idx}"; fi
  TABLE="labfw_$(printf '%s' "$CON" | tr -c 'a-zA-Z0-9' '_')"
  IF="$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v c="$CON" '$1==c{print $2}')"

  if [[ -z $IF ]]; then
    warn "${SSID} (${CON}) is not active."; fail=1; continue
  fi
  if [[ "$(iw dev "$IF" info | awk '/type/{print $2}')" != AP ]]; then
    warn "${IF} is not in AP mode."; fail=1; continue
  fi
  if ! nft list table inet "$TABLE" >/dev/null 2>&1; then
    warn "Table inet ${TABLE} not loaded — ${SSID} clients are NOT isolated."; fail=1; continue
  fi
  printf '[+] %-9s %-6s %-18s isolated (inet %s)\n' "$SSID" "$IF" "$ADDR" "$TABLE"
done
(( fail == 0 )) || die "One or more APs failed verification. Check: journalctl -u NetworkManager-dispatcher -n50"

cat <<EOF

[+] All APs up. NAT via ${UPLINK_IF}.
    Blocked:  lab -> { ${BLOCK_NETS} }$( [[ $ISOLATE_LAB_APS == 1 ]] && printf ' + AP <-> AP' )
    Clients:  iw dev <iface> station dump
    Leases:   sudo cat /var/lib/NetworkManager/dnsmasq-<iface>.leases
    FW hits:  sudo nft list ruleset | grep -A8 labfw_
    Capture:  sudo tcpdump -i <iface> -nn -w lab-\$(date +%F_%H%M).pcap
EOF
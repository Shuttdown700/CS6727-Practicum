#!/usr/bin/env bash
# setup_wired_lab.sh — Raspberry Pi 5 wired lab segment
#   eth0   = point-to-point lab link to the Pi 2 (static, no DHCP server)
#   wlan0  = WAN uplink (home Wi-Fi), NAT via nftables masquerade
#   Lab hosts reach the internet and the Pi, but not private/home networks.
#
# Usage:
#   sudo ./setup_wired_lab.sh
#   sudo LINK_LAB_AP=1 ./setup_wired_lab.sh     # also allow wired <-> LAB-NET Wi-Fi clients
#
# Companion to lab-ap-setup.sh; uses its own nft table (inet labwired) and its
# own dispatcher hook, so the two are independent. Safe to rerun.

set -euo pipefail

# ---- config (override via env) ------------------------------------------------
WIRED_IF="${WIRED_IF:-eth0}"
WIRED_ADDR="${WIRED_ADDR:-172.16.0.1/16}"   # this Pi's address on the lab link
WIRED_NET="${WIRED_NET:-172.16.0.0/16}"     # must match WIRED_ADDR's prefix
CON_NAME="${CON_NAME:-lab-wired}"
LAB_AP_NET="${LAB_AP_NET:-192.168.67.0/24}" # LAB-NET Wi-Fi subnet, for LINK_LAB_AP
LINK_LAB_AP="${LINK_LAB_AP:-0}"             # 1 = permit wired <-> Wi-Fi lab traffic
BLOCK_NETS="${BLOCK_NETS:-10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10}"
FW_HOOK="/etc/NetworkManager/dispatcher.d/91-lab-wired-fw"
SYSCTL_FILE="/etc/sysctl.d/99-lab-router.conf"

log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
[[ -e /sys/class/net/${WIRED_IF} ]] || die "Interface ${WIRED_IF} not present."
systemctl is-active --quiet NetworkManager || die "NetworkManager not active (Bookworm+ required)."

export DEBIAN_FRONTEND=noninteractive
apt-get -y install nftables >/dev/null

# ---- sanity: lab subnet must not overlap the uplink subnet --------------------
UPLINK_IF="$(ip -4 route show default | awk '{print $5; exit}')"
[[ -n $UPLINK_IF ]] || warn "No default route — lab hosts will have no upstream until the uplink is up."
if [[ -n $UPLINK_IF ]]; then
  UPLINK_NET="$(ip -4 -o route show dev "$UPLINK_IF" scope link proto kernel | awk '{print $1; exit}')"
  log "Uplink: ${UPLINK_IF} (${UPLINK_NET:-unknown})"
  [[ ${UPLINK_NET%%/*} == ${WIRED_NET%%/*} ]] && die "Lab subnet ${WIRED_NET} overlaps uplink subnet ${UPLINK_NET}."
fi

# ---- IPv4 forwarding (persistent) ---------------------------------------------
log "Enabling IPv4 forwarding"
cat > "$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward = 1
EOF
sysctl -q -p "$SYSCTL_FILE"

# ---- NAT + isolation hook ------------------------------------------------------
# Masquerades the lab subnet out whatever interface is NOT the lab link, so it
# follows the default route without hardcoding wlan0. Traffic addressed to the Pi
# itself hits the INPUT hook, not FORWARD, so the Pi stays reachable from the lab.
if [[ $LINK_LAB_AP == 1 ]]; then
  AP_RULE="    iifname \"\$IFACE\" ip daddr ${LAB_AP_NET} counter accept"
  log "Wired <-> ${LAB_AP_NET} (LAB-NET Wi-Fi) will be permitted"
else
  AP_RULE="    # LINK_LAB_AP=0: LAB-NET Wi-Fi clients are covered by the block list below"
fi

log "Installing firewall hook ${FW_HOOK}"
cat > "$FW_HOOK" <<EOF
#!/bin/sh
# Managed by setup_wired_lab.sh — NAT + isolation for the ${CON_NAME} segment.
IFACE="\$1"; ACTION="\$2"
[ "\$CONNECTION_ID" = "${CON_NAME}" ] || exit 0
case "\$ACTION" in
  pre-up|up)
    /usr/sbin/nft -f - <<NFT
table inet labwired
delete table inet labwired
table inet labwired {
  chain lab_postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr ${WIRED_NET} oifname != "\$IFACE" counter masquerade
  }
  chain lab_forward {
    type filter hook forward priority -10; policy accept;
    iifname "\$IFACE" ip daddr ${WIRED_NET} counter accept
${AP_RULE}
    iifname "\$IFACE" ip daddr { ${BLOCK_NETS} } counter reject with icmpx admin-prohibited
    iifname "\$IFACE" meta nfproto ipv6 counter drop
  }
}
NFT
    ;;
  pre-down|down)
    /usr/sbin/nft delete table inet labwired 2>/dev/null || true
    ;;
esac
EOF
chown root:root "$FW_HOOK"
chmod 0755 "$FW_HOOK"
mkdir -p /etc/NetworkManager/dispatcher.d/pre-up.d
ln -sf "$FW_HOOK" /etc/NetworkManager/dispatcher.d/pre-up.d/91-lab-wired-fw
systemctl enable --now NetworkManager-dispatcher.service >/dev/null 2>&1 || true

# ---- (re)create the static wired profile --------------------------------------
# Retire any other profile bound to this NIC so it cannot race ours.
while IFS=: read -r uuid name; do
  [[ -z $uuid ]] && continue
  [[ $name == "$CON_NAME" ]] && continue
  log "Disabling autoconnect on conflicting profile '${name}'"
  nmcli con modify "$uuid" connection.autoconnect no
done < <(nmcli -t -f UUID,NAME,DEVICE,TYPE con show | awk -F: -v i="$WIRED_IF" '$4=="802-3-ethernet" && $3==i {print $1":"$2}')

while nmcli con show id "$CON_NAME" &>/dev/null; do
  log "Removing existing '${CON_NAME}' profile"
  nmcli con delete id "$CON_NAME"
done

log "Creating ${CON_NAME}: ${WIRED_ADDR} on ${WIRED_IF}"
nmcli con add type ethernet con-name "$CON_NAME" ifname "$WIRED_IF" autoconnect yes \
  connection.autoconnect-priority 10 \
  ipv4.method manual ipv4.addresses "$WIRED_ADDR" \
  ipv4.never-default yes ipv4.may-fail no \
  ipv6.method disabled >/dev/null
# never-default: the lab link must never win the default route from the Wi-Fi uplink.

nmcli con up "$CON_NAME"

# ---- verify -------------------------------------------------------------------
sleep 2
echo
ip -4 -br addr show "$WIRED_IF"
ip -4 route show default
echo
nft list table inet labwired >/dev/null 2>&1 \
  || die "Table inet labwired not loaded — NAT is NOT active. Check: journalctl -u NetworkManager-dispatcher"
nft list table inet labwired
[[ "$(sysctl -n net.ipv4.ip_forward)" == 1 ]] || die "net.ipv4.ip_forward is 0."

cat <<EOF

[+] Done. ${WIRED_IF} = ${WIRED_ADDR}, NAT out ${UPLINK_IF:-default route}.
    Blocked:  ${WIRED_IF} -> { ${BLOCK_NETS} } (Pi itself + internet allowed)
    FW hits:  sudo nft list table inet labwired
    Capture:  sudo tcpdump -i ${WIRED_IF} -nn -w wired-\$(date +%F_%H%M).pcap

    On the Pi 2, set gateway and DNS (no DHCP server runs on this link):
      sudo nmcli con modify <profile> ipv4.method manual \\
        ipv4.addresses 172.16.0.2/16 ipv4.gateway ${WIRED_ADDR%/*} \\
        ipv4.dns "1.1.1.1 9.9.9.9" ipv6.method disabled
      sudo nmcli con up <profile>
    Then from the Pi 2: ping ${WIRED_ADDR%/*} && ping 1.1.1.1 && ping -c1 example.com
EOF
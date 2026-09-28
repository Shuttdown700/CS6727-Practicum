#!/usr/bin/env bash
# setup_wired_lab.sh — Raspberry Pi 5 wired lab segment (storage)
#   eth0   = point-to-point lab link to the Pi 2 NAS (static, no DHCP server)
#   wlan0  = WAN uplink (home Wi-Fi), NAT via nftables masquerade
#   Wired hosts reach the internet, the Pi, and both lab Wi-Fi segments,
#   but not the home LAN.
#
# Usage:
#   sudo ./setup_wired_lab.sh
#   sudo LINK_LAB_APS=0 ./setup_wired_lab.sh    # isolate wired from the Wi-Fi lab segments
#
# Companion to lab-ap-setup.sh. Uses its own nft table (inet labwired) and its
# own dispatcher hook, so the two are independent. While lab-segment.sh is
# active it subsumes this table; teardown there restores it. Safe to rerun.

set -euo pipefail

# ---- config (override via env) ------------------------------------------------
WIRED_IF="${WIRED_IF:-eth0}"
WIRED_ADDR="${WIRED_ADDR:-172.16.0.1/16}"   # this Pi's address on the lab link
WIRED_NET="${WIRED_NET:-172.16.0.0/16}"     # must match WIRED_ADDR's prefix
CON_NAME="${CON_NAME:-lab-wired}"

# Lab Wi-Fi segments this wired segment may exchange traffic with. These accepts
# are emitted BEFORE the block list, so they hold even if BLOCK_NETS is widened.
LAB_AP_NETS="${LAB_AP_NETS:-192.168.67.0/24 192.168.68.0/24}"
LINK_LAB_APS="${LINK_LAB_APS:-1}"           # 0 = isolate wired from the Wi-Fi lab

# Home LAN protection. Must not contain the lab segments: 172.16.0.0/12 and
# 192.168.0.0/16 are deliberately absent so the NAS and the lab APs can talk.
# This matches the BLOCK_NETS in lab-ap-setup.sh — keep the two in step.
BLOCK_NETS="${BLOCK_NETS:-10.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10}"

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

uplink_iface() {
  ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

# ---- sanity: real overlap check against the uplink and the lab Wi-Fi nets -----
UPLINK_IF="$(uplink_iface)"
[[ -n $UPLINK_IF ]] || warn "No default route — wired hosts have no upstream until the uplink is up."

overlaps() {  # $1 $2 = CIDRs; exit 0 if they overlap
  python3 - "$1" "$2" <<'PY'
import ipaddress,sys
a=ipaddress.ip_network(sys.argv[1],strict=False)
b=ipaddress.ip_network(sys.argv[2],strict=False)
sys.exit(0 if a.overlaps(b) else 1)
PY
}

if [[ -n $UPLINK_IF ]]; then
  UPLINK_NET="$(ip -4 -o route show dev "$UPLINK_IF" scope link proto kernel | awk '{print $1; exit}')"
  log "Uplink: ${UPLINK_IF} (${UPLINK_NET:-unknown})"
  if [[ -n ${UPLINK_NET:-} ]] && overlaps "$WIRED_NET" "$UPLINK_NET"; then
    die "Wired subnet ${WIRED_NET} overlaps the uplink subnet ${UPLINK_NET}."
  fi
fi
for n in $LAB_AP_NETS; do
  overlaps "$WIRED_NET" "$n" && die "Wired subnet ${WIRED_NET} overlaps lab Wi-Fi subnet ${n}."
done

# ---- IPv4 forwarding (persistent) ---------------------------------------------
log "Enabling IPv4 forwarding"
cat > "$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward = 1
EOF
sysctl -q -p "$SYSCTL_FILE"

# ---- build the per-segment accept rules ---------------------------------------
AP_RULES=""
if [[ $LINK_LAB_APS == 1 ]]; then
  for n in $LAB_AP_NETS; do
    AP_RULES+="    iifname \"\$IFACE\" ip daddr ${n} counter accept comment \"wired -> lab wifi\""$'\n'
  done
  log "Wired <-> lab Wi-Fi permitted: ${LAB_AP_NETS}"
else
  AP_RULES="    # LINK_LAB_APS=0: lab Wi-Fi segments fall through to the block list"$'\n'
  warn "LINK_LAB_APS=0 — the NAS will not be able to answer lab Wi-Fi clients."
fi

# ---- NAT + isolation hook ------------------------------------------------------
# The masquerade is scoped to the uplink interface, resolved at hook run time so
# it survives a rename or a switch to a wired WAN. Scoping matters: masquerading
# out every non-lab-link interface would rewrite the NAS's source address on
# inter-segment traffic and make captures unreadable.
#
# `ct state established,related accept` makes the filter stateful, so replies to
# permitted flows always return even if the block list is later widened. A flow
# denied on its first packet never establishes, so home-LAN protection holds.
#
# Traffic addressed to the Pi itself hits the INPUT hook, not FORWARD, so the Pi
# (and the dnsmasq resolver on it) stays reachable from the wired segment.
log "Installing firewall hook ${FW_HOOK}"
cat > "$FW_HOOK" <<EOF
#!/bin/sh
# Managed by setup_wired_lab.sh — NAT + isolation for the ${CON_NAME} segment.
IFACE="\$1"; ACTION="\$2"
[ "\$CONNECTION_ID" = "${CON_NAME}" ] || exit 0
case "\$ACTION" in
  pre-up|up)
    UP="\$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i=="dev"){print \$(i+1); exit}}')"
    if [ -n "\$UP" ]; then
      MASQ="ip saddr ${WIRED_NET} oifname \\"\$UP\\" counter masquerade"
    else
      MASQ="ip saddr ${WIRED_NET} oifname != \\"\$IFACE\\" counter masquerade"
    fi
    /usr/sbin/nft -f - <<NFT
table inet labwired
delete table inet labwired
table inet labwired {
  chain lab_postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    \$MASQ
  }
  chain lab_forward {
    type filter hook forward priority -10; policy accept;
    ct state established,related counter accept
    iifname "\$IFACE" ip daddr ${WIRED_NET} counter accept comment "intra-segment"
${AP_RULES}    iifname "\$IFACE" ip daddr { ${BLOCK_NETS} } counter reject with icmpx admin-prohibited comment "home LAN protection"
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
# Retire any other ethernet profile that could claim this NIC — whether it is
# currently bound to it (DEVICE) or merely pinned to it while down.
while IFS=: read -r uuid ctype; do
  [[ $ctype == 802-3-ethernet ]] || continue
  name="$(nmcli -g connection.id con show "$uuid")"
  [[ $name == "$CON_NAME" ]] && continue
  dev="$(nmcli -g GENERAL.DEVICES con show "$uuid" 2>/dev/null || true)"
  pin="$(nmcli -g connection.interface-name con show "$uuid" 2>/dev/null || true)"
  [[ $dev == "$WIRED_IF" || $pin == "$WIRED_IF" || -z $pin ]] || continue
  log "Disabling autoconnect on conflicting profile '${name}'"
  nmcli con modify "$uuid" connection.autoconnect no
done < <(nmcli -t -f UUID,TYPE con show)

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
nft list table inet labwired | grep -q masquerade \
  || die "Masquerade rule missing from inet labwired — wired hosts will have no internet."
nft list table inet labwired
[[ "$(sysctl -n net.ipv4.ip_forward)" == 1 ]] || die "net.ipv4.ip_forward is 0."

cat <<EOF

[+] Done. ${WIRED_IF} = ${WIRED_ADDR}, NAT out ${UPLINK_IF:-default route}.
    Reachable: the Pi, the internet$( [[ $LINK_LAB_APS == 1 ]] && printf ', lab Wi-Fi (%s)' "$LAB_AP_NETS" )
    Blocked:   { ${BLOCK_NETS} }
    FW hits:   sudo nft list table inet labwired
    Capture:   sudo tcpdump -i ${WIRED_IF} -nn -w wired-\$(date +%F_%H%M).pcap

    On the Pi 2, set gateway and DNS (no DHCP server runs on this link;
    DNS is the dnsmasq resolver on this Pi):
      sudo nmcli con modify <profile> ipv4.method manual \\
        ipv4.addresses 172.16.0.2/16 ipv4.gateway ${WIRED_ADDR%/*} \\
        ipv4.dns "${WIRED_ADDR%/*}" ipv4.ignore-auto-dns yes ipv6.method disabled
      sudo nmcli con up <profile>
    Then from the Pi 2:
      ping -c1 ${WIRED_ADDR%/*} && ping -c1 1.1.1.1 && ping -c1 example.com
EOF
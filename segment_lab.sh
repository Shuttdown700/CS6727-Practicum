#!/usr/bin/env bash
# lab-segment.sh — segment the lab AP into operator / fabrication / storage
#                  networks and switch control variants for evaluation runs.
#
# Companion to lab-ap-setup.sh. That script builds a flat lab AP; this one
# splits it into routed segments and swaps the forwarding policy between the
# three control variants under test.
#
#   setup      add segment addressing + AP isolation (run once)
#   baseline   permissive policy — current improvised practice
#   minimal    ingress/egress controls only
#   full       complete mediation — operator reaches nothing directly
#   status     show current state
#   teardown   remove segmentation, restore lab-ap-setup.sh firewall
#
# Usage:
#   sudo ./lab-segment.sh setup
#   sudo ./lab-segment.sh full
#   sudo ./lab-segment.sh status
#
# Design notes
#   * Addressing is applied ONCE and left in place across all variants, so
#     printers never need reconfiguring between runs and captures stay
#     comparable. Only forwarding policy and NAT change per variant.
#   * Segments are separate SUBNETS on one radio, not separate L2 domains.
#     Different subnets force inter-segment traffic through the Pi, where it
#     can be filtered and logged. AP isolation blocks the L2 shortcut.
#   * While segmentation is active this script's nftables table subsumes the
#     `inet labfw` table from lab-ap-setup.sh, including its home-network
#     protection. teardown restores it.
#   * The mediating service runs on the Pi. Pi-originated traffic is OUTPUT,
#     not FORWARD, so it is never matched by these rules — the mediator always
#     reaches every segment. Set MEDIATOR_IP if it moves to its own host.

set -euo pipefail

# ---- config (override via env) ------------------------------------------------
CON_NAME="${CON_NAME:-lab-ap}"

OPER_NET="${OPER_NET:-192.168.67.0/24}"     # operator segment (NM shared, DHCP)
FAB_ADDR="${FAB_ADDR:-192.168.68.1/24}"     # Pi's address on fabrication segment
STOR_ADDR="${STOR_ADDR:-172.16.1.1/24}"     # Pi's address on storage segment (eth0)

# Mediating service location. Empty = on the Pi itself (default).
# Set to a host IP if the service moves off the Pi.
MEDIATOR_IP="${MEDIATOR_IP:-}"

# Private space the lab must never reach (home LAN protection). Lab segments
# are excepted automatically.
BLOCK_NETS="${BLOCK_NETS:-10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10}"

LOG_DROPS="${LOG_DROPS:-1}"                 # 1 = log blocked inter-segment attempts
STATE_DIR="/etc/lab-segment"
NFT_FILE="${STATE_DIR}/labseg.nft"
VARIANT_FILE="${STATE_DIR}/variant"
HOOK="/etc/NetworkManager/dispatcher.d/95-lab-segment"

log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
command -v nft   >/dev/null || die "nftables not installed."
command -v nmcli >/dev/null || die "NetworkManager not installed."

FAB_NET="$(python3 - "$FAB_ADDR" <<'PY' 2>/dev/null || true
import ipaddress,sys
print(ipaddress.ip_interface(sys.argv[1]).network)
PY
)"
[[ -n ${FAB_NET:-} ]] || FAB_NET="${FAB_ADDR%.*}.0/${FAB_ADDR##*/}"

STOR_NET="$(python3 - "$STOR_ADDR" <<'PY' 2>/dev/null || true
import ipaddress,sys
print(ipaddress.ip_interface(sys.argv[1]).network)
PY
)"
[[ -n ${STOR_NET:-} ]] || STOR_NET="${STOR_ADDR%.*}.0/${STOR_ADDR##*/}"

# ---- interface discovery ------------------------------------------------------
nmcli con show id "$CON_NAME" &>/dev/null \
  || die "Connection '${CON_NAME}' not found. Run lab-ap-setup.sh first."

ap_iface() {
  local d
  d="$(nmcli -t -f GENERAL.DEVICES con show id "$CON_NAME" 2>/dev/null | cut -d: -f2)"
  [[ -n $d ]] && { echo "$d"; return; }
  # profile is down — fall back to the MAC it is pinned to
  local mac cand
  mac="$(nmcli -g 802-11-wireless.mac-address con show id "$CON_NAME" | tr 'A-Z' 'a-z')"
  for cand in /sys/class/net/*; do
    [[ -e $cand/phy80211 ]] || continue
    [[ "$(cat "$cand/address")" == "$mac" ]] && { echo "${cand##*/}"; return; }
  done
  echo ""
}

uplink_iface() {
  ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

storage_iface() {
  local d
  for d in /sys/class/net/*; do
    d="${d##*/}"
    [[ $d == lo || -e /sys/class/net/$d/phy80211 ]] && continue
    ip -4 addr show dev "$d" 2>/dev/null | grep -q "${STOR_ADDR%/*}" && { echo "$d"; return; }
  done
  # not yet addressed — first non-wireless, non-loopback, non-virtual
  for d in /sys/class/net/*; do
    d="${d##*/}"
    [[ $d == lo || -e /sys/class/net/$d/phy80211 ]] && continue
    [[ $d == veth* || $d == docker* || $d == br-* ]] && continue
    echo "$d"; return
  done
  echo ""
}

AP_IF="$(ap_iface)"
[[ -n $AP_IF ]] || die "Could not determine the AP interface for '${CON_NAME}'."

# ---- setup: addressing + AP isolation ----------------------------------------
do_setup() {
  local up_if stor_if cur
  mkdir -p "$STATE_DIR"

  log "AP interface: ${AP_IF}"

  # Secondary address for the fabrication segment on the AP profile.
  cur="$(nmcli -g ipv4.addresses con show id "$CON_NAME")"
  if [[ $cur == *"${FAB_ADDR}"* ]]; then
    log "Fabrication address ${FAB_ADDR} already present"
  else
    log "Adding fabrication address ${FAB_ADDR} to '${CON_NAME}'"
    nmcli con modify "$CON_NAME" +ipv4.addresses "$FAB_ADDR"
  fi

  # AP isolation: blocks station-to-station frames at the radio so a client
  # cannot bypass routing with a static route + ARP entry. Routed traffic is
  # unaffected because it is addressed to the AP's own MAC.
  if nmcli con modify "$CON_NAME" 802-11-wireless.ap-isolation 1 2>/dev/null; then
    log "AP isolation enabled"
  else
    warn "AP isolation not settable on this NetworkManager version — L2 bypass is possible."
    warn "Note this as a limitation, or add a USB ethernet adapter for a true second segment."
  fi

  nmcli con up "$CON_NAME" >/dev/null 2>&1 || warn "Could not bring '${CON_NAME}' up; addressing applies on next connect."

  # Storage segment on wired interface, if not already configured elsewhere.
  stor_if="$(storage_iface)"
  if [[ -n $stor_if ]]; then
    if ip -4 addr show dev "$stor_if" | grep -q "${STOR_ADDR%/*}"; then
      log "Storage address ${STOR_ADDR} already on ${stor_if}"
    else
      warn "Storage address ${STOR_ADDR} not configured on ${stor_if}."
      warn "Configure it however you manage that link; rules will apply once it exists."
    fi
  fi

  up_if="$(uplink_iface)"
  log "Uplink interface: ${up_if:-<none>}"

  cat <<EOF

[+] Segment addressing in place.

    Operator segment     ${OPER_NET}      DHCP from NetworkManager
    Fabrication segment  ${FAB_NET}      STATIC — configure on each printer
    Storage segment      ${STOR_NET}      wired

    Configure each 3D printer with a static address on the fabrication segment:

      Printer 1   ${FAB_NET%.*}.101
      Printer 2   ${FAB_NET%.*}.102
      Netmask     255.255.255.0
      Gateway     ${FAB_ADDR%/*}
      DNS         ${FAB_ADDR%/*}

    Do this once. Addressing stays fixed across all three variants so the
    printers never need touching again and captures remain comparable.

    Expect mDNS/SSDP printer discovery to stop working from the workstation.
    That is real, control-induced friction — measure it, do not engineer
    around it.

    Next: sudo $0 baseline
EOF
}

# ---- ruleset generation -------------------------------------------------------
# $1 = variant
gen_ruleset() {
  local variant="$1" up_if stor_if logrule oper_fab oper_stor oper_wan fab_wan mediator_rule
  up_if="$(uplink_iface)"
  stor_if="$(storage_iface)"

  if [[ $LOG_DROPS == 1 ]]; then
    logrule='log prefix "labseg-block " level info limit rate 10/second'
  else
    logrule=''
  fi

  # Mediator exception: only needed if the service is NOT on the Pi.
  mediator_rule=""
  if [[ -n $MEDIATOR_IP ]]; then
    mediator_rule="    ip saddr ${MEDIATOR_IP} counter accept comment \"mediating service\""
  fi

  case "$variant" in
    baseline)
      # Flat behaviour: everything permitted. Represents current practice.
      oper_fab="accept"; oper_stor="accept"; oper_wan="accept"; fab_wan="accept" ;;
    minimal)
      # Ingress/egress controls only. Print submission still direct.
      oper_fab="accept"; oper_stor="accept"; oper_wan="block";  fab_wan="block" ;;
    full)
      # Complete mediation. Operator reaches nothing directly.
      oper_fab="block";  oper_stor="block";  oper_wan="block";  fab_wan="block" ;;
    *) die "Unknown variant '${variant}'." ;;
  esac

  {
    cat <<NFT
#!/usr/sbin/nft -f
# Generated by lab-segment.sh — variant: ${variant}
# Do not edit; regenerate with: sudo $0 ${variant}

table inet labfw
delete table inet labfw

table inet labseg
delete table inet labseg

table inet labseg {
  chain forward {
    type filter hook forward priority -20; policy accept;

    ct state established,related counter accept
NFT

    [[ -n $mediator_rule ]] && echo "$mediator_rule"

    # operator -> fabrication
    if [[ $oper_fab == block ]]; then
      cat <<NFT
    ip saddr ${OPER_NET} ip daddr ${FAB_NET} counter ${logrule} reject with icmpx admin-prohibited comment "oper->fab blocked (full)"
NFT
    else
      echo "    ip saddr ${OPER_NET} ip daddr ${FAB_NET} counter accept comment \"oper->fab permitted\""
    fi

    # fabrication -> operator (never initiated)
    cat <<NFT
    ip saddr ${FAB_NET} ip daddr ${OPER_NET} counter ${logrule} drop comment "fab->oper never initiated"
NFT

    # operator -> storage
    if [[ $oper_stor == block ]]; then
      cat <<NFT
    ip saddr ${OPER_NET} ip daddr ${STOR_NET} counter ${logrule} reject with icmpx admin-prohibited comment "oper->storage blocked (full)"
NFT
    else
      echo "    ip saddr ${OPER_NET} ip daddr ${STOR_NET} counter accept comment \"oper->storage permitted\""
    fi

    # fabrication -> storage: never
    cat <<NFT
    ip saddr ${FAB_NET} ip daddr ${STOR_NET} counter ${logrule} drop comment "fab->storage never"
NFT

    # WAN egress
    if [[ -n $up_if ]]; then
      if [[ $fab_wan == block ]]; then
        cat <<NFT
    ip saddr ${FAB_NET} oifname "${up_if}" counter ${logrule} reject with icmpx admin-prohibited comment "fab WAN denied"
NFT
      else
        echo "    ip saddr ${FAB_NET} oifname \"${up_if}\" counter accept comment \"fab WAN permitted (baseline)\""
      fi

      if [[ $oper_wan == block ]]; then
        cat <<NFT
    ip saddr ${OPER_NET} oifname "${up_if}" counter ${logrule} reject with icmpx admin-prohibited comment "oper WAN denied - mediator only"
NFT
      else
        echo "    ip saddr ${OPER_NET} oifname \"${up_if}\" counter accept comment \"oper WAN permitted (baseline)\""
      fi
    fi

    # home-network protection (subsumes inet labfw); lab segments excepted above
    cat <<NFT

    iifname "${AP_IF}" ip daddr { ${BLOCK_NETS} } counter reject with icmpx admin-prohibited comment "home LAN protection"
    meta nfproto ipv6 counter drop
  }
}
NFT

    # NAT for the fabrication segment only where its WAN access is permitted.
    if [[ -n $up_if && $fab_wan == accept ]]; then
      cat <<NFT

table ip labseg_nat
delete table ip labseg_nat

table ip labseg_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat - 10; policy accept;
    ip saddr ${FAB_NET} oifname "${up_if}" counter masquerade
  }
}
NFT
    else
      cat <<NFT

table ip labseg_nat
delete table ip labseg_nat
NFT
    fi
  } > "$NFT_FILE"

  chmod 0644 "$NFT_FILE"
}

# ---- dispatcher hook: reapply after NM reconnects ----------------------------
install_hook() {
  cat > "$HOOK" <<EOF
#!/bin/sh
# Managed by lab-segment.sh — reapplies segmentation rules after reconnect.
# Runs after 90-lab-ap-fw and replaces inet labfw with inet labseg.
[ "\$CONNECTION_ID" = "${CON_NAME}" ] || exit 0
case "\$2" in
  up|pre-up) [ -f "${NFT_FILE}" ] && /usr/sbin/nft -f "${NFT_FILE}" ;;
esac
exit 0
EOF
  chown root:root "$HOOK"; chmod 0755 "$HOOK"
  mkdir -p /etc/NetworkManager/dispatcher.d/pre-up.d
  ln -sf "$HOOK" /etc/NetworkManager/dispatcher.d/pre-up.d/95-lab-segment
}

# ---- variant application ------------------------------------------------------
do_variant() {
  local variant="$1"
  mkdir -p "$STATE_DIR"

  nmcli -g ipv4.addresses con show id "$CON_NAME" | grep -q "${FAB_ADDR}" \
    || die "Segment addressing not applied. Run: sudo $0 setup"

  log "Generating ruleset for variant: ${variant}"
  gen_ruleset "$variant"

  log "Applying"
  nft -f "$NFT_FILE" || die "nft failed. Inspect ${NFT_FILE}"

  echo "$variant" > "$VARIANT_FILE"
  install_hook

  log "Variant '${variant}' active"
  echo
  nft list table inet labseg 2>/dev/null | sed 's/^/    /'
  echo
  cat <<EOF
    Counters:  sudo nft list table inet labseg
    Blocks:    sudo journalctl -kf | grep labseg-block
    Reset:     sudo nft reset counters table inet labseg
EOF
}

# ---- status -------------------------------------------------------------------
do_status() {
  local variant iso
  variant="$(cat "$VARIANT_FILE" 2>/dev/null || echo '<none>')"
  iso="$(nmcli -g 802-11-wireless.ap-isolation con show id "$CON_NAME" 2>/dev/null || echo '?')"

  cat <<EOF

  Variant          ${variant}
  AP interface     ${AP_IF}
  AP isolation     ${iso}   (1 = on, 0 = off, -1 = driver default)
  Uplink           $(uplink_iface)

  Operator         ${OPER_NET}
  Fabrication      ${FAB_NET}
  Storage          ${STOR_NET}

  Addresses on ${AP_IF}:
EOF
  ip -4 -br addr show dev "$AP_IF" 2>/dev/null | sed 's/^/    /'

  echo
  if nft list table inet labseg >/dev/null 2>&1; then
    echo "  inet labseg loaded:"
    nft list table inet labseg | sed 's/^/    /'
  else
    echo "  inet labseg NOT loaded — segmentation inactive"
  fi

  echo
  if nft list table inet labfw >/dev/null 2>&1; then
    echo "  inet labfw present (lab-ap-setup.sh firewall — segmentation is off)"
  fi
  echo
}

# ---- teardown -----------------------------------------------------------------
do_teardown() {
  log "Removing segmentation"

  nft delete table inet labseg   2>/dev/null || true
  nft delete table ip   labseg_nat 2>/dev/null || true

  rm -f "$HOOK" /etc/NetworkManager/dispatcher.d/pre-up.d/95-lab-segment
  rm -f "$NFT_FILE" "$VARIANT_FILE"

  if nmcli -g ipv4.addresses con show id "$CON_NAME" | grep -q "${FAB_ADDR}"; then
    log "Removing ${FAB_ADDR} from '${CON_NAME}'"
    nmcli con modify "$CON_NAME" -ipv4.addresses "$FAB_ADDR"
  fi

  nmcli con modify "$CON_NAME" 802-11-wireless.ap-isolation 0 2>/dev/null || true
  nmcli con up "$CON_NAME" >/dev/null 2>&1 || true

  log "Done — lab-ap-setup.sh firewall (inet labfw) restored on next connect"
  warn "Printers still hold static ${FAB_NET} addresses; set them back to DHCP if you want a truly flat lab."
}

# ---- dispatch -----------------------------------------------------------------
case "${1:-}" in
  setup)                do_setup ;;
  baseline|minimal|full) do_variant "$1" ;;
  status)               do_status ;;
  teardown)             do_teardown ;;
  *)
    cat <<EOF
Usage: sudo $0 {setup|baseline|minimal|full|status|teardown}

  setup      Add fabrication segment addressing and enable AP isolation.
             Run once, then configure printers with static addresses.

  baseline   Permissive — current improvised practice.
               operator -> fabrication   permitted
               operator -> storage       permitted
               operator -> WAN           permitted
               fabrication -> WAN        permitted

  minimal    Ingress/egress controls only.
               operator -> fabrication   permitted (print submission direct)
               operator -> storage       permitted
               operator -> WAN           DENIED
               fabrication -> WAN        DENIED

  full       Complete mediation.
               operator -> fabrication   DENIED
               operator -> storage       DENIED
               operator -> WAN           DENIED
               fabrication -> WAN        DENIED
               (mediating service on the Pi reaches everything)

  status     Show addressing, AP isolation, active variant, rule counters.
  teardown   Remove segmentation; restore lab-ap-setup.sh firewall.

Env: CON_NAME OPER_NET FAB_ADDR STOR_ADDR MEDIATOR_IP BLOCK_NETS LOG_DROPS
EOF
    exit 1 ;;
esac
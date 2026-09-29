#!/usr/bin/env bash
# lab-segment.sh — segment the lab into operator / fabrication / storage networks
#                  and switch control variants for evaluation runs.
#
# Companion to lab-ap-setup.sh (two APs) and setup_wired_lab.sh (wired link).
# Those scripts build the segments; this one imposes the forwarding policy and
# swaps it between the three control variants under test.
#
#   setup      verify segment addressing + enable AP isolation (run once)
#   baseline   permissive policy — current improvised practice
#   minimal    ingress/egress controls only
#   full       complete mediation — operator reaches nothing directly
#   status     show current state
#   teardown   remove segmentation, restore the per-segment firewalls
#
# Usage:
#   sudo ./lab-segment.sh setup
#   sudo ./lab-segment.sh full
#   sudo ./lab-segment.sh status
#
# Network model (post-second-dongle):
#   Operator     192.168.67.0/24   LAB-NET   wlan1   lab-ap      DHCP via NM shared
#   Fabrication  192.168.68.0/24   LAB-NET2  wlan2   lab-ap2     DHCP via NM shared
#   Storage      172.16.0.0/16     wired     eth0    lab-wired   static, Pi 2 NAS
#   Uplink       10.0.0.0/24       home      wlan0   (client)
#
# Design notes
#   * Each segment is now its own L2 domain on its own radio or wire. There is
#     no L2 shortcut between operator and fabrication to defend against, so AP
#     isolation is defence-in-depth (station-to-station within one SSID), not
#     the segment boundary itself.
#   * Addressing is applied by the build scripts and left alone across all
#     variants, so devices never need reconfiguring between runs and captures
#     stay comparable. Only forwarding policy changes per variant.
#   * While segmentation is active, `inet labseg` subsumes the per-segment
#     tables from the build scripts (labfw_lab_ap, labfw_lab_ap2, labwired),
#     including their home-LAN protection and the wired masquerade. Those
#     tables are deleted so they cannot re-reject traffic labseg accepted:
#     an `accept` in one base chain does not stop traversal of the next.
#     teardown restores them.
#   * The mediating service runs on the Pi. Pi-originated traffic is OUTPUT,
#     not FORWARD, so it is never matched by these rules — the mediator always
#     reaches every segment. Set MEDIATOR_IP if it moves to its own host.

set -euo pipefail

# ---- config (override via env) ------------------------------------------------
OPER_CON="${OPER_CON:-lab-ap}"              # LAB-NET     (wlan1)
FAB_CON="${FAB_CON:-lab-ap2}"               # LAB-NET2    (wlan2)
STOR_CON="${STOR_CON:-lab-wired}"           # wired link  (eth0)

OPER_NET="${OPER_NET:-192.168.67.0/24}"     # operator segment
FAB_NET="${FAB_NET:-192.168.68.0/24}"       # fabrication segment
STOR_ADDR="${STOR_ADDR:-172.16.0.1/16}"     # Pi's address on the storage segment

# Mediating service location. Empty = on the Pi itself (default).
MEDIATOR_IP="${MEDIATOR_IP:-}"

# Private space the lab must never reach (home LAN protection). Lab segments are
# excepted by the inter-segment rules, which are evaluated first.
BLOCK_NETS="${BLOCK_NETS:-10.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10}"

LOG_DROPS="${LOG_DROPS:-1}"                 # 1 = log blocked attempts (rate-limited)
STATE_DIR="/etc/lab-segment"
NFT_FILE="${STATE_DIR}/labseg.nft"
VARIANT_FILE="${STATE_DIR}/variant"
HOOK="/etc/NetworkManager/dispatcher.d/95-lab-segment"

# Tables installed by the build scripts that labseg replaces while active.
SUBSUMED_TABLES=("inet labfw_lab_ap" "inet labfw_lab_ap2" "inet labwired" "inet labfw")
BUILD_HOOKS=(
  "/etc/NetworkManager/dispatcher.d/90-lab-ap-fw:${OPER_CON}"
  "/etc/NetworkManager/dispatcher.d/90-lab-ap2-fw:${FAB_CON}"
  "/etc/NetworkManager/dispatcher.d/91-lab-wired-fw:${STOR_CON}"
)

log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
command -v nft   >/dev/null || die "nftables not installed."
command -v nmcli >/dev/null || die "NetworkManager not installed."

STOR_NET="$(python3 - "$STOR_ADDR" <<'PY' 2>/dev/null || true
import ipaddress,sys
print(ipaddress.ip_interface(sys.argv[1]).network)
PY
)"
[[ -n ${STOR_NET:-} ]] || die "Could not derive the storage network from ${STOR_ADDR}."

# ---- interface discovery ------------------------------------------------------
# Resolve a connection to its device; fall back to the MAC it is pinned to when
# the profile is down, so status/teardown work on a half-up system.
con_iface() {
  local con="$1" d mac cand
  d="$(nmcli -t -f GENERAL.DEVICES con show id "$con" 2>/dev/null | cut -d: -f2)"
  [[ -n $d ]] && { echo "$d"; return; }
  mac="$(nmcli -g 802-11-wireless.mac-address con show id "$con" 2>/dev/null | tr 'A-Z' 'a-z')"
  if [[ -n $mac ]]; then
    for cand in /sys/class/net/*; do
      [[ -e $cand/phy80211 ]] || continue
      [[ "$(cat "$cand/address")" == "$mac" ]] && { echo "${cand##*/}"; return; }
    done
  fi
  nmcli -g connection.interface-name con show id "$con" 2>/dev/null || echo ""
}

uplink_iface() {
  ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

require_con() {
  nmcli con show id "$1" &>/dev/null || die "Connection '$1' not found. Run the build scripts first."
}
require_con "$OPER_CON"
require_con "$FAB_CON"
require_con "$STOR_CON"

OPER_IF="$(con_iface "$OPER_CON")"
FAB_IF="$(con_iface "$FAB_CON")"
STOR_IF="$(con_iface "$STOR_CON")"
[[ -n $OPER_IF ]] || die "Could not determine the interface for '${OPER_CON}'."
[[ -n $FAB_IF  ]] || die "Could not determine the interface for '${FAB_CON}'."
[[ -n $STOR_IF ]] || die "Could not determine the interface for '${STOR_CON}'."

LAB_IFACES="\"${OPER_IF}\", \"${FAB_IF}\", \"${STOR_IF}\""

# ---- setup: verify addressing, enable AP isolation ---------------------------
do_setup() {
  local addr iso_ok=1
  mkdir -p "$STATE_DIR"

  log "Operator    ${OPER_CON}  ${OPER_IF}  ${OPER_NET}"
  log "Fabrication ${FAB_CON}  ${FAB_IF}  ${FAB_NET}"
  log "Storage     ${STOR_CON}  ${STOR_IF}  ${STOR_NET}"

  # Each segment owns its addressing via its own profile; verify, do not modify.
  addr="$(nmcli -g ipv4.addresses con show id "$OPER_CON")"
  [[ $addr == *"${OPER_NET%.*}."* ]] || warn "${OPER_CON} address '${addr}' does not look like ${OPER_NET}."
  addr="$(nmcli -g ipv4.addresses con show id "$FAB_CON")"
  [[ $addr == *"${FAB_NET%.*}."* ]] || warn "${FAB_CON} address '${addr}' does not look like ${FAB_NET}."
  addr="$(nmcli -g ipv4.addresses con show id "$STOR_CON")"
  [[ $addr == *"${STOR_ADDR%/*}"* ]] || warn "${STOR_CON} address '${addr}' does not look like ${STOR_ADDR}."

  # Station-to-station isolation within each SSID. No longer the segment
  # boundary (separate radios do that) — this stops printer-to-printer and
  # client-to-client traffic inside one segment.
  for c in "$OPER_CON" "$FAB_CON"; do
    if nmcli con modify "$c" 802-11-wireless.ap-isolation 1 2>/dev/null; then
      log "AP isolation enabled on ${c}"
    else
      iso_ok=0
      warn "AP isolation not settable on ${c} — intra-segment L2 traffic is possible."
    fi
  done
  (( iso_ok == 1 )) || warn "Record this as a measurement limitation; it does not affect segment separation."

  for c in "$OPER_CON" "$FAB_CON"; do
    nmcli con up "$c" >/dev/null 2>&1 || warn "Could not bring '${c}' up; settings apply on next connect."
  done

  cat <<EOF

[+] Segment addressing verified.

    Operator segment     ${OPER_NET}   SSID LAB-NET    DHCP from NetworkManager
    Fabrication segment  ${FAB_NET}   SSID LAB-NET2   DHCP from NetworkManager
    Storage segment      ${STOR_NET}    wired ${STOR_IF}     static (Pi 2 NAS at 172.16.0.2)

    Printers join the fabrication segment by SSID — no static addressing needed.
    Point each printer at LAB-NET2; it will lease an address and take
    ${FAB_NET%.*}.1 as gateway and DNS automatically.

    Expect mDNS/SSDP printer discovery to stop working from the operator
    workstation. The segments are now separate L2 domains, so broadcast
    discovery cannot cross them at all. That is real, control-induced
    friction — measure it, do not engineer around it.

    Next: sudo $0 baseline
EOF
}

# ---- ruleset generation -------------------------------------------------------
# Emits a logging rule (rate-limited, no verdict) followed by a separate
# enforcing rule. Never combine them: a `limit` statement that is over its rate
# stops the rule, so `log ... limit ... reject` silently stops rejecting under
# flood and the packet falls through to `policy accept`.
emit_block() {  # $1=saddr expr  $2=daddr expr  $3=verdict  $4=comment
  local match="$1 $2"
  if [[ $LOG_DROPS == 1 ]]; then
    echo "    ${match} limit rate 10/second log prefix \"labseg-block \" level info"
  fi
  echo "    ${match} counter ${3} comment \"${4}\""
}
emit_accept() { # $1=saddr expr  $2=daddr expr  $3=comment
  echo "    $1 $2 counter accept comment \"$3\""
}

gen_ruleset() {
  local variant="$1" up_if
  local oper_fab oper_stor oper_wan fab_wan stor_wan reverse
  up_if="$(uplink_iface)"

  case "$variant" in
    baseline)
      # Flat behaviour: everything permitted, both directions. A control that
      # blocked reverse-initiated traffic would not represent a flat network.
      oper_fab=accept; oper_stor=accept; oper_wan=accept; fab_wan=accept; stor_wan=accept; reverse=accept ;;
    minimal)
      # Ingress/egress controls only. Print submission still direct.
      oper_fab=accept; oper_stor=accept; oper_wan=block;  fab_wan=block;  stor_wan=block;  reverse=block ;;
    full)
      # Complete mediation. Operator reaches nothing directly.
      oper_fab=block;  oper_stor=block;  oper_wan=block;  fab_wan=block;  stor_wan=block;  reverse=block ;;
    *) die "Unknown variant '${variant}'." ;;
  esac

  local REJ="reject with icmpx admin-prohibited"

  {
    cat <<NFT
#!/usr/sbin/nft -f
# Generated by lab-segment.sh — variant: ${variant}
# Do not edit; regenerate with: sudo $0 ${variant}
#
# The create-then-delete pairs below are the idiomatic way to drop a table that
# may or may not exist: creating it first makes the delete unconditional.

NFT

    # Remove the build scripts' tables so they cannot override labseg.
    local t
    for t in "${SUBSUMED_TABLES[@]}"; do
      printf 'table %s\ndelete table %s\n' "$t" "$t"
    done

    cat <<NFT

table inet labseg
delete table inet labseg

table inet labseg {
  chain forward {
    type filter hook forward priority -20; policy accept;

    ct state established,related counter accept
NFT

    # Mediator exception: only needed if the service is NOT on the Pi.
    [[ -n $MEDIATOR_IP ]] && \
      echo "    ip saddr ${MEDIATOR_IP} counter accept comment \"mediating service\""

    echo

    # --- operator-initiated ---------------------------------------------------
    if [[ $oper_fab == block ]]; then
      emit_block "ip saddr ${OPER_NET}" "ip daddr ${FAB_NET}" "$REJ" "oper->fab blocked (${variant})"
    else
      emit_accept "ip saddr ${OPER_NET}" "ip daddr ${FAB_NET}" "oper->fab permitted"
    fi

    if [[ $oper_stor == block ]]; then
      emit_block "ip saddr ${OPER_NET}" "ip daddr ${STOR_NET}" "$REJ" "oper->storage blocked (${variant})"
    else
      emit_accept "ip saddr ${OPER_NET}" "ip daddr ${STOR_NET}" "oper->storage permitted"
    fi

    echo

    # --- reverse-initiated: devices never originate toward the operator -------
    if [[ $reverse == block ]]; then
      emit_block "ip saddr ${FAB_NET}"  "ip daddr ${OPER_NET}" "drop" "fab->oper never initiated"
      emit_block "ip saddr ${FAB_NET}"  "ip daddr ${STOR_NET}" "drop" "fab->storage never"
      emit_block "ip saddr ${STOR_NET}" "ip daddr ${OPER_NET}" "drop" "storage->oper never initiated"
      emit_block "ip saddr ${STOR_NET}" "ip daddr ${FAB_NET}"  "drop" "storage->fab never"
    else
      emit_accept "ip saddr ${FAB_NET}"  "ip daddr ${OPER_NET}" "fab->oper permitted (baseline)"
      emit_accept "ip saddr ${FAB_NET}"  "ip daddr ${STOR_NET}" "fab->storage permitted (baseline)"
      emit_accept "ip saddr ${STOR_NET}" "ip daddr ${OPER_NET}" "storage->oper permitted (baseline)"
      emit_accept "ip saddr ${STOR_NET}" "ip daddr ${FAB_NET}"  "storage->fab permitted (baseline)"
    fi

    echo

    # --- WAN egress -----------------------------------------------------------
    if [[ -n $up_if ]]; then
      local seg name net pol
      for seg in "OPER:${OPER_NET}:${oper_wan}" "FAB:${FAB_NET}:${fab_wan}" "STOR:${STOR_NET}:${stor_wan}"; do
        IFS=: read -r name net pol <<<"$seg"
        if [[ $pol == block ]]; then
          emit_block "ip saddr ${net}" "oifname \"${up_if}\"" "$REJ" "${name} WAN denied"
        else
          emit_accept "ip saddr ${net}" "oifname \"${up_if}\"" "${name} WAN permitted (baseline)"
        fi
      done
    else
      echo "    # no default route at generation time — WAN rules omitted"
    fi

    # --- home-LAN protection (subsumes the build scripts' block lists) --------
    cat <<NFT

    ip saddr { ${OPER_NET}, ${FAB_NET}, ${STOR_NET} } ip daddr { ${BLOCK_NETS} } counter ${REJ} comment "home LAN protection"
    iifname { ${LAB_IFACES} } meta nfproto ipv6 counter drop
  }
}
NFT

    # --- NAT ------------------------------------------------------------------
    # NM's "shared" mode already masquerades the two AP segments. The wired
    # segment's masquerade came from `inet labwired`, which labseg deletes, so
    # it is reproduced here. Scoped to the uplink only, so inter-segment traffic
    # keeps its real source address and captures stay readable.
    if [[ -n $up_if ]]; then
      cat <<NFT

table ip labseg_nat
delete table ip labseg_nat

table ip labseg_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat - 10; policy accept;
    ip saddr ${STOR_NET} oifname "${up_if}" counter masquerade
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

# ---- dispatcher hook: reapply after any segment reconnects -------------------
install_hook() {
  cat > "$HOOK" <<EOF
#!/bin/sh
# Managed by lab-segment.sh — reapplies segmentation after a segment reconnects.
# Sorts after 90-/91- so it replaces the tables those hooks just installed.
case "\$CONNECTION_ID" in
  ${OPER_CON}|${FAB_CON}|${STOR_CON}) ;;
  *) exit 0 ;;
esac
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

  log "Generating ruleset for variant: ${variant}"
  gen_ruleset "$variant"

  log "Validating"
  nft -c -f "$NFT_FILE" || die "Generated ruleset failed validation. Inspect ${NFT_FILE}"

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
  local variant
  variant="$(cat "$VARIANT_FILE" 2>/dev/null || echo '<none>')"

  cat <<EOF

  Variant          ${variant}
  Uplink           $(uplink_iface)

  Segment       Connection   Iface   Network            AP isolation
  Operator      ${OPER_CON}       ${OPER_IF}    ${OPER_NET}     $(nmcli -g 802-11-wireless.ap-isolation con show id "$OPER_CON" 2>/dev/null || echo '-')
  Fabrication   ${FAB_CON}      ${FAB_IF}    ${FAB_NET}     $(nmcli -g 802-11-wireless.ap-isolation con show id "$FAB_CON" 2>/dev/null || echo '-')
  Storage       ${STOR_CON}    ${STOR_IF}    ${STOR_NET}      n/a
                                             (1 = on, 0 = off, -1 = driver default)

  Addresses:
EOF
  local i
  for i in "$OPER_IF" "$FAB_IF" "$STOR_IF"; do
    ip -4 -br addr show dev "$i" 2>/dev/null | sed 's/^/    /'
  done

  echo
  if nft list table inet labseg >/dev/null 2>&1; then
    echo "  inet labseg loaded:"
    nft list table inet labseg | sed 's/^/    /'
  else
    echo "  inet labseg NOT loaded — segmentation inactive"
  fi

  echo
  local t present=""
  for t in "${SUBSUMED_TABLES[@]}"; do
    nft list table $t >/dev/null 2>&1 && present+="${t}  "
  done
  if [[ -n $present ]]; then
    echo "  Build-script tables present: ${present}"
    [[ $variant != '<none>' ]] && warn "These should have been subsumed — rerun: sudo $0 ${variant}"
  fi
  echo
}

# ---- teardown -----------------------------------------------------------------
do_teardown() {
  log "Removing segmentation"

  nft delete table inet labseg      2>/dev/null || true
  nft delete table ip   labseg_nat  2>/dev/null || true

  rm -f "$HOOK" /etc/NetworkManager/dispatcher.d/pre-up.d/95-lab-segment
  rm -f "$NFT_FILE" "$VARIANT_FILE"

  # Restore the build scripts' tables without forcing a reconnect.
  local entry hook con iface
  for entry in "${BUILD_HOOKS[@]}"; do
    hook="${entry%%:*}"; con="${entry##*:}"
    [[ -x $hook ]] || { warn "Missing ${hook}; '${con}' rules restore on next reconnect."; continue; }
    iface="$(con_iface "$con")"
    [[ -n $iface ]] || continue
    log "Restoring ${con} rules via ${hook##*/}"
    CONNECTION_ID="$con" /bin/sh "$hook" "$iface" up || warn "${hook##*/} returned non-zero."
  done

  for c in "$OPER_CON" "$FAB_CON"; do
    nmcli con modify "$c" 802-11-wireless.ap-isolation 0 2>/dev/null || true
  done

  log "Done — per-segment firewalls restored"
  warn "Addressing is untouched; all three segments remain up and separate."
}

# ---- dispatch -----------------------------------------------------------------
case "${1:-}" in
  setup)                 do_setup ;;
  baseline|minimal|full) do_variant "$1" ;;
  status)                do_status ;;
  teardown)              do_teardown ;;
  *)
    cat <<EOF
Usage: sudo $0 {setup|baseline|minimal|full|status|teardown}

  setup      Verify segment addressing and enable AP isolation. Run once.

  baseline   Permissive — current improvised practice (flat network).
               operator <-> fabrication   permitted
               operator <-> storage       permitted
               fabrication <-> storage    permitted
               all segments -> WAN        permitted

  minimal    Ingress/egress controls only.
               operator -> fabrication    permitted (print submission direct)
               operator -> storage        permitted
               reverse-initiated          DENIED
               all segments -> WAN        DENIED

  full       Complete mediation.
               operator -> fabrication    DENIED
               operator -> storage        DENIED
               reverse-initiated          DENIED
               all segments -> WAN        DENIED
               (mediating service on the Pi reaches everything)

  status     Show addressing, AP isolation, active variant, rule counters.
  teardown   Remove segmentation; restore per-segment firewalls.

Env: OPER_CON FAB_CON STOR_CON OPER_NET FAB_NET STOR_ADDR
     MEDIATOR_IP BLOCK_NETS LOG_DROPS
EOF
    exit 1 ;;
esac
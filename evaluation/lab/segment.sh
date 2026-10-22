#!/usr/bin/env bash
#
# Description: Segment the lab into operator / fabrication / storage networks and
#              switch solution variants for evaluation runs.
#
# Arguments:
#   setup:         verify segment addressing + enable AP isolation (run once)
#   baseline:      no service — current improvised practice
#   observational: service observes; workflow unconstrained
#   mediated:      service is the sole path to storage and equipment
#   status:        show current state
#   teardown:      remove segmentation, restore the per-segment firewalls
#
# Usage Examples:
#   sudo ./segment.sh setup
#   sudo ./segment.sh mediated
#   sudo ./segment.sh status
#
# Network model (cao 2026-10-13):
#   Operator     192.168.67.0/24   LAB-NET   wlan1   lab-ap      DHCP via NM shared
#   Fabrication  192.168.68.0/24   LAB-NET2  wlan2   lab-ap2     DHCP via NM shared
#   Storage      172.16.0.0/16     wired     eth0    lab-wired   static, Pi 2 NAS
#   Uplink       10.0.0.0/24       home      wlan0   (client)
#
# ---------------------------------------------------------------------------
# WHAT EACH VARIANT DOES TO THE NETWORK, AND WHY
#
#   baseline       Flat. The operator reaches equipment and storage directly.
#                  No service is running. This is the improvised practice the
#                  project is measured against.
#
#   observational  THE FORWARD POLICY IS DELIBERATELY IDENTICAL TO BASELINE.
#                  The observational variant watches; it does not constrain the
#                  workflow. If this mode blocked operator->fabrication, the
#                  firewall would be performing the mediation and the variant
#                  comparison would be measuring nftables rather than the
#                  software. The difference between baseline and observational
#                  is entirely in what is RUNNING, not in what is PERMITTED,
#                  and that is a finding worth reporting rather than a gap.
#
#                  The one thing this mode does check is that the share is
#                  mounted read-only: a service attesting to the integrity of
#                  a share it can write to is asserting something it cannot
#                  support.
#
#   mediated       operator -> fabrication is DENIED: job submission is where
#                  the authorization claim lives and the printer has no ACL of
#                  its own, so the network has to carry it.
#
#                  operator -> storage is PERMITTED, deliberately. Write
#                  mediation is enforced where the share is served, not here:
#                  the Samba config grants write to the service account alone
#                  and read to everyone else. Blocking the route as well would
#                  enforce the same claim twice and make the service a single
#                  point of failure for merely READING a design — fabguard
#                  down would mean nobody can open a file. The firewall
#                  governs reachability; the ACL governs write authority.
#                  Those are different claims and they belong in different
#                  places.
#
# BREAK-GLASS
#   `breakglass on` permits operator -> fabrication for a bounded window, so a
#   network fabrication path exists while the service is down. It is a
#   separate, human-run command on purpose. fabguard never touches nftables:
#   a control that opens itself when it believes it is failing means crashing
#   the control IS the attack.
#
#   The window is time-limited and closes itself through a systemd timer. Work
#   done during it is not authorized, only accounted for -- Fabrication
#   Activity Recording, Fabrication Artifact Verification and Repository
#   Change Detection catch it on their next pass once the service returns, and
#   Job Reconciliation ties it to the degraded-mode exception covering that
#   window. Open the exception in the portal as well, prospectively if it is
#   still reachable and retrospectively if it was not.
#
# WAN EGRESS IS NOT A VARIANT PROPERTY
#   Per-segment internet access is held CONSTANT across all three variants,
#   because it is a property of the modelled environment rather than of the
#   solution. Varying it alongside the mediation policy would confound the
#   comparison: any measured difference could then be the WAN rule rather than
#   the mediation.
#
#     operator    -> WAN   PERMITTED by default. Makerspace workstations have
#                          internet, and that is how downloaded models arrive
#                          (attack leaf L-019). Blocking it here would remove a
#                          threat path the model depends on.
#     fabrication -> WAN   DENIED by default. Printers are cloud-denied in the
#                          modelled environment (interview I-02).
#     storage     -> WAN   DENIED by default. The NAS has no reason to
#                          originate toward the internet.
#
#   Override with OPER_WAN / FAB_WAN / STOR_WAN if the lab needs to differ, and
#   say so in the write-up if you do.
# ---------------------------------------------------------------------------

set -euo pipefail

# Configurations (defaults can be overridden via environment variables)

# Segment connections and their interfaces. The build scripts create these profiles and assign them to the correct radios.
OPER_CON="${OPER_CON:-lab-ap}" # LAB-NET (wlan1)
FAB_CON="${FAB_CON:-lab-ap2}" # LAB-NET2 (wlan2)
STOR_CON="${STOR_CON:-lab-wired}" # wired link (eth0)

# Segment networks. The build scripts assign these to the correct profiles; labseg does not modify them.
OPER_NET="${OPER_NET:-192.168.67.0/24}" # operator segment
FAB_NET="${FAB_NET:-192.168.68.0/24}" # fabrication segment
STOR_ADDR="${STOR_ADDR:-172.16.0.1/16}" # Pi's address on the storage segment

# Mediating service location. Empty = on the Pi itself (default).
# When the service runs on the Pi it is the router, so its own traffic is
# output rather than forward and needs no rule here. Set this only if the
# service is moved to a host on one of the segments.
MEDIATOR_IP="${MEDIATOR_IP:-}"

# Per-segment WAN policy. Constant across variants on purpose — see the header.
OPER_WAN="${OPER_WAN:-permit}"
FAB_WAN="${FAB_WAN:-deny}"
STOR_WAN="${STOR_WAN:-deny}"

# Networks that are blocked from the lab segments. The build scripts block these via their own tables, which labseg deletes and replaces with its own rules.
# Note this blocks traffic TO the home LAN, not traffic THROUGH it: an
# internet-bound packet has a public destination and is not matched here, so
# the operator segment still reaches the internet while being unable to touch
# anything on the home network.
BLOCK_NETS="${BLOCK_NETS:-10.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10}"

LOG_DROPS="${LOG_DROPS:-1}" # 1 = log blocked attempts (rate-limited)

# Where the service mounts the Samba share, so the mount options can be checked
# against the variant. Must match config.REPOSITORY_PATH in the solution.
REPO_MOUNT="${REPO_MOUNT:-/mnt/labnas}"

# The solution's config.py, cross-checked so the network variant and the
# software variant cannot silently disagree. Empty to skip the check.
SOLUTION_CONFIG="${SOLUTION_CONFIG:-}"

# Break-glass window length, in minutes. A window with no expiry is a disabled
# control with a nicer name, so `breakglass on` always schedules its own close.
BREAKGLASS_MINUTES="${BREAKGLASS_MINUTES:-120}"

# State files and hook locations
STATE_DIR="/etc/lab-segment"
NFT_FILE="${STATE_DIR}/labseg.nft"
VARIANT_FILE="${STATE_DIR}/variant"
BG_STATE="${STATE_DIR}/breakglass"          # present = open; holds the expiry
BG_UNIT="labseg-breakglass-off"             # transient systemd timer unit
HOOK="/etc/NetworkManager/dispatcher.d/95-lab-segment"

# The build scripts create their own tables to enforce per-segment firewalls. labseg deletes those tables and replaces them with its own rules, so it must know which tables to remove.
SUBSUMED_TABLES=("inet labfw_lab_ap" "inet labfw_lab_ap2" "inet labwired" "inet labfw")
BUILD_HOOKS=(
  "/etc/NetworkManager/dispatcher.d/90-lab-ap-fw:${OPER_CON}"
  "/etc/NetworkManager/dispatcher.d/90-lab-ap2-fw:${FAB_CON}"
  "/etc/NetworkManager/dispatcher.d/91-lab-wired-fw:${STOR_CON}"
)

VARIANTS=(baseline observational mediated)

# Logging helpers
log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

# Check prerequisites
[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
command -v nft   >/dev/null || die "nftables not installed."
command -v nmcli >/dev/null || die "NetworkManager not installed."

# Derive the storage network from the Pi's address. This is used in the ruleset to allow operator->storage and fabrication->storage traffic, and to masquerade storage->WAN traffic.
STOR_NET="$(python3 - "$STOR_ADDR" <<'PY' 2>/dev/null || true
import ipaddress,sys
print(ipaddress.ip_interface(sys.argv[1]).network)
PY
)"
[[ -n ${STOR_NET:-} ]] || die "Could not derive the storage network from ${STOR_ADDR}."

# Resolve a connection name to its interface. This is needed because the build scripts create the connections, and labseg does not know which interface each connection is bound to. It first tries `nmcli con show id <name>` to get the device, and if that fails (e.g., for a disconnected Wi-Fi profile), it falls back to matching the MAC address of the connection to the MAC address of each wireless interface.
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

# Resolve the default route's interface. This is used to apply WAN egress rules only to the uplink interface, so inter-segment traffic keeps its real source address and captures stay readable.
uplink_iface() {
  ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

# Verify that a connection exists. If not, exit with an error. This is used to ensure that the build scripts have been run and the expected connections are present before proceeding with segmentation.
require_con() {
  nmcli con show id "$1" &>/dev/null || die "Connection '$1' not found. Run the build scripts first."
}
require_con "$OPER_CON"
require_con "$FAB_CON"
require_con "$STOR_CON"

# Resolve the connections to their interfaces. If any cannot be resolved, exit with an error. This is used to ensure that the build scripts have been run and the expected connections are present before proceeding with segmentation.
OPER_IF="$(con_iface "$OPER_CON")"
FAB_IF="$(con_iface "$FAB_CON")"
STOR_IF="$(con_iface "$STOR_CON")"
[[ -n $OPER_IF ]] || die "Could not determine the interface for '${OPER_CON}'."
[[ -n $FAB_IF  ]] || die "Could not determine the interface for '${FAB_CON}'."
[[ -n $STOR_IF ]] || die "Could not determine the interface for '${STOR_CON}'."

LAB_IFACES="\"${OPER_IF}\", \"${FAB_IF}\", \"${STOR_IF}\""

# Set up the segmenting ruleset. This verifies that the connections are present and have the expected addressing, enables AP isolation on the Wi-Fi segments, and prints instructions for the next step (choosing a variant).
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

  # Enable AP isolation on the Wi-Fi segments. This prevents intra-segment L2 traffic, which is a prerequisite for measuring the effects of segmentation. If AP isolation cannot be set, warn that intra-segment traffic is possible and record it as a measurement limitation.
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

  # Print instructions for the next step (choosing a variant).
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

# Emit a block rule. This prints a rule that drops traffic from $1 to $2, with the given verdict and comment. If LOG_DROPS is set, it also logs the blocked attempts at a rate of 10 per second.
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

# Is a break-glass window open and unexpired? An expired state file is treated
# as closed even if the timer that should have removed it never fired, so a
# missed timer fails toward the control rather than away from it.
bg_active() {
  [[ -f $BG_STATE ]] || return 1
  local expiry now
  expiry="$(cat "$BG_STATE" 2>/dev/null)"
  [[ -n $expiry ]] || return 1
  now="$(date -u +%s)"
  (( now < $(date -u -d "$expiry" +%s 2>/dev/null || echo 0) ))
}

# Generate the nftables ruleset for the given variant. This creates a table inet labseg with a forward chain that implements the segmentation policy, and a table ip labseg_nat that implements NAT for the storage segment. The generated ruleset is written to $NFT_FILE.
gen_ruleset() {
  local variant="$1" up_if
  local oper_fab oper_stor reverse
  up_if="$(uplink_iface)"

  case "$variant" in
    baseline)
      # Flat behaviour: everything permitted, both directions. A control that
      # blocked reverse-initiated traffic would not represent a flat network.
      oper_fab=accept; oper_stor=accept; reverse=accept ;;
    observational)
      # Identical to baseline, deliberately. The observational variant
      # observes; it does not constrain the workflow. Blocking anything here
      # would make the firewall do the mediation, and the variant comparison
      # would then measure nftables rather than the software.
      oper_fab=accept; oper_stor=accept; reverse=accept ;;
    mediated)
      # Job submission is mediated here because the printer has no ACL of its
      # own. Storage is NOT blocked here: write mediation lives in the Samba
      # config, which grants write to the service account alone. Enforcing it
      # at L3 as well would mean fabguard being down stops people reading a
      # design, which buys nothing the ACL does not already provide.
      oper_fab=block;  oper_stor=accept;  reverse=block ;;
    *) die "Unknown variant '${variant}'." ;;
  esac

  # Break-glass overrides the job-submission denial for the duration of the
  # window. Regenerating the whole ruleset rather than inserting a rule keeps
  # NFT_FILE the single source of truth, so the NetworkManager hook reapplies
  # the window intact after a reconnect instead of silently closing it.
  local bg_note=""
  if bg_active; then
    if [[ $variant == mediated ]]; then
      oper_fab=accept
      bg_note="  BREAK-GLASS OPEN until $(cat "$BG_STATE" 2>/dev/null)"
    fi
  fi

  local REJ="reject with icmpx admin-prohibited"

  {
    cat <<NFT
#!/usr/sbin/nft -f
# Generated by segment.sh — variant: ${variant}
# Do not edit; regenerate with: sudo $0 ${variant}
#
# WAN policy (constant across variants, so it cannot confound the comparison):
#   operator    -> WAN  ${OPER_WAN}
#   fabrication -> WAN  ${FAB_WAN}
#   storage     -> WAN  ${STOR_WAN}
#
# The create-then-delete pairs below are the idiomatic way to drop a table that
# may or may not exist: creating it first makes the delete unconditional.

NFT

    # Remove the build scripts' tables so they cannot override labseg.
    local t
    for t in "${SUBSUMED_TABLES[@]}"; do
      printf 'table %s\ndelete table %s\n' "$t" "$t"
    done

    # --- NetworkManager shared-mode tables ------------------------------------
    # NM's "shared" IPv4 mode installs `table ip nm-shared-<iface>` with its own
    # base chains, and labseg does not replace them by existing. Base chains are
    # ALL traversed in priority order and an accept in one does not end
    # evaluation, so labseg accepting at -20 means nothing once nm-shared
    # rejects the same packet at 0. Its filter_forward ends with
    #
    #     iifname "<if>" reject
    #     oifname "<if>" reject
    #
    # and a bare `reject` is ICMP port-unreachable -- which is exactly what an
    # operator pinging the printer sees, from the Pi, in EVERY variant
    # including baseline. Left in place it silently blocks operator ->
    # fabrication throughout, so the baseline is not a flat network and the
    # comparison measures NetworkManager.
    #
    # Its nat_postrouting is also wrong for this lab: it masquerades anything
    # leaving the segment, so inter-segment traffic reaches the printer wearing
    # the Pi's address and the machine cannot tell one workstation from
    # another. labseg_nat below masquerades to the uplink only.
    #
    # Both chains are flushed rather than the table dropped, because NM owns
    # the table and recreates it; an empty base chain with policy accept is
    # inert. Declaring each chain first makes the flush unconditional, the same
    # idiom as the create-then-delete pairs above. Priorities must match what
    # NM uses (filter_forward 0, nat_postrouting 100) or the declaration
    # collides with the existing chain.
    local nmif
    for nmif in "$OPER_IF" "$FAB_IF"; do
      cat <<NFT
table ip nm-shared-${nmif} {
  chain filter_forward  { type filter hook forward     priority 0;   policy accept; }
  chain nat_postrouting { type nat    hook postrouting priority 100; policy accept; }
}
flush chain ip nm-shared-${nmif} filter_forward
flush chain ip nm-shared-${nmif} nat_postrouting
NFT
    done

    cat <<NFT

table inet labseg
delete table inet labseg

table inet labseg {
  chain forward {
    type filter hook forward priority -20; policy accept;

    ct state established,related counter accept
NFT

    # Mediator exception: only needed if the service is NOT on the Pi. When it
    # is on the Pi, the Pi is the router and its traffic never traverses the
    # forward chain at all.
    [[ -n $MEDIATOR_IP ]] && \
      echo "    ip saddr ${MEDIATOR_IP} counter accept comment \"mediating service\""

    echo

    # --- operator-initiated ---------------------------------------------------
    if [[ $oper_fab == block ]]; then
      emit_block "ip saddr ${OPER_NET}" "ip daddr ${FAB_NET}" "$REJ" "oper->fab blocked (${variant})"
    elif [[ -n $bg_note ]]; then
      emit_accept "ip saddr ${OPER_NET}" "ip daddr ${FAB_NET}" "oper->fab BREAK-GLASS (${variant})"
    else
      emit_accept "ip saddr ${OPER_NET}" "ip daddr ${FAB_NET}" "oper->fab permitted (${variant})"
    fi

    if [[ $oper_stor == block ]]; then
      emit_block "ip saddr ${OPER_NET}" "ip daddr ${STOR_NET}" "$REJ" "oper->storage blocked (${variant})"
    elif [[ $variant == mediated ]]; then
      emit_accept "ip saddr ${OPER_NET}" "ip daddr ${STOR_NET}" \
                  "oper->storage reachable; writes denied at the Samba ACL"
    else
      emit_accept "ip saddr ${OPER_NET}" "ip daddr ${STOR_NET}" "oper->storage permitted (${variant})"
    fi

    echo

    # --- reverse-initiated: devices never originate toward the operator -------
    if [[ $reverse == block ]]; then
      emit_block "ip saddr ${FAB_NET}"  "ip daddr ${OPER_NET}" "drop" "fab->oper never initiated"
      emit_block "ip saddr ${FAB_NET}"  "ip daddr ${STOR_NET}" "drop" "fab->storage never"
      emit_block "ip saddr ${STOR_NET}" "ip daddr ${OPER_NET}" "drop" "storage->oper never initiated"
      emit_block "ip saddr ${STOR_NET}" "ip daddr ${FAB_NET}"  "drop" "storage->fab never"
    else
      emit_accept "ip saddr ${FAB_NET}"  "ip daddr ${OPER_NET}" "fab->oper permitted (${variant})"
      emit_accept "ip saddr ${FAB_NET}"  "ip daddr ${STOR_NET}" "fab->storage permitted (${variant})"
      emit_accept "ip saddr ${STOR_NET}" "ip daddr ${OPER_NET}" "storage->oper permitted (${variant})"
      emit_accept "ip saddr ${STOR_NET}" "ip daddr ${FAB_NET}"  "storage->fab permitted (${variant})"
    fi

    echo

    # --- home-LAN protection (subsumes the build scripts' block lists) --------
    # MUST precede the WAN rules. The WAN rules match on the outbound
    # interface, and traffic to a home-LAN host leaves by that same interface,
    # so an accept there would let operator traffic onto the home network
    # before this rule was ever reached. Destination-based denials go first;
    # interface-based permits go last.
    cat <<NFT
    ip saddr { ${OPER_NET}, ${FAB_NET}, ${STOR_NET} } ip daddr { ${BLOCK_NETS} } counter ${REJ} comment "home LAN protection"

NFT

    # --- WAN egress -----------------------------------------------------------
    # Held constant across variants. See the header for why.
    if [[ -n $up_if ]]; then
      local seg name net pol
      for seg in "OPER:${OPER_NET}:${OPER_WAN}" "FAB:${FAB_NET}:${FAB_WAN}" "STOR:${STOR_NET}:${STOR_WAN}"; do
        IFS=: read -r name net pol <<<"$seg"
        if [[ $pol == deny ]]; then
          emit_block "ip saddr ${net}" "oifname \"${up_if}\"" "$REJ" "${name} WAN denied (environment)"
        else
          emit_accept "ip saddr ${net}" "oifname \"${up_if}\"" "${name} WAN permitted (environment)"
        fi
      done
    else
      echo "    # no default route at generation time — WAN rules omitted"
    fi

    # --- IPv6 -----------------------------------------------------------------
    # Every rule above matches on `ip saddr`, so an IPv6 packet matches none of
    # them and would ride the accept policy straight through. The segmentation
    # is an IPv4 claim; this keeps v6 from quietly falsifying it.
    cat <<NFT

    iifname { ${LAB_IFACES} } meta nfproto ipv6 counter drop
  }
}
NFT

    # --- NAT ------------------------------------------------------------------
    # All three segments masquerade here now, because nm-shared's own
    # nat_postrouting was flushed above. Scoped to the uplink, so inter-segment
    # traffic keeps its real source address: the printer sees the workstation
    # that talked to it rather than the Pi, which is what makes equipment-side
    # logs and packet captures worth anything during a break-glass window.
    if [[ -n $up_if ]]; then
      cat <<NFT

table ip labseg_nat
delete table ip labseg_nat

table ip labseg_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat - 10; policy accept;
    ip saddr ${OPER_NET} oifname "${up_if}" counter masquerade
    ip saddr ${FAB_NET}  oifname "${up_if}" counter masquerade
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

# Check the share mount against what the variant expects. The observational
# variant must not be able to write to the share it is attesting to; the
# mediated variant has to write, because it is the sanctioned write path.
# This is advisory: a wrong mount is a measurement problem, not a reason to
# refuse to configure the network.
check_repo_mount() {
  local variant="$1" opts
  opts="$(findmnt -no OPTIONS --target "$REPO_MOUNT" 2>/dev/null || true)"
  if [[ -z $opts ]]; then
    case "$variant" in
      observational|mediated)
        warn "${REPO_MOUNT} is not mounted. The service cannot snapshot the share."
        echo "       sudo mount -a   (check /etc/fstab)" >&2 ;;
    esac
    return
  fi
  case "$variant" in
    observational)
      if [[ ,$opts, == *,ro,* ]]; then
        log "Share ${REPO_MOUNT} is read-only — correct for observational."
      else
        warn "Share ${REPO_MOUNT} is mounted READ-WRITE but the variant is observational."
        echo "       A service that attests to the integrity of a share it can write to is" >&2
        echo "       asserting something it cannot support. Remount with 'ro':" >&2
        echo "       sudo mount -o remount,ro ${REPO_MOUNT}" >&2
      fi ;;
    mediated)
      if [[ ,$opts, == *,ro,* ]]; then
        warn "Share ${REPO_MOUNT} is READ-ONLY but the variant is mediated."
        echo "       The service is the sanctioned write path and needs to write:" >&2
        echo "       sudo mount -o remount,rw ${REPO_MOUNT}" >&2
      else
        log "Share ${REPO_MOUNT} is writable — correct for mediated."
      fi
      # This mount is the SERVICE's. Operator workstations now reach the share
      # directly and must be read-only there, which is a Samba question this
      # script cannot answer from the Pi 5 side.
      echo "       Confirm separately that operator workstations get READ ONLY:" >&2
      echo "       on the NAS, 'read only = yes' with 'write list = @labsvc'." >&2
      echo "       If an operator can still write, the mediated claim is false and" >&2
      echo "       Repository Change Detection is the only thing catching it." >&2 ;;
  esac
}

# Open or close the break-glass window.
#
# Deliberately a separate command, run by a person, never by fabguard. The
# service is the thing most likely to be down when this is needed, and a
# control that can open the path it enforces -- triggered by its own failure --
# turns "crash the service" into the whole attack.
do_breakglass() {
  local action="${1:-}" variant expiry mins="${BREAKGLASS_MINUTES}"
  variant="$(cat "$VARIANT_FILE" 2>/dev/null || echo '')"

  case "$action" in
    on)
      [[ $variant == mediated ]] || die \
        "Break-glass only means something under 'mediated' (current: ${variant:-none}). \
Under baseline and observational the operator already reaches the equipment."
      [[ $mins =~ ^[0-9]+$ && $mins -gt 0 ]] || die "BREAKGLASS_MINUTES must be a positive integer."

      expiry="$(date -u -d "+${mins} minutes" +'%Y-%m-%dT%H:%M:%SZ')"
      mkdir -p "$STATE_DIR"
      printf '%s\n' "$expiry" > "$BG_STATE"
      chmod 0644 "$BG_STATE"

      gen_ruleset "$variant"
      nft -c -f "$NFT_FILE" || die "Generated ruleset failed validation."
      nft -f "$NFT_FILE"    || die "nft failed. Inspect ${NFT_FILE}"

      # Close it automatically. A window nobody remembers to shut is an
      # unmediated network with extra paperwork.
      systemctl stop "${BG_UNIT}.timer" 2>/dev/null || true
      if command -v systemd-run >/dev/null; then
        systemd-run --unit="$BG_UNIT" --on-active="${mins}m" \
          --description="Close the lab break-glass window" \
          "$(readlink -f "$0")" breakglass off >/dev/null 2>&1 \
          && log "Auto-close scheduled in ${mins} minute(s)" \
          || warn "Could not schedule auto-close — CLOSE IT BY HAND."
      else
        warn "systemd-run unavailable — no auto-close. CLOSE IT BY HAND."
      fi

      command -v logger >/dev/null && \
        logger -t labseg "break-glass OPENED until ${expiry} by ${SUDO_USER:-root}"

      cat <<EOF

  ######################################################################
  #  BREAK-GLASS OPEN — operator -> fabrication is PERMITTED           #
  #  expires ${expiry}                                   #
  ######################################################################

  Work done now is accounted for, not authorized. Do both of these:

    1. Open a degraded-mode exception in the portal covering this window.
       Prospectively if the portal is up; retrospectively if it was not.
    2. Close this window as soon as the service is back:
         sudo $0 breakglass off

  Detection is retrospective, because the collectors are part of the
  service that is down. On restart, Fabrication Activity Recording and
  Fabrication Artifact Verification find what ran and what is on the
  media, Repository Change Detection finds writes outside the sanctioned
  path, and Job Reconciliation ties them to the covering exception.

  A print that starts AND finishes inside the window may produce no
  observed job -- the printer keeps no history this service can read.
  The artifact left on the media is what catches it. Say so in the
  write-up rather than claiming the window is fully observed.

EOF
      ;;

    off)
      systemctl stop "${BG_UNIT}.timer" 2>/dev/null || true
      if [[ ! -f $BG_STATE ]]; then
        log "Break-glass was not open."
      else
        rm -f "$BG_STATE"
        command -v logger >/dev/null && \
          logger -t labseg "break-glass CLOSED by ${SUDO_USER:-root}"
        log "Break-glass closed"
      fi
      if [[ -n $variant ]]; then
        gen_ruleset "$variant"
        nft -c -f "$NFT_FILE" || die "Generated ruleset failed validation."
        nft -f "$NFT_FILE"    || die "nft failed. Inspect ${NFT_FILE}"
        log "Ruleset restored for variant '${variant}'"
      fi
      echo
      echo "  Reconcile the window in the portal: close the degraded-mode"
      echo "  exception and confirm what was fabricated during it."
      echo
      ;;

    status|"")
      if bg_active; then
        log "Break-glass OPEN until $(cat "$BG_STATE")"
      elif [[ -f $BG_STATE ]]; then
        warn "Break-glass state file is EXPIRED ($(cat "$BG_STATE")) but still present."
        warn "The ruleset treats it as closed. Run: sudo $0 breakglass off"
      else
        log "Break-glass closed"
      fi
      ;;
    *) die "Usage: $0 breakglass {on|off|status}" ;;
  esac
}

# Cross-check the network variant against the solution's own VARIANT. Running
# the mediated firewall with observational software (or the reverse) produces
# evaluation data that looks valid and is not, so it is worth catching here.
check_solution_variant() {
  local variant="$1" cfg sw
  cfg="$SOLUTION_CONFIG"
  if [[ -z $cfg ]]; then
    local here; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    for cfg in "${here}/../../solution/config.py" "${here}/../solution/config.py" \
               "/opt/fabguard/config.py"; do
      [[ -f $cfg ]] && break || cfg=""
    done
  fi
  [[ -n $cfg && -f $cfg ]] || return 0

  sw="$(grep -oP '^VARIANT\s*=\s*"\K[a-z]+' "$cfg" 2>/dev/null | head -1)"
  [[ -n $sw ]] || return 0

  if [[ $variant == baseline ]]; then
    log "Solution config says VARIANT=\"${sw}\" — stop the service for a baseline run."
  elif [[ $sw != "$variant" ]]; then
    warn "MISMATCH: network variant is '${variant}' but ${cfg} says VARIANT=\"${sw}\"."
    echo "       Evaluation data from this combination will look valid and will not be." >&2
    echo "       Set VARIANT = \"${variant}\" in config.py and restart the service." >&2
  else
    log "Solution config agrees: VARIANT=\"${sw}\"."
  fi
}

# Hook to reapply segmentation after a segment reconnects. This is needed because the build scripts' hooks (90-/91-) run after labseg's hook, so they would overwrite labseg's rules on reconnect. This hook runs after 90-/91- and reapplies the labseg ruleset.
install_hook() {
  cat > "$HOOK" <<EOF
#!/bin/sh
# Managed by segment.sh — reapplies segmentation after a segment reconnects.
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

# Variant selection. This generates the ruleset for the given variant, validates it, applies it, records the active variant, and installs the hook to reapply segmentation after a segment reconnects.
do_variant() {
  local variant="$1"
  mkdir -p "$STATE_DIR"

  # Switching variants closes any open window. A break-glass carried silently
  # into a different variant would be an open path nobody chose.
  if [[ -f $BG_STATE ]]; then
    rm -f "$BG_STATE"
    systemctl stop "${BG_UNIT}.timer" 2>/dev/null || true
    warn "Closed an open break-glass window before switching variant."
  fi

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

  check_repo_mount "$variant"
  check_solution_variant "$variant"
  echo

  if [[ $variant == observational ]]; then
    cat <<EOF
    NOTE: this ruleset is byte-for-byte the baseline policy, on purpose.
    The observational variant observes; it does not constrain the workflow.
    If the firewall blocked operator->fabrication here, the firewall would be
    doing the mediation and the comparison would measure nftables rather than
    the software. Report that as a finding: the observational variant needs
    no network change, which is a large part of why its friction is low.

EOF
  fi

  nft list table inet labseg 2>/dev/null | sed 's/^/    /'
  echo
  cat <<EOF
    Counters:  sudo nft list table inet labseg
    Blocks:    sudo journalctl -kf | grep labseg-block
    Reset:     sudo nft reset counters table inet labseg
EOF
}

# Status of the active variant. This prints the active variant, the uplink interface, the connections and their interfaces and networks, the AP isolation status of each Wi-Fi segment, the addresses of each segment, and the current ruleset and counters.
do_status() {
  local variant
  variant="$(cat "$VARIANT_FILE" 2>/dev/null || echo '<none>')"

  cat <<EOF

  Variant          ${variant}
  Break-glass      $(bg_active && echo "OPEN until $(cat "$BG_STATE")" \
                      || { [[ -f $BG_STATE ]] && echo "EXPIRED file present — run: $0 breakglass off" \
                           || echo "closed"; })
  Uplink           $(uplink_iface)
  WAN policy       operator ${OPER_WAN} · fabrication ${FAB_WAN} · storage ${STOR_WAN}
                   (constant across variants — environment, not solution)

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
  printf '  Share %s: %s\n' "$REPO_MOUNT" \
    "$(findmnt -no OPTIONS --target "$REPO_MOUNT" 2>/dev/null || echo 'not mounted')"
  [[ $variant != '<none>' ]] && { check_repo_mount "$variant"; check_solution_variant "$variant"; }

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

  # NM recreates its shared-mode rules whenever it feels like it, and they
  # reject inter-segment forwarding at a later priority than labseg. A single
  # rule back in either chain silently blocks operator -> fabrication in every
  # variant, so this is worth checking every time rather than assuming.
  local nmif n
  for nmif in "$OPER_IF" "$FAB_IF"; do
    n="$(nft list chain ip "nm-shared-${nmif}" filter_forward 2>/dev/null \
         | grep -cE '^\s+(ip|iifname|oifname|ct)' || true)"
    if [[ ${n:-0} -gt 0 ]]; then
      warn "nm-shared-${nmif} filter_forward has ${n} rule(s) — NM has re-added them."
      echo "       They reject inter-segment traffic at priority 0, after labseg at -20," >&2
      echo "       which blocks operator->fabrication in EVERY variant. Rerun:" >&2
      echo "       sudo $0 ${variant}" >&2
    fi
  done
  echo
}

# Teardown segmentation. This removes the labseg tables, restores the build scripts' tables, and disables AP isolation on the Wi-Fi segments. It does not modify the segment addressing, so all three segments remain up and separate.
do_teardown() {
  log "Removing segmentation"

  nft delete table inet labseg      2>/dev/null || true
  nft delete table ip   labseg_nat  2>/dev/null || true

  systemctl stop "${BG_UNIT}.timer" 2>/dev/null || true
  rm -f "$HOOK" /etc/NetworkManager/dispatcher.d/pre-up.d/95-lab-segment
  rm -f "$NFT_FILE" "$VARIANT_FILE" "$BG_STATE"

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

# Dispatch the command line to the appropriate function. The first argument is the command, and the rest are passed to that function.
case "${1:-}" in
  setup)                              do_setup ;;
  baseline|observational|mediated)    do_variant "$1" ;;
  breakglass)                         do_breakglass "${2:-status}" ;;
  status)                             do_status ;;
  teardown)                           do_teardown ;;
  minimal|full)
    # Renamed in step with the solution architecture. Deliberately refused
    # rather than aliased: the semantics changed as well as the names, so
    # silently running different rules under an old name would corrupt a
    # comparison against earlier runs.
    cat >&2 <<EOF
[x] '$1' no longer exists. The variants now follow the solution architecture:

      minimal  ->  observational   NOT a rename. 'minimal' blocked WAN egress and
                                   reverse-initiated traffic; 'observational' is
                                   deliberately identical to baseline, because the
                                   observational variant does not constrain the
                                   workflow. Earlier 'minimal' runs are not
                                   comparable to 'observational' runs.

      full     ->  mediated        Same intent, same operator-facing policy. WAN
                                   egress is now held constant across variants
                                   instead of being denied only here, so 'full'
                                   runs differ from 'mediated' runs on the WAN
                                   rules alone.

    Re-run any earlier measurements you intend to compare.
EOF
    exit 1 ;;
  *)
    cat <<EOF
Usage: sudo $0 {setup|baseline|observational|mediated|breakglass|status|teardown}

  setup          Verify segment addressing and enable AP isolation. Run once.

  baseline       No service. Current improvised practice (flat network).
                   operator <-> fabrication   permitted
                   operator <-> storage       permitted
                   fabrication <-> storage    permitted

  observational  Service observes; workflow unconstrained.
                   FORWARD POLICY IDENTICAL TO BASELINE, on purpose.
                   The observational variant watches, it does not mediate. A
                   firewall that blocked the workflow here would be doing the
                   mediation itself, and the comparison would measure nftables
                   rather than the software.
                   Share should be mounted read-only; checked, not enforced.

  mediated       Service is the sanctioned path.
                   operator -> fabrication    DENIED  (no ACL on the printer,
                                              so the network has to carry it)
                   operator -> storage        PERMITTED; writes are denied at
                                              the Samba ACL, not here
                   reverse-initiated          DENIED
                   Reachability is enforced here, write authority on the NAS.
                   Enforcing both at L3 would make the service a single point
                   of failure for reading a file, which the ACL already
                   handles better.

  breakglass on  Permit operator -> fabrication for ${BREAKGLASS_MINUTES} minutes so a network
                 fabrication path exists while the service is down. Run by a
                 person; fabguard never touches nftables. Closes itself via a
                 systemd timer, and is closed by any variant switch.
  breakglass off Close the window now and restore the variant's ruleset.
  breakglass     Report whether a window is open.

  status         Show addressing, AP isolation, active variant, break-glass
                 state, rule counters, share mount, and config.py agreement.
  teardown       Remove segmentation; restore per-segment firewalls.

WAN egress is held CONSTANT across all three variants, because it belongs to
the modelled environment rather than to the solution. Varying it alongside the
mediation policy would confound the comparison.
   operator    -> WAN  ${OPER_WAN}   workstations have internet; this is how
                              downloaded models arrive (leaf L-019)
   fabrication -> WAN  ${FAB_WAN}      printers are cloud-denied (interview I-02)
   storage     -> WAN  ${STOR_WAN}      the NAS never originates outbound

Env: OPER_CON FAB_CON STOR_CON OPER_NET FAB_NET STOR_ADDR
     OPER_WAN FAB_WAN STOR_WAN MEDIATOR_IP BLOCK_NETS LOG_DROPS
     REPO_MOUNT SOLUTION_CONFIG BREAKGLASS_MINUTES
EOF
    exit 1 ;;
esac
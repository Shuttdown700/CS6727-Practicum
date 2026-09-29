#!/usr/bin/env bash
# lab_capture.sh — capture controller for lab_segment.sh evaluation runs
#
# Captures every lab segment simultaneously, tags the run with the active
# control variant, and records the evidence needed to compare runs:
# nftables counters before and after, associated stations, DHCP leases,
# and a checksummed manifest of every pcap.
#
#   start     begin a run on all lab interfaces
#   stop      end the run, ship the tail, write closing metadata
#   status    show the active run
#   list      list runs on the capture store
#
# Usage:
#   sudo ./lab_capture.sh start
#   sudo ./lab_capture.sh start --label print-submission --duration 900
#   sudo ./lab_capture.sh start --filter 'not port 22'
#   sudo ./lab_capture.sh stop
#
# Design
#   * tcpdump writes to LOCAL staging, not straight to the NAS. A Wi-Fi hiccup
#     mid-write would corrupt an in-flight capture on a CIFS mount; locally it
#     cannot. Each file is shipped to the NAS by tcpdump's -z hook as soon as
#     rotation closes it, so staging holds only the active file plus any backlog.
#   * The uplink is refused as a capture source. Capturing it would record the
#     CIFS writes of the capture itself — an unbounded feedback loop.
#   * Counters are snapshotted at start and stop. The delta is the measurement:
#     which control rules actually fired during the run.

set -euo pipefail

STORE="${STORE:-/mnt/appo/labcaptures}"
STAGING="${STAGING:-/var/lib/labcap/staging}"
RUNTIME_DIR="/run/labcap"
ROTATE_SECS="${ROTATE_SECS:-300}"          # new file every 5 minutes
SNAPLEN="${SNAPLEN:-0}"                    # 0 = whole packet
COMPRESS="${COMPRESS:-1}"                  # gzip each closed file before shipping
MIN_FREE_MB="${MIN_FREE_MB:-2048}"         # refuse to start below this on staging
VARIANT_FILE="/etc/lab-segment/variant"
SHIPPER="/usr/local/sbin/labcap-ship"

# Segments to capture: label:connection-name
SEGMENTS="${SEGMENTS:-operator:lab-ap fabrication:lab-ap2 storage:lab-wired}"

log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
command -v tcpdump >/dev/null || die "tcpdump not installed."

uplink_iface() {
  ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

con_iface() {
  local d
  d="$(nmcli -t -f GENERAL.DEVICES con show id "$1" 2>/dev/null | cut -d: -f2)"
  [[ -n $d ]] && { echo "$d"; return; }
  nmcli -g connection.interface-name con show id "$1" 2>/dev/null || echo ""
}

# ---- shipper: invoked by tcpdump -z on each closed savefile -------------------
install_shipper() {
  cat > "$SHIPPER" <<'SH'
#!/bin/sh
# Managed by labcap.sh. Argument is the savefile tcpdump just closed.
f="$1"
[ -n "$f" ] && [ -f "$f" ] || exit 0
dest="$(cat /run/labcap/dest 2>/dev/null)" || exit 0
[ -n "$dest" ] || exit 0
[ "$(cat /run/labcap/compress 2>/dev/null)" = "1" ] && gzip -1 -- "$f" && f="${f}.gz"
[ -d "$dest" ] || exit 0
b="$(basename -- "$f")"
sum="$(sha256sum -- "$f" | cut -d' ' -f1)"
tmp="${dest}/.${b}.part"
if cp -- "$f" "$tmp" 2>/dev/null && mv -- "$tmp" "${dest}/${b}" 2>/dev/null; then
  # manifest stays in `sha256sum -c` format: exactly two fields. Anything else
  # (a timestamp column) makes the whole file unverifiable.
  ( flock 9; printf '%s  %s\n' "$sum" "$b" >&9 ) 9>>"/run/labcap/manifest"
  ( flock 8; printf '%s  %s\n' "$(date -Is)" "$b" >&8 ) 8>>"/run/labcap/shiplog"
  rm -f -- "$f"
else
  rm -f -- "$tmp"
fi
exit 0
SH
  chown root:root "$SHIPPER"; chmod 0755 "$SHIPPER"
}

snapshot() {  # $1 = destination directory, $2 = phase label
  local d="$1" p="$2"
  { date -Is; echo "phase=${p}"; } > "${d}/${p}.txt"
  for t in labseg labfw_lab_ap labfw_lab_ap2 labwired; do
    nft list table inet "$t" 2>/dev/null > "${d}/${p}-nft-${t}.txt" || true
  done
  nft list table ip labseg_nat 2>/dev/null > "${d}/${p}-nft-labseg_nat.txt" || true
  ip -4 -br addr             > "${d}/${p}-addr.txt" 2>/dev/null || true
  ip -4 route                > "${d}/${p}-route.txt" 2>/dev/null || true
  {
    for seg in $SEGMENTS; do
      local ifn; ifn="$(con_iface "${seg#*:}")"
      [[ -n $ifn ]] || continue
      echo "== ${seg%%:*} (${ifn}) =="
      iw dev "$ifn" station dump 2>/dev/null | grep -E '^Station|signal:|rx bytes|tx bytes' || echo "  (not wireless)"
      cat "/var/lib/NetworkManager/dnsmasq-${ifn}.leases" 2>/dev/null || true
    done
  } > "${d}/${p}-clients.txt" 2>/dev/null || true
}

# ---- start --------------------------------------------------------------------
do_start() {
  local label="" duration="" filter=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --label)    label="$2"; shift 2 ;;
      --duration) duration="$2"; shift 2 ;;
      --filter)   filter="$2"; shift 2 ;;
      *) die "Unknown option '$1'." ;;
    esac
  done

  [[ -f "${RUNTIME_DIR}/runid" ]] && die "A run is already active. Stop it first: sudo $0 stop"

  local variant up_if
  variant="$(cat "$VARIANT_FILE" 2>/dev/null || echo unknown)"
  [[ $variant == unknown ]] && warn "No active lab-segment variant — captures will be tagged 'unknown'."
  up_if="$(uplink_iface)"

  # resolve interfaces, refusing the uplink
  local -a names=() ifaces=()
  for seg in $SEGMENTS; do
    local nm="${seg%%:*}" con="${seg#*:}" ifn
    ifn="$(con_iface "$con")"
    if [[ -z $ifn ]]; then warn "Segment '${nm}' (${con}) has no interface — skipping."; continue; fi
    if [[ $ifn == "$up_if" ]]; then warn "Segment '${nm}' resolves to the uplink ${ifn} — refusing."; continue; fi
    [[ -e "/sys/class/net/${ifn}" ]] || { warn "${ifn} not present — skipping ${nm}."; continue; }
    names+=("$nm"); ifaces+=("$ifn")
  done
  (( ${#ifaces[@]} > 0 )) || die "No capturable lab interfaces found."

  # capture store must be writable
  mkdir -p "$STORE" 2>/dev/null || die "Cannot create ${STORE}. Is the capture store mounted?"
  touch "${STORE}/.w" 2>/dev/null || die "${STORE} is not writable."
  rm -f "${STORE}/.w"

  local runid rundir stagedir free_mb
  runid="$(date +%Y%m%d-%H%M%S)-${variant}${label:+-${label}}"
  rundir="${STORE}/${runid}"
  stagedir="${STAGING}/${runid}"
  mkdir -p "$rundir" "$stagedir"

  free_mb="$(df -Pm "$stagedir" | awk 'NR==2{print $4}')"
  (( free_mb >= MIN_FREE_MB )) || die "Only ${free_mb} MB free on staging; need ${MIN_FREE_MB} MB."

  install_shipper
  mkdir -p "$RUNTIME_DIR"
  printf '%s' "$rundir"   > "${RUNTIME_DIR}/dest"
  printf '%s' "$COMPRESS" > "${RUNTIME_DIR}/compress"
  : > "${RUNTIME_DIR}/manifest"
  : > "${RUNTIME_DIR}/shiplog"
  printf '%s' "$runid"    > "${RUNTIME_DIR}/runid"
  printf '%s' "$stagedir" > "${RUNTIME_DIR}/stagedir"

  {
    echo "run_id=${runid}"
    echo "variant=${variant}"
    echo "label=${label:-<none>}"
    echo "filter=${filter:-<none>}"
    echo "started=$(date -Is)"
    echo "rotate_secs=${ROTATE_SECS}"
    echo "snaplen=${SNAPLEN}"
    echo "compressed=${COMPRESS}"
    echo "host=$(hostname)"
    echo "kernel=$(uname -r)"
    echo "tcpdump=$(tcpdump --version 2>&1 | head -1)"
    echo "uplink=${up_if:-<none>}"
    for i in "${!ifaces[@]}"; do echo "segment=${names[$i]}:${ifaces[$i]}"; done
  } > "${rundir}/run.meta"

  snapshot "$rundir" "start"

  log "Run ${runid} (variant: ${variant})"
  for i in "${!ifaces[@]}"; do
    local nm="${names[$i]}" ifn="${ifaces[$i]}"
    local pattern="${stagedir}/${nm}_${ifn}_%Y%m%d-%H%M%S.pcap"
    # shellcheck disable=SC2086
    if [[ -n $duration ]]; then
      timeout --signal=TERM "$duration" \
        tcpdump -i "$ifn" -n -s "$SNAPLEN" -G "$ROTATE_SECS" -w "$pattern" -z "$SHIPPER" ${filter:+$filter} \
        >"${stagedir}/${nm}.log" 2>&1 &
    else
      tcpdump -i "$ifn" -n -s "$SNAPLEN" -G "$ROTATE_SECS" -w "$pattern" -z "$SHIPPER" ${filter:+$filter} \
        >"${stagedir}/${nm}.log" 2>&1 &
    fi
    echo "$!" >> "${RUNTIME_DIR}/pids"
    log "  ${nm} on ${ifn} (pid $!)"
  done

  sleep 2
  local alive=0 p
  while read -r p; do kill -0 "$p" 2>/dev/null && alive=$((alive+1)); done < "${RUNTIME_DIR}/pids"
  (( alive == ${#ifaces[@]} )) || {
    warn "Only ${alive}/${#ifaces[@]} captures started. Logs in ${stagedir}/*.log"
    head -5 "${stagedir}"/*.log 2>/dev/null || true
  }

  cat <<EOF

[+] Capturing ${#ifaces[@]} segment(s) under variant '${variant}'.
    Run:      ${runid}
    Store:    ${rundir}
    Staging:  ${stagedir}
    Rotation: every ${ROTATE_SECS}s, shipped to the store as each file closes
${duration:+    Duration: ${duration}s (auto-stops capture; still run 'stop' to close the run)}

    Progress: sudo $0 status
    Finish:   sudo $0 stop
EOF
}

# ---- stop ---------------------------------------------------------------------
do_stop() {
  [[ -f "${RUNTIME_DIR}/runid" ]] || die "No active run."
  local runid rundir stagedir
  runid="$(cat "${RUNTIME_DIR}/runid")"
  rundir="$(cat "${RUNTIME_DIR}/dest")"
  stagedir="$(cat "${RUNTIME_DIR}/stagedir")"

  log "Stopping ${runid}"
  if [[ -f "${RUNTIME_DIR}/pids" ]]; then
    while read -r p; do kill -TERM "$p" 2>/dev/null || true; done < "${RUNTIME_DIR}/pids"
    sleep 3
    while read -r p; do kill -KILL "$p" 2>/dev/null || true; done < "${RUNTIME_DIR}/pids"
  fi

  # tcpdump's -z hook never fires for the final, unrotated file — ship by hand.
  log "Shipping remaining files"
  shopt -s nullglob
  for f in "${stagedir}"/*.pcap; do "$SHIPPER" "$f"; done
  shopt -u nullglob

  snapshot "$rundir" "stop"
  {
    echo "ended=$(date -Is)"
    echo "files=$(wc -l < "${RUNTIME_DIR}/manifest" 2>/dev/null || echo 0)"
  } >> "${rundir}/run.meta"
  cp -f "${RUNTIME_DIR}/manifest" "${rundir}/manifest.sha256" 2>/dev/null || true
  cp -f "${RUNTIME_DIR}/shiplog"  "${rundir}/ship.log"        2>/dev/null || true

  # leftovers mean the store went away mid-run; keep them rather than lose data
  shopt -s nullglob
  local left=("${stagedir}"/*.pcap "${stagedir}"/*.pcap.gz)
  shopt -u nullglob
  if (( ${#left[@]} > 0 )); then
    warn "${#left[@]} file(s) could not be shipped and remain in ${stagedir}"
  else
    mv -f "${stagedir}"/*.log "${rundir}/" 2>/dev/null || true
    rmdir "$stagedir" 2>/dev/null || true
  fi

  rm -f "${RUNTIME_DIR}/runid" "${RUNTIME_DIR}/pids" "${RUNTIME_DIR}/dest" \
        "${RUNTIME_DIR}/stagedir" "${RUNTIME_DIR}/compress" \
        "${RUNTIME_DIR}/manifest" "${RUNTIME_DIR}/shiplog"

  log "Run complete"
  echo
  sed 's/^/    /' "${rundir}/run.meta"
  echo
  echo "    Captures: ${rundir}"
  echo "    Verify:   cd ${rundir} && sha256sum -c manifest.sha256"
}

# ---- status -------------------------------------------------------------------
do_status() {
  if [[ ! -f "${RUNTIME_DIR}/runid" ]]; then
    echo "  No active run."
    echo "  Variant: $(cat "$VARIANT_FILE" 2>/dev/null || echo '<none>')"
    return
  fi
  local runid rundir stagedir alive=0 total=0 p
  runid="$(cat "${RUNTIME_DIR}/runid")"
  rundir="$(cat "${RUNTIME_DIR}/dest")"
  stagedir="$(cat "${RUNTIME_DIR}/stagedir")"
  while read -r p; do total=$((total+1)); kill -0 "$p" 2>/dev/null && alive=$((alive+1)); done < "${RUNTIME_DIR}/pids"

  cat <<EOF

  Run          ${runid}
  Variant      $(cat "$VARIANT_FILE" 2>/dev/null || echo unknown)
  Captures     ${alive}/${total} running
  Shipped      $(wc -l < "${RUNTIME_DIR}/manifest" 2>/dev/null || echo 0) file(s)
  Staging      $(du -sh "$stagedir" 2>/dev/null | cut -f1) in ${stagedir}
  Store        $(du -sh "$rundir" 2>/dev/null | cut -f1) in ${rundir}
  Free (stage) $(df -Ph "$stagedir" | awk 'NR==2{print $4}')
  Free (store) $(df -Ph "$rundir" 2>/dev/null | awk 'NR==2{print $4}')

EOF
  ps -o pid=,etime=,args= -p "$(tr '\n' ',' < "${RUNTIME_DIR}/pids" | sed 's/,$//')" 2>/dev/null \
    | sed 's/^/    /' || true
  echo
}

# ---- list ---------------------------------------------------------------------
do_list() {
  [[ -d $STORE ]] || die "${STORE} not available. Is the capture store mounted?"
  printf '  %-42s %-10s %-8s %s\n' RUN VARIANT SIZE FILES
  for d in "$STORE"/*/; do
    [[ -d $d ]] || continue
    local n v
    n="$(basename "$d")"
    v="$(awk -F= '/^variant=/{print $2}' "${d}run.meta" 2>/dev/null || echo '?')"
    printf '  %-42s %-10s %-8s %s\n' "$n" "$v" \
      "$(du -sh "$d" 2>/dev/null | cut -f1)" \
      "$(find "$d" -name '*.pcap*' 2>/dev/null | wc -l)"
  done
}

# ---- dispatch -----------------------------------------------------------------
cmd="${1:-}"; shift || true
case "$cmd" in
  start)  do_start "$@" ;;
  stop)   do_stop ;;
  status) do_status ;;
  list)   do_list ;;
  *)
    cat <<EOF
Usage: sudo $0 {start|stop|status|list} [options]

  start [--label NAME] [--duration SECONDS] [--filter 'BPF']
            Begin a capture on every lab segment. The run is tagged with the
            active lab_segment.sh variant, so runs are comparable after the fact.

  stop      End the run, ship the final files, snapshot closing counters,
            and write the checksum manifest.

  status    Active run, per-interface capture health, shipped count, free space.
  list      Runs present on the capture store.

Env: STORE STAGING SEGMENTS ROTATE_SECS SNAPLEN COMPRESS MIN_FREE_MB

Each run directory contains:
  run.meta                 run id, variant, interfaces, host, timings
  start-*.txt / stop-*.txt  nftables counters, addressing, routes, clients
  manifest.sha256          checksum per pcap; verify with: sha256sum -c
  ship.log                 when each file reached the store
  <segment>_<if>_*.pcap.gz rotated captures
EOF
    exit 1 ;;
esac
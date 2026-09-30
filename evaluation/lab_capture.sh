#!/usr/bin/env bash
# lab_capture.sh — capture controller for lab_segment.sh evaluation runs
#
# Captures every lab segment simultaneously, tags the run with the active
# control variant, samples host resource pressure throughout, and records the
# evidence needed to compare runs: nftables counters before and after,
# associated stations, DHCP leases, a resource time series, and a checksummed
# manifest of every pcap.
#
#   start      begin a run on all lab interfaces
#   stop       end the run, ship the tail, write closing metadata
#   status     show the active run and its current resource reading
#   list       list runs on the capture store
#   resources  post-hoc resource analysis for a run
#
# Usage:
#   sudo ./lab_capture.sh start
#   sudo ./lab_capture.sh start --label print-submission --duration 900
#   sudo ./lab_capture.sh start --filter 'not port 22' --sample-interval 2
#   sudo ./lab_capture.sh stop
#   sudo ./lab_capture.sh resources 20260930-1102-full-print-submission
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
#   * Resource sampling exists to answer one question: when a run looks slow or
#     lossy, was the Pi the cause? The discriminator is the staging backlog read
#     against CPU. Backlog growing with CPU pinned means compute-bound; backlog
#     growing with CPU idle means the store or its link is the constraint.
#     Neither is visible from the pcaps alone, so both are recorded here.

set -euo pipefail

STORE="${STORE:-/mnt/appo/labcaptures}"
STAGING="${STAGING:-/var/lib/labcap/staging}"
RUNTIME_DIR="/run/labcap"
ROTATE_SECS="${ROTATE_SECS:-300}"          # new file every 5 minutes
SNAPLEN="${SNAPLEN:-0}"                    # 0 = whole packet
COMPRESS="${COMPRESS:-1}"                  # gzip each closed file before shipping
MIN_FREE_MB="${MIN_FREE_MB:-2048}"         # refuse to start below this on staging
SAMPLE_SECS="${SAMPLE_SECS:-5}"            # resource poll interval
RESOURCE_SAMPLE="${RESOURCE_SAMPLE:-1}"    # 0 = disable the sampler entirely
VARIANT_FILE="/etc/lab-segment/variant"
SHIPPER="/usr/local/sbin/labcap-ship"

# Thresholds used only to colour the verdict in `resources` / `status`.
T_CPU="${T_CPU:-85}"          # % busy, all cores
T_SOFTIRQ="${T_SOFTIRQ:-25}"  # % softirq — packet processing specifically
T_IO="${T_IO:-90}"            # % disk utilisation on the staging device
T_TEMP="${T_TEMP:-80}"        # degrees C
T_MEM_MB="${T_MEM_MB:-200}"   # MB available

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

# Backing block device for a path, reduced to the parent (mmcblk0p2 -> mmcblk0,
# sda1 -> sda, nvme0n1p1 -> nvme0n1) so it matches a /proc/diskstats row.
backing_dev() {
  local src base
  src="$(df -P "$1" 2>/dev/null | awk 'NR==2{print $1}')"
  base="$(basename "${src:-}")"
  case "$base" in
    mmcblk*p[0-9]*) echo "${base%p[0-9]*}" ;;
    nvme*n[0-9]*p[0-9]*) echo "${base%p[0-9]*}" ;;
    sd[a-z][0-9]*) echo "${base%%[0-9]*}" ;;
    *) echo "$base" ;;
  esac
}

# ---- shipper: invoked by tcpdump -z on each closed savefile -------------------
install_shipper() {
  cat > "$SHIPPER" <<'SH'
#!/bin/sh
# Managed by lab_capture.sh. Argument is the savefile tcpdump just closed.
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

# ---- resource sampler ---------------------------------------------------------
# Runs in the background for the life of the run, appending one CSV row per
# interval. Everything comes from /proc and /sys except the Pi-specific throttle
# word, so a sample costs a handful of small reads and is negligible next to
# three tcpdumps. Rates and deltas are computed against the previous sample, so
# the first row after the header is the baseline and carries zeros.
sampler() {  # $1 = csv path, $2 = interval secs, $3 = stagedir, $4.. = interfaces
  set +e
  local csv="$1" iv="$2" stagedir="$3"; shift 3
  local -a ifl=("$@")
  local tick; tick="$(getconf CLK_TCK 2>/dev/null || echo 100)"
  local ncpu; ncpu="$(nproc 2>/dev/null || echo 1)"
  local ddev; ddev="$(backing_dev "$stagedir")"
  local t0; t0="$(date +%s)"

  # header
  {
    printf 'ts,elapsed_s,load1,load5,cpu_busy_pct,cpu_iowait_pct,cpu_softirq_pct'
    printf ',mem_avail_mb,swap_used_mb,temp_c,arm_mhz,throttled'
    printf ',psi_cpu_avg10,psi_io_avg10,psi_mem_avg10'
    printf ',disk_util_pct,disk_write_mbs,stage_files,stage_mb,shipped_files'
    printf ',cap_cpu_pct,cap_rss_mb,gzip_n'
    for i in "${ifl[@]}"; do printf ',%s_rx_pps,%s_rx_drop,%s_rx_miss,%s_rx_fifo' "$i" "$i" "$i" "$i"; done
    printf '\n'
  } > "$csv"

  local p_total=0 p_idle=0 p_iowait=0 p_softirq=0
  local p_ioticks=0 p_wsect=0 p_capticks=0
  local -A p_rxp=() p_rxd=() p_rxm=() p_rxf=()
  local first=1

  while :; do
    local now ts elapsed
    now="$(date +%s)"; ts="$(date -Is)"; elapsed=$((now - t0))

    # --- cpu ------------------------------------------------------------------
    local cu cn cs ci cw cq cx cst total idle_all
    read -r _ cu cn cs ci cw cq cx cst _ < /proc/stat
    total=$((cu+cn+cs+ci+cw+cq+cx+cst)); idle_all=$((ci+cw))
    local d_total=$((total-p_total)) d_idle=$((idle_all-p_idle))
    local d_iow=$((cw-p_iowait)) d_sirq=$((cx-p_softirq))
    local cpu_busy=0 cpu_iow=0 cpu_sirq=0
    if (( first == 0 && d_total > 0 )); then
      cpu_busy=$(( (d_total-d_idle)*100/d_total ))
      cpu_iow=$(( d_iow*100/d_total ))
      cpu_sirq=$(( d_sirq*100/d_total ))
    fi
    p_total=$total; p_idle=$idle_all; p_iowait=$cw; p_softirq=$cx

    # --- load, memory ---------------------------------------------------------
    local l1 l5; read -r l1 l5 _ < /proc/loadavg
    local memav swtot swfree
    memav="$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo 2>/dev/null)"
    swtot="$(awk '/^SwapTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
    swfree="$(awk '/^SwapFree:/{print $2}' /proc/meminfo 2>/dev/null)"
    local swused=$(( ( ${swtot:-0} - ${swfree:-0} ) / 1024 ))

    # --- thermal / clock / throttle (Pi-specific; blank where unavailable) ----
    local temp mhz thr
    temp="$(awk '{printf "%.1f", $1/1000}' /sys/class/thermal/thermal_zone0/temp 2>/dev/null)"
    mhz="$(awk '{print int($1/1000)}' /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null)"
    thr="$(vcgencmd get_throttled 2>/dev/null | cut -d= -f2)"

    # --- pressure stall (absent unless CONFIG_PSI is enabled) -----------------
    local pc pi pm
    pc="$(awk '/^some/{print $2}' /proc/pressure/cpu    2>/dev/null | cut -d= -f2)"
    pi="$(awk '/^some/{print $2}' /proc/pressure/io     2>/dev/null | cut -d= -f2)"
    pm="$(awk '/^some/{print $2}' /proc/pressure/memory 2>/dev/null | cut -d= -f2)"

    # --- staging device I/O ---------------------------------------------------
    local ioticks=0 wsect=0 dutil=0 dwmbs=0
    if [[ -n $ddev ]]; then
      read -r ioticks wsect < <(awk -v d="$ddev" '$3==d{print $13, $10; exit}' /proc/diskstats 2>/dev/null)
      ioticks="${ioticks:-0}"; wsect="${wsect:-0}"
      if (( first == 0 && iv > 0 )); then
        dutil=$(( (ioticks - p_ioticks) * 100 / (iv * 1000) ))
        (( dutil > 100 )) && dutil=100
        dwmbs=$(( (wsect - p_wsect) * 512 / 1048576 / iv ))
      fi
      p_ioticks=$ioticks; p_wsect=$wsect
    fi

    # --- backlog and shipping -------------------------------------------------
    local sfiles smb shipped
    sfiles="$(find "$stagedir" -maxdepth 1 -name '*.pcap*' 2>/dev/null | wc -l)"
    smb="$(du -sm "$stagedir" 2>/dev/null | cut -f1)"
    shipped="$(wc -l < "${RUNTIME_DIR}/manifest" 2>/dev/null || echo 0)"

    # --- capture process cost -------------------------------------------------
    local capticks=0 caprss=0 capcpu=0 pid
    if [[ -f "${RUNTIME_DIR}/pids" ]]; then
      while read -r pid; do
        [[ -r "/proc/${pid}/stat" ]] || continue
        local u s r
        read -r u s < <(awk '{print $14, $15}' "/proc/${pid}/stat" 2>/dev/null)
        r="$(awk '/^VmRSS:/{print $2}' "/proc/${pid}/status" 2>/dev/null)"
        capticks=$(( capticks + ${u:-0} + ${s:-0} ))
        caprss=$(( caprss + ${r:-0} ))
      done < "${RUNTIME_DIR}/pids"
    fi
    if (( first == 0 && iv > 0 )); then
      capcpu=$(( (capticks - p_capticks) * 100 / (iv * tick) ))
    fi
    p_capticks=$capticks
    # pgrep -c prints 0 AND exits non-zero when nothing matches, so a
    # `|| echo 0` fallback would emit two lines and corrupt the row.
    local gzipn; gzipn="$(pgrep -c gzip 2>/dev/null)" || gzipn=0
    [[ $gzipn =~ ^[0-9]+$ ]] || gzipn=0

    # --- per-interface counters ----------------------------------------------
    local ifcols=""
    for i in "${ifl[@]}"; do
      local sd="/sys/class/net/${i}/statistics"
      local rp rd rm rf
      rp="$(cat "${sd}/rx_packets" 2>/dev/null || echo 0)"
      rd="$(cat "${sd}/rx_dropped" 2>/dev/null || echo 0)"
      rm="$(cat "${sd}/rx_missed_errors" 2>/dev/null || echo 0)"
      rf="$(cat "${sd}/rx_fifo_errors" 2>/dev/null || echo 0)"
      local pps=0 dd=0 dm=0 df=0
      if (( first == 0 && iv > 0 )); then
        pps=$(( (rp - ${p_rxp[$i]:-0}) / iv ))
        dd=$(( rd - ${p_rxd[$i]:-0} ))
        dm=$(( rm - ${p_rxm[$i]:-0} ))
        df=$(( rf - ${p_rxf[$i]:-0} ))
      fi
      p_rxp[$i]=$rp; p_rxd[$i]=$rd; p_rxm[$i]=$rm; p_rxf[$i]=$rf
      ifcols+=",${pps},${dd},${dm},${df}"
    done

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s%s\n' \
      "$ts" "$elapsed" "$l1" "$l5" "$cpu_busy" "$cpu_iow" "$cpu_sirq" \
      "${memav:-}" "$swused" "${temp:-}" "${mhz:-}" "${thr:-}" \
      "${pc:-}" "${pi:-}" "${pm:-}" \
      "$dutil" "$dwmbs" "${sfiles:-0}" "${smb:-0}" "${shipped:-0}" \
      "$capcpu" "$(( caprss / 1024 ))" "${gzipn:-0}" "$ifcols" >> "$csv"

    first=0
    sleep "$iv"
  done
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
  # host resource context, so a run is interpretable without the time series
  {
    echo "== cpu =="; nproc; grep -m1 'model name\|Model' /proc/cpuinfo 2>/dev/null
    echo "== mem =="; free -m
    echo "== thermal/throttle =="
    awk '{printf "temp_c=%.1f\n", $1/1000}' /sys/class/thermal/thermal_zone0/temp 2>/dev/null
    vcgencmd get_throttled 2>/dev/null || echo "vcgencmd unavailable"
    echo "== disk =="; df -h "$STAGING" "$STORE" 2>/dev/null
  } > "${d}/${p}-host.txt" 2>&1 || true
}

# ---- start --------------------------------------------------------------------
do_start() {
  local label="" duration="" filter="" sample="$SAMPLE_SECS"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --label)           label="$2"; shift 2 ;;
      --duration)        duration="$2"; shift 2 ;;
      --filter)          filter="$2"; shift 2 ;;
      --sample-interval) sample="$2"; shift 2 ;;
      --no-sample)       RESOURCE_SAMPLE=0; shift ;;
      *) die "Unknown option '$1'." ;;
    esac
  done
  [[ $sample =~ ^[0-9]+$ ]] && (( sample >= 1 )) || die "--sample-interval must be a positive integer."

  [[ -f "${RUNTIME_DIR}/runid" ]] && die "A run is already active. Stop it first: sudo $0 stop"

  local variant up_if
  variant="$(cat "$VARIANT_FILE" 2>/dev/null || echo unknown)"
  [[ $variant == unknown ]] && warn "No active lab_segment variant — captures will be tagged 'unknown'."
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
    echo "sample_secs=$( ((RESOURCE_SAMPLE)) && echo "$sample" || echo disabled)"
    echo "host=$(hostname)"
    echo "kernel=$(uname -r)"
    echo "ncpu=$(nproc)"
    echo "mem_total_mb=$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo)"
    echo "staging_dev=$(backing_dev "$stagedir")"
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

  # Sampler starts after the tcpdumps so its first delta covers a loaded system,
  # and its PID is tracked separately so `stop` can kill it last.
  if (( RESOURCE_SAMPLE )); then
    sampler "${stagedir}/resources.csv" "$sample" "$stagedir" "${ifaces[@]}" &
    echo "$!" > "${RUNTIME_DIR}/sampler_pid"
    log "  resource sampler every ${sample}s (pid $!)"
  else
    warn "Resource sampling disabled."
  fi

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
    Sampling: $( ((RESOURCE_SAMPLE)) && echo "every ${sample}s -> resources.csv" || echo disabled )
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

  # Sampler dies last so the tail of the series covers shutdown and the final
  # shipping burst — often where the backlog actually shows up.
  if [[ -f "${RUNTIME_DIR}/sampler_pid" ]]; then
    local sp; sp="$(cat "${RUNTIME_DIR}/sampler_pid")"
    kill -TERM "$sp" 2>/dev/null || true
    pkill -TERM -P "$sp" 2>/dev/null || true
  fi

  # tcpdump's -z hook never fires for the final, unrotated file — ship by hand.
  log "Shipping remaining files"
  shopt -s nullglob
  for f in "${stagedir}"/*.pcap; do "$SHIPPER" "$f"; done
  shopt -u nullglob

  # tcpdump prints its kernel-drop count only on exit. That number is the
  # authoritative answer to "did the host lose packets", so lift it into run.meta
  # rather than leaving it buried in a per-segment log.
  local dropped_total=0
  {
    shopt -s nullglob
    for lf in "${stagedir}"/*.log "${rundir}"/*.log; do
      local seg d
      seg="$(basename "$lf" .log)"
      d="$(awk '/dropped by kernel/{print $1; exit}' "$lf" 2>/dev/null)"
      [[ -n ${d:-} ]] || continue
      echo "dropped_by_kernel_${seg}=${d}"
      dropped_total=$(( dropped_total + d ))
    done
    shopt -u nullglob
    echo "dropped_by_kernel_total=${dropped_total}"
  } >> "${rundir}/run.meta"

  snapshot "$rundir" "stop"
  {
    echo "ended=$(date -Is)"
    echo "files=$(wc -l < "${RUNTIME_DIR}/manifest" 2>/dev/null || echo 0)"
  } >> "${rundir}/run.meta"
  cp -f "${RUNTIME_DIR}/manifest" "${rundir}/manifest.sha256" 2>/dev/null || true
  cp -f "${RUNTIME_DIR}/shiplog"  "${rundir}/ship.log"        2>/dev/null || true
  cp -f "${stagedir}/resources.csv" "${rundir}/resources.csv" 2>/dev/null || true

  # leftovers mean the store went away mid-run; keep them rather than lose data
  shopt -s nullglob
  local left=("${stagedir}"/*.pcap "${stagedir}"/*.pcap.gz)
  shopt -u nullglob
  if (( ${#left[@]} > 0 )); then
    warn "${#left[@]} file(s) could not be shipped and remain in ${stagedir}"
  else
    mv -f "${stagedir}"/*.log "${rundir}/" 2>/dev/null || true
    rm -f "${stagedir}/resources.csv"
    rmdir "$stagedir" 2>/dev/null || true
  fi

  rm -f "${RUNTIME_DIR}/runid" "${RUNTIME_DIR}/pids" "${RUNTIME_DIR}/dest" \
        "${RUNTIME_DIR}/stagedir" "${RUNTIME_DIR}/compress" \
        "${RUNTIME_DIR}/manifest" "${RUNTIME_DIR}/shiplog" \
        "${RUNTIME_DIR}/sampler_pid"

  log "Run complete"
  echo
  sed 's/^/    /' "${rundir}/run.meta"
  echo
  analyse_resources "$rundir"
  echo "    Captures: ${rundir}"
  echo "    Verify:   cd ${rundir} && sha256sum -c manifest.sha256"
}

# ---- resource analysis --------------------------------------------------------
analyse_resources() {  # $1 = run directory
  local rundir="$1" csv="${1}/resources.csv"
  [[ -f $csv ]] || { echo "    (no resource series for this run)"; echo; return; }

  local ncpu drops
  ncpu="$(awk -F= '/^ncpu=/{print $2}' "${rundir}/run.meta" 2>/dev/null || echo 1)"
  drops="$(awk -F= '/^dropped_by_kernel_total=/{print $2}' "${rundir}/run.meta" 2>/dev/null || echo 0)"

  awk -F, -v ncpu="${ncpu:-1}" -v drops="${drops:-0}" \
      -v tcpu="$T_CPU" -v tsirq="$T_SOFTIRQ" -v tio="$T_IO" -v ttemp="$T_TEMP" -v tmem="$T_MEM_MB" '
  NR==1 { for (i=1;i<=NF;i++) col[$i]=i; next }
  {
    n++
    v_cpu=$(col["cpu_busy_pct"]);  if (v_cpu>mx_cpu) mx_cpu=v_cpu;   s_cpu+=v_cpu
    v_si=$(col["cpu_softirq_pct"]);if (v_si>mx_si)  mx_si=v_si;      s_si+=v_si
    v_io=$(col["disk_util_pct"]);  if (v_io>mx_io)  mx_io=v_io;      s_io+=v_io
    v_w=$(col["disk_write_mbs"]);  if (v_w>mx_w)    mx_w=v_w
    v_t=$(col["temp_c"]);          if (v_t>mx_t)    mx_t=v_t
    v_m=$(col["mem_avail_mb"]);    if (n==1||v_m<mn_m) mn_m=v_m
    v_l=$(col["load1"]);           if (v_l>mx_l)    mx_l=v_l
    v_b=$(col["stage_files"]);     if (v_b>mx_b)    mx_b=v_b
    v_c=$(col["cap_cpu_pct"]);     if (v_c>mx_c)    mx_c=v_c
    thr=$(col["throttled"]);       if (thr!="" && thr!="0x0") thr_seen=thr
    # backlog trend: mean of the last third vs the first third
    bl[n]=v_b
  }
  END {
    if (n<2) { print "    (resource series too short to analyse)"; exit }
    third=int(n/3); if (third<1) third=1
    for (i=1;i<=third;i++) b1+=bl[i]
    for (i=n-third+1;i<=n;i++) b2+=bl[i]
    b1/=third; b2/=third

    printf "    Resource summary (%d samples)\n", n
    printf "      CPU busy      max %3d%%   mean %3d%%\n", mx_cpu, s_cpu/n
    printf "      CPU softirq   max %3d%%   mean %3d%%   (packet processing)\n", mx_si, s_si/n
    printf "      tcpdump CPU   max %3d%%   (of one core; %d cores present)\n", mx_c, ncpu
    printf "      Load (1m)     max %.2f\n", mx_l
    printf "      Disk util     max %3d%%   peak write %d MB/s\n", mx_io, mx_w
    printf "      Mem available min %d MB\n", mn_m
    if (mx_t>0) printf "      Temperature   max %.1f C\n", mx_t
    printf "      Staging backlog max %d file(s)   first-third %.1f -> last-third %.1f\n", mx_b, b1, b2
    printf "      Kernel drops  %d packet(s)\n", drops
    print  ""

    v=0
    if (drops+0 > 0) { printf "    [!] %d packets dropped by the kernel — the host did not keep up.\n", drops; v=1 }
    if (mx_cpu+0 >= tcpu)  { printf "    [!] CPU hit %d%% (threshold %d%%) — compute-bound.\n", mx_cpu, tcpu; v=1 }
    if (mx_si+0  >= tsirq) { printf "    [!] softirq hit %d%% — packet processing is saturating a core.\n", mx_si; v=1 }
    if (mx_io+0  >= tio)   { printf "    [!] staging disk hit %d%% utilisation — storage-bound.\n", mx_io; v=1 }
    if (mx_t+0   >= ttemp) { printf "    [!] peak %.1f C — check for thermal throttling.\n", mx_t; v=1 }
    if (mn_m+0   <= tmem)  { printf "    [!] available memory fell to %d MB.\n", mn_m; v=1 }
    if (thr_seen != "")    { printf "    [!] throttle word %s reported (bit 0 under-voltage, bit 1 freq-capped, bit 2 throttled).\n", thr_seen; v=1 }

    if (b2 > b1 + 1) {
      if (mx_cpu+0 >= tcpu || mx_si+0 >= tsirq)
        print  "    [!] Backlog grew while CPU was saturated: compute is the constraint."
      else
        print  "    [!] Backlog grew while CPU had headroom: the capture store or its link is the constraint, not the Pi."
      v=1
    }
    if (v==0) print "    [ok] No resource constraint evident. Delays are not explained by this host."
    print ""
  }' "$csv"
}

do_resources() {
  local target="${1:-}" rundir
  if [[ -z $target ]]; then
    if [[ -f "${RUNTIME_DIR}/dest" ]]; then
      rundir="$(cat "${RUNTIME_DIR}/dest")"
      warn "Run still active — analysing the series so far."
    else
      die "Give a run id. List them with: sudo $0 list"
    fi
  else
    rundir="${STORE}/${target}"
  fi
  [[ -d $rundir ]] || die "No such run: ${rundir}"
  echo
  echo "  ${rundir##*/}"
  echo
  analyse_resources "$rundir"
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

  local sampler_state="off"
  if [[ -f "${RUNTIME_DIR}/sampler_pid" ]]; then
    kill -0 "$(cat "${RUNTIME_DIR}/sampler_pid")" 2>/dev/null && sampler_state="running" || sampler_state="DEAD"
  fi

  cat <<EOF

  Run          ${runid}
  Variant      $(cat "$VARIANT_FILE" 2>/dev/null || echo unknown)
  Captures     ${alive}/${total} running
  Sampler      ${sampler_state}
  Shipped      $(wc -l < "${RUNTIME_DIR}/manifest" 2>/dev/null || echo 0) file(s)
  Staging      $(du -sh "$stagedir" 2>/dev/null | cut -f1) in ${stagedir}
  Store        $(du -sh "$rundir" 2>/dev/null | cut -f1) in ${rundir}
  Free (stage) $(df -Ph "$stagedir" | awk 'NR==2{print $4}')
  Free (store) $(df -Ph "$rundir" 2>/dev/null | awk 'NR==2{print $4}')
EOF

  local csv="${stagedir}/resources.csv"
  if [[ -f $csv ]]; then
    echo
    echo "  Latest sample:"
    # Columns are looked up by header name, not position, so adding a metric to
    # the sampler never silently shifts what this prints.
    awk -F, 'NR==1{for(i=1;i<=NF;i++) c[$i]=i; next} {for(i=1;i<=NF;i++) v[i]=$i; got=1}
      END{ if(!got){print "    (no samples yet)"; exit}
        printf "    cpu %s%%  softirq %s%%  load %s  mem %s MB  temp %sC  disk %s%%  backlog %s file(s)  tcpdump %s%% of a core\n",
          v[c["cpu_busy_pct"]], v[c["cpu_softirq_pct"]], v[c["load1"]], v[c["mem_avail_mb"]],
          v[c["temp_c"]], v[c["disk_util_pct"]], v[c["stage_files"]], v[c["cap_cpu_pct"]] }' "$csv" 2>/dev/null \
      || echo "    (unreadable)"
    echo "    Full series: ${csv}"
  fi

  echo
  ps -o pid=,etime=,args= -p "$(tr '\n' ',' < "${RUNTIME_DIR}/pids" | sed 's/,$//')" 2>/dev/null \
    | sed 's/^/    /' || true
  echo
}

# ---- list ---------------------------------------------------------------------
do_list() {
  [[ -d $STORE ]] || die "${STORE} not available. Is the capture store mounted?"
  printf '  %-42s %-10s %-8s %-6s %s\n' RUN VARIANT SIZE FILES DROPS
  for d in "$STORE"/*/; do
    [[ -d $d ]] || continue
    local n v dr
    n="$(basename "$d")"
    v="$(awk -F= '/^variant=/{print $2}' "${d}run.meta" 2>/dev/null || echo '?')"
    dr="$(awk -F= '/^dropped_by_kernel_total=/{print $2}' "${d}run.meta" 2>/dev/null)"
    printf '  %-42s %-10s %-8s %-6s %s\n' "$n" "$v" \
      "$(du -sh "$d" 2>/dev/null | cut -f1)" \
      "$(find "$d" -name '*.pcap*' 2>/dev/null | wc -l)" \
      "${dr:--}"
  done
}

# ---- dispatch -----------------------------------------------------------------
cmd="${1:-}"; shift || true
case "$cmd" in
  start)     do_start "$@" ;;
  stop)      do_stop ;;
  status)    do_status ;;
  list)      do_list ;;
  resources) do_resources "${1:-}" ;;
  *)
    cat <<EOF
Usage: sudo $0 {start|stop|status|list|resources} [options]

  start [--label NAME] [--duration SECONDS] [--filter 'BPF']
        [--sample-interval SECONDS] [--no-sample]
            Begin a capture on every lab segment. The run is tagged with the
            active lab_segment.sh variant, so runs are comparable after the fact.
            A background sampler records host resource pressure throughout.

  stop      End the run, ship the final files, snapshot closing counters, lift
            tcpdump's kernel-drop counts into run.meta, and print the resource
            verdict.

  status    Active run, capture health, shipped count, free space, and the most
            recent resource sample.

  list      Runs on the capture store, with kernel drops per run.

  resources [RUN_ID]
            Resource summary and verdict for a finished run; with no argument,
            the run currently in progress.

Env: STORE STAGING SEGMENTS ROTATE_SECS SNAPLEN COMPRESS MIN_FREE_MB
     SAMPLE_SECS RESOURCE_SAMPLE T_CPU T_SOFTIRQ T_IO T_TEMP T_MEM_MB

Each run directory contains:
  run.meta                 run id, variant, interfaces, host spec, timings,
                           kernel drops per segment
  start-*.txt / stop-*.txt  nftables counters, addressing, routes, clients, host
  resources.csv            resource time series, one row per sample interval
  manifest.sha256          checksum per pcap; verify with: sha256sum -c
  ship.log                 when each file reached the store
  <segment>_<if>_*.pcap.gz rotated captures
EOF
    exit 1 ;;
esac
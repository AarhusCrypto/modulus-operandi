#!/usr/bin/env bash
# Benchmark grid over TCP between parties in network namespaces with netem; see usage below.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/bench.sh [options]

Runs `modulus-operandi party` processes, one per party, for every party count in every
cell: each latency batch (one instance, no rate) at each latency RTT, and each throughput
batch at each instance count, rate and throughput RTT, the instances being batches in
flight at once. After the build, the script re-executes itself in a private network
namespace (`unshare -rn`, or `unshare -n` as root), where each party gets a network
namespace of its own, joined to the others by a bridge through a veth pair; netem on each
party's egress delays by RTT/2 and caps that party's uplink at the rate, and netem on the
bridge's end of the pair caps its downlink at the same rate, without delay, queueing
bursts from several senders. Per repetition the protocols run in turn, each as a fresh
set of processes with a fresh --sid and --seed <rep>, and with --reps 2: the first
repetition of the same configuration is an untimed warm-up, left out, so that the
measured second one runs on connections whose TCP windows have grown and on a heap
already in use, as in a running service, rather than cold.

Options (the variable in brackets sets the same):
  --parties LIST          party counts [PARTIES, default "2 4 8 16"]
  --rtts LIST             RTTs in ms of the latency cells [RTTS, default "1 10 100"]
  --throughput-rtts LIST  RTTs in ms of the throughput cells [THROUGHPUT_RTTS, default 1]
  --rates LIST            per-party uplink rates of the throughput cells, "none" for
                          unlimited [RATES, default "100mbit 1gbit"]
  --protocols LIST        [PROTOCOLS, default "modconv1 modconv2 zzlp25"]
  --reps N                repetitions per cell [REPS, default 15]
  --latency-batch LIST    batches of the latency cells, "" skips them [LATENCY_BATCH, default 1]
  --throughput-batch LIST batches of the throughput cells, per instance, "" skips them
                          [THROUGHPUT_BATCH, default 256]
  --instances LIST        instance counts of the throughput cells
                          [INSTANCES, default 256]
  --cores LIST            comma-separated, pins party i to the i-th with taskset; on a
                          hybrid CPU, choose performance cores [CORES, unset: no pinning]
  --out FILE              summary CSV [OUT, default bench-<timestamp>.csv]; the raw
                          per-party lines go to FILE with "-raw.csv" in place of ".csv"
  --no-warmup             no warm-up repetition: --reps 1, each measured repetition cold,
                          for quick checks [WARMUP=0, default 1]
  --no-netns              never use network namespaces; needs ALLOW_BARE_LOOPBACK=1
  --dry-run               print the commands instead of running them
  -h, --help

A repetition in which a party exits non-zero is left out with a warning; the summary
gives the median, minimum and 90th percentile over the repetitions that completed, the
throughput dec_per_s = batch * instances * 1e6 / median, and the number of those
repetitions. The raw per-party CSV has no throughput column.

Other variables: BASE_PORT (every party's port, default 47000; on the bare loopback,
party i listens on BASE_PORT + i), TIMEOUT (party --timeout in seconds, default 600),
PARTY_ARGS (more party flags, e.g. "--lwe-dim 1024 -k 64"), ALLOW_BARE_LOOPBACK=1
(where network namespaces are unavailable, or with --no-netns: all parties on
127.0.0.1, RTT 0, no rate, no netem).

The defaults are the cells of the paper's tables: the parties, RTTs and rates of the
evaluation of Zyskind et al. (CCS 2025) plus 2 parties, with throughput at RTT 1 ms and
256 instances of 256. RTTS=0 THROUGHPUT_RTTS=0 RATES=none gives a baseline without
emulation, and --instances "1 2 4 8 16 32 64 128 256" shows per protocol the instance
count that saturates the link.
USAGE
}

die() {
  echo "bench.sh: $*" >&2
  exit 1
}
warn() { echo "bench.sh: warning: $*" >&2; }

PARTIES=${PARTIES:-2 4 8 16}
RTTS=${RTTS:-1 10 100}
THROUGHPUT_RTTS=${THROUGHPUT_RTTS:-1}
RATES=${RATES:-100mbit 1gbit}
PROTOCOLS=${PROTOCOLS:-modconv1 modconv2 zzlp25}
REPS=${REPS:-15}
LATENCY_BATCH=${LATENCY_BATCH-1}
THROUGHPUT_BATCH=${THROUGHPUT_BATCH-256}
INSTANCES=${INSTANCES-256}
CORES=${CORES:-}
OUT=${OUT:-}
BASE_PORT=${BASE_PORT:-47000}
TIMEOUT=${TIMEOUT:-600}
PARTY_ARGS=${PARTY_ARGS:-}
WARMUP=${WARMUP:-1}
DRY_RUN=0
NO_NETNS=0
ARGS=("$@")

# Checks that the option in $1 has a value.
arg() { (($# >= 2)) || die "$1 needs a value"; }

while (($#)); do
  case $1 in
    --parties) arg "$@"; PARTIES=$2; shift ;;
    --rtts) arg "$@"; RTTS=$2; shift ;;
    --throughput-rtts) arg "$@"; THROUGHPUT_RTTS=$2; shift ;;
    --rates) arg "$@"; RATES=$2; shift ;;
    --protocols) arg "$@"; PROTOCOLS=$2; shift ;;
    --reps) arg "$@"; REPS=$2; shift ;;
    --latency-batch) arg "$@"; LATENCY_BATCH=$2; shift ;;
    --throughput-batch) arg "$@"; THROUGHPUT_BATCH=$2; shift ;;
    --instances) arg "$@"; INSTANCES=$2; shift ;;
    --cores) arg "$@"; CORES=$2; shift ;;
    --out) arg "$@"; OUT=$2; shift ;;
    --no-warmup) WARMUP=0 ;;
    --no-netns) NO_NETNS=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release/modulus-operandi
IFS=, read -ra CORE_LIST <<<"$CORES"
read -ra EXTRA <<<"$PARTY_ARGS"
OUT=${OUT:-bench-$(date +%Y%m%d-%H%M%S).csv}
RAW=${OUT%.csv}-raw.csv

is_num() { [[ $1 =~ ^[0-9]+([.][0-9]+)?$ ]]; }
[[ $REPS =~ ^[1-9][0-9]*$ ]] || die "--reps must be a positive integer, got '$REPS'"
[[ $WARMUP == [01] ]] || die "WARMUP must be 0 or 1, got '$WARMUP'"
# Each process set runs WARMUP untimed repetitions, then the measured one, whose rep column
# is WARMUP.
PARTY_REPS=$((WARMUP + 1))
for r in $RTTS $THROUGHPUT_RTTS; do is_num "$r" || die "bad RTT '$r'"; done
for r in $RATES; do
  [[ $r == none || ${r,,} =~ ^[0-9]+([.][0-9]+)?([kmgt]i?)?(bit|bps)$ ]] || die "bad rate '$r', e.g. 100mbit"
done
for b in $LATENCY_BATCH $THROUGHPUT_BATCH; do [[ $b =~ ^[1-9][0-9]*$ ]] || die "bad batch '$b'"; done
for j in $INSTANCES; do [[ $j =~ ^[1-9][0-9]*$ ]] || die "bad instance count '$j'"; done
[[ -z ${THROUGHPUT_BATCH// /} || -n ${INSTANCES// /} ]] || die "throughput batches need --instances"
NMAX=0
for n in $PARTIES; do
  if [[ ! $n =~ ^[0-9]+$ ]] || ((n < 2 || n > 253)); then die "bad party count '$n'"; fi
  [[ -z $CORES ]] || ((n <= ${#CORE_LIST[@]})) || die "a cell with $n parties needs $n cores, CORES has ${#CORE_LIST[@]}"
  ((n <= NMAX)) || NMAX=$n
done
[[ -n ${LATENCY_BATCH// /} || -n ${THROUGHPUT_BATCH// /} ]] || die "both batches are empty"

# The cells, as (rtt, batch, instances, rate): each latency batch at one instance without a
# rate at each latency RTT, each throughput batch at each instance count per rate at each
# throughput RTT, each cell once.
CELLS=()
add_cell() {
  local c
  for c in "${CELLS[@]}"; do [[ $c == "$1" ]] && return; done
  CELLS+=("$1")
}
for b in $LATENCY_BATCH; do
  for rtt in $RTTS; do add_cell "$rtt $b 1 none"; done
done
for b in $THROUGHPUT_BATCH; do
  for rtt in $THROUGHPUT_RTTS; do
    for j in $INSTANCES; do
      for rate in $RATES; do add_cell "$rtt $b $j $rate"; done
    done
  done
done
((${#CELLS[@]})) || die "no cells: every latency or throughput list is empty"

# Prints a command, quoting only the arguments that need it.
show() {
  local a out=()
  for a in "$@"; do
    if [[ $a =~ ^[A-Za-z0-9_./:,=+-]+$ ]]; then out+=("$a"); else out+=("$(printf '%q' "$a")"); fi
  done
  echo "${out[*]}"
}

# Prints a command (dry run) or runs it.
run() {
  if ((DRY_RUN)); then
    show "$@"
  else
    "$@"
  fi
}

# The unshare that gives this user a network namespace of its own.
if ((EUID == 0)); then UNSHARE=(unshare -n); else UNSHARE=(unshare -rn); fi

# Succeeds if the unshare works, else sets NETNS_ERR to why not.
netns_ok() {
  command -v unshare >/dev/null || { NETNS_ERR="unshare not found"; return 1; }
  NETNS_ERR=$("${UNSHARE[@]}" true 2>&1) && return
  NETNS_ERR="${UNSHARE[*]} fails${NETNS_ERR:+: $NETNS_ERR}"
  return 1
}

# The mode: network namespaces, which unshare gives root and, with unprivileged user
# namespaces, any user; or the bare loopback without netem. Inside the outer namespace,
# the re-executed script is its root and skips this.
BARE=0
if [[ -n ${BENCH_IN_NETNS:-} ]]; then
  ((EUID == 0)) || die "BENCH_IN_NETNS is set, but this is not the root of a namespace"
  MODE=netns
else
  NETNS_ERR=
  if ((!NO_NETNS)) && netns_ok; then
    MODE=netns
  elif [[ ${ALLOW_BARE_LOOPBACK:-0} == 1 ]]; then
    MODE=bare
    BARE=1
    for c in "${CELLS[@]}"; do
      read -r rtt _ _ rate <<<"$c"
      [[ $rtt == 0 ]] || die "on the bare loopback only RTT 0 is possible, got RTTS='$RTTS' THROUGHPUT_RTTS='$THROUGHPUT_RTTS'"
      [[ $rate == none ]] || die "on the bare loopback no rate is possible, got RATES='$RATES'"
    done
    if ((NO_NETNS)); then
      warn "--no-netns: measuring on the bare loopback, without netem"
    else
      warn "no network namespace ($NETNS_ERR): measuring on the bare loopback, without netem"
    fi
  else
    REFUSE="the emulation needs network namespaces; run where unshare -rn works (unprivileged user"
    REFUSE+=" namespaces, not with --no-netns), as root (sudo -E env PATH=\"\$PATH\" $0), or with"
    REFUSE+=" ALLOW_BARE_LOOPBACK=1 RTTS=0 THROUGHPUT_RTTS=0 RATES=none on the bare loopback"
    ((NO_NETNS)) || REFUSE+=" ($NETNS_ERR)"
    ((DRY_RUN)) || die "$REFUSE"
    warn "a real run would refuse: $REFUSE"
    MODE=netns
  fi
  case $MODE in
    netns) DESC="network namespaces" ;;
    bare) DESC="bare loopback" ;;
  esac
  echo "bench.sh: mode: $DESC" >&2
  ((DRY_RUN)) && echo "# mode: $DESC"
  if [[ $MODE == netns && -n ${THROUGHPUT_BATCH// /} ]]; then
    BACKLOG=$(cat /proc/sys/net/core/netdev_max_backlog 2>/dev/null) || BACKLOG=
    if [[ ! $BACKLOG =~ ^[0-9]+$ ]]; then
      warn "cannot read net.core.netdev_max_backlog; the paper's throughput cells ran at 100000"
    elif ((BACKLOG < 100000)); then
      warn "net.core.netdev_max_backlog is $BACKLOG; the paper's throughput cells ran at 100000" \
        "(sudo sysctl -w net.core.netdev_max_backlog=100000)"
    fi
  fi
  echo "bench.sh: RUSTFLAGS: ${RUSTFLAGS:-none}" >&2

  # The build runs outside the namespace, which has no network for cargo; under sudo, as the
  # invoking user, so that target/ keeps its owner.
  BUILD=(cargo build --release --manifest-path "$ROOT/Cargo.toml")
  if ((EUID == 0)) && [[ -n ${SUDO_USER:-} ]]; then
    BUILD=(sudo -u "$SUDO_USER" -E env "PATH=$PATH" "${BUILD[@]}")
  fi
  run "${BUILD[@]}"
  if [[ $MODE == netns ]]; then
    if ((DRY_RUN)); then
      echo "# the rest runs inside: BENCH_IN_NETNS=1 $(show "${UNSHARE[@]}" "$0" "${ARGS[@]}")"
    else
      export BENCH_IN_NETNS=1
      exec "${UNSHARE[@]}" "$0" "${ARGS[@]}"
    fi
  fi
fi

if [[ -n $CORES ]]; then
  PINNING=
  for i in "${!CORE_LIST[@]}"; do PINNING+=", party $i on core ${CORE_LIST[i]}"; done
  echo "bench.sh: pinning: ${PINNING#, }" >&2
else
  echo "bench.sh: pinning: none" >&2
fi
if ((WARMUP)); then
  echo "bench.sh: warm-up: one untimed repetition before each measured one, in the same processes" >&2
else
  echo "bench.sh: warm-up: none, every measured repetition cold" >&2
fi

PIDS=()
HOLDERS=()
WORK=
# Party processes first, then the holders of the party namespaces, whose veths vanish with
# them; the outer namespace, with the bridge, vanishes with this script.
cleanup() {
  local pid
  for pid in "${PIDS[@]}" "${HOLDERS[@]}"; do kill "$pid" 2>/dev/null || true; done
  [[ -n $WORK ]] && rm -rf "$WORK"
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Party i's address in its namespace.
party_ip() { echo "10.0.0.$(($1 + 1))"; }

# Runs (or prints) a command in party $1's network namespace.
in_ns() {
  local i=$1
  shift
  run nsenter -t "${HOLDERS[i]}" -n "$@"
}

# Waits until process $1 is in a network namespace other than this one.
wait_netns() {
  local pid=$1 own k
  own=$(readlink /proc/self/ns/net)
  for ((k = 0; k < 500; k++)); do
    kill -0 "$pid" 2>/dev/null || die "the holder of a party namespace exited"
    [[ $(readlink "/proc/$pid/ns/net" 2>/dev/null) == "$own" ]] || return 0
    sleep 0.01
  done
  die "the holder $pid did not enter a network namespace of its own"
}

# Builds the topology in the outer namespace: the bridge br0, and per party a network
# namespace, held by a process that exits with this script, whose eth0 is one end of a veth
# pair and whose other end, vp<i>, is a port of br0.
setup_netns() {
  local i c err
  for c in ip tc nsenter ping tail; do command -v "$c" >/dev/null || die "$c not found"; done
  if ((DRY_RUN)); then
    show ip link add br0 type bridge
  else
    err=$(ip link add br0 type bridge 2>&1) ||
      die "cannot create the bridge br0, does the kernel have the bridge module? ip says: $err"
  fi
  run ip link set br0 up
  for ((i = 0; i < NMAX; i++)); do
    if ((DRY_RUN)); then
      echo "$(show unshare -n tail -f /dev/null --pid=$$) &   # holds party $i's namespace, pid PID_$i"
      HOLDERS+=("PID_$i")
    else
      unshare -n tail -f /dev/null --pid=$$ &
      HOLDERS+=($!)
      wait_netns "${HOLDERS[i]}"
    fi
    run ip link add "vp$i" type veth peer name eth0 netns "${HOLDERS[i]}"
    run ip link set "vp$i" master br0
    run ip link set "vp$i" up
    in_ns "$i" ip link set lo up
    in_ns "$i" ip addr add "$(party_ip "$i")/24" dev eth0
    in_ns "$i" ip link set eth0 up
    # A large initial window, so that a fresh connection sends a batch's messages without
    # first spending round trips in slow start, as a warm one would.
    in_ns "$i" ip route replace 10.0.0.0/24 dev eth0 proto kernel scope link \
      src "$(party_ip "$i")" initcwnd 1000 initrwnd 1000
    # Keep the window a connection has grown across the idle between the warm-up and the
    # measured repetition, as a service whose connections never go cold would.
    in_ns "$i" sh -c 'echo 0 >/proc/sys/net/ipv4/tcp_slow_start_after_idle'
  done
  # A namespace's ping_group_range admits no group, so ping needs a raw socket, which
  # CAP_NET_RAW allows here; should ping fail all the same, admit group 0, the only one
  # unshare -r maps (a wider range is EINVAL).
  if ((!DRY_RUN)) && ! in_ns 0 ping -c 1 -W 1 -q 127.0.0.1 >/dev/null 2>&1; then
    in_ns 0 sh -c 'echo "0 0" >/proc/sys/net/ipv4/ping_group_range' 2>/dev/null || true
    echo "bench.sh: ping failed in party 0's namespace, set its net.ipv4.ping_group_range to 0 0" >&2
  fi
}

half() { awk -v r="$1" 'BEGIN { printf "%g", r / 2 }'; }

# A tc rate (e.g. 100mbit, 100Mbit, 1kibps) in bit/s.
rate_bps() {
  awk -v r="$1" 'BEGIN {
    r = tolower(r); m = 1
    if (sub(/bps$/, "", r)) m = 8; else sub(/bit$/, "", r)
    if (sub(/i$/, "", r)) b = 1024; else b = 1000
    if (sub(/k$/, "", r)) m *= b; else if (sub(/m$/, "", r)) m *= b ^ 2
    else if (sub(/g$/, "", r)) m *= b ^ 3; else if (sub(/t$/, "", r)) m *= b ^ 4
    printf "%.0f", r * m
  }'
}

# Sets netem on every party's eth0 for an RTT (ms) and a rate, or none for RTT 0 without a
# rate, and on its vp<i>, the bridge's end, which sends towards the party, for the rate
# alone: the delay is already on the sender's eth0, and the deep queue lets the bursts of
# several senders to one party queue, as at a switch port, rather than be dropped. The old
# netem goes first: a replace would keep the rate it is not given.
set_qdisc() {
  local rtt=$1 rate=$2 i
  ((BARE)) && return
  local args=(delay "$(half "$rtt")ms" limit 100000)
  [[ $rate != none ]] && args+=(rate "$rate")
  for ((i = 0; i < NMAX; i++)); do
    in_ns "$i" tc qdisc del dev eth0 root 2>/dev/null || true
    [[ $rtt == 0 && $rate == none ]] || in_ns "$i" tc qdisc add dev eth0 root netem "${args[@]}"
    run tc qdisc del dev "vp$i" root 2>/dev/null || true
    [[ $rate == none ]] || run tc qdisc add dev "vp$i" root netem limit 100000 rate "$rate"
  done
}

# The netem delay in ms from `tc qdisc show` output on stdin, empty if none.
tc_delay_ms() {
  awk '{
    for (i = 1; i < NF; i++) if ($i == "delay") {
      v = $(i + 1)
      if (v ~ /ms$/) { sub(/ms$/, "", v); print v + 0 }
      else if (v ~ /us$/) { sub(/us$/, "", v); print v / 1000 }
      else if (v ~ /ns$/) { sub(/ns$/, "", v); print v / 1e6 }
      else if (v ~ /s$/) { sub(/s$/, "", v); print v * 1000 }
      exit
    }
  }'
}

# The netem rate from `tc qdisc show` output on stdin, empty if none.
tc_rate() { awk '{ for (i = 1; i < NF; i++) if ($i == "rate") { print $(i + 1); exit } }'; }

# The average RTT in ms from ping output on stdin, empty if none.
ping_avg_ms() { sed -n 's|.*= *[0-9.]*/\([0-9.]*\)/.*|\1|p'; }

# Checks the rate in `tc qdisc show` output $2 for the device named $1 against the rate $3.
check_rate() {
  local dev=$1 shown=$2 rate=$3 reported
  reported=$(tc_rate <<<"$shown")
  if [[ $rate == none ]]; then
    [[ -z $reported ]] || die "tc reports rate $reported on $dev, asked none: $shown"
    return
  fi
  [[ -n $reported ]] || die "tc reports no rate on $dev: $shown"
  awk -v a="$(rate_bps "$rate")" -v r="$(rate_bps "$reported")" \
    'BEGIN { exit !(r >= 0.9 * a && r <= 1.1 * a) }' ||
    die "tc reports rate $reported on $dev, asked $rate: $shown"
}

# Checks the qdiscs of party i < n against the cell: delay and rate on its eth0, the rate
# alone on its vp<i>.
check_qdisc() {
  local i=$1 rtt=$2 rate=$3 oneway shown reported
  shown=$(tc qdisc show dev "vp$i")
  reported=$(tc_delay_ms <<<"$shown")
  [[ -z $reported ]] || die "tc reports delay ${reported}ms on party $i's vp$i, asked none: $shown"
  check_rate "party $i's vp$i" "$shown" "$rate"
  oneway=$(half "$rtt")
  shown=$(in_ns "$i" tc qdisc show dev eth0)
  if [[ $rtt == 0 && $rate == none ]]; then
    [[ $shown != *netem* ]] || die "netem still active on party $i's eth0: $shown"
    return
  fi
  reported=$(tc_delay_ms <<<"$shown")
  [[ -n $reported || $oneway == 0 ]] || die "tc reports no delay on party $i's eth0: $shown"
  awk -v a="$oneway" -v r="${reported:-0}" 'BEGIN { exit !(r >= 0.9 * a && r <= 1.1 * a) }' ||
    die "tc reports delay ${reported}ms on party $i's eth0, asked ${oneway}ms: $shown"
  check_rate "party $i's eth0" "$shown" "$rate"
}

# Checks the qdiscs and the ping RTT against the cell; sets MEASURED to the average ping RTT.
validate() {
  local n=$1 rtt=$2 rate=$3 lo hi i target ping=(ping)
  lo=$(half "$rtt")
  # The upper bound allows for a 98-byte ping frame's serialization on the four shaped
  # links it crosses there and back, two uplinks and two downlinks.
  hi=$(awk -v r="$rtt" -v b="$([[ $rate == none ]] || rate_bps "$rate")" \
    'BEGIN { printf "%g", 1.5 * r + 1 + (b ? 4 * 98 * 8 / b * 1000 : 0) }')
  if ((BARE)); then
    target=127.0.0.1
  else
    target=$(party_ip 1)
    ping=(nsenter -t "${HOLDERS[0]}" -n ping)
  fi
  if ((DRY_RUN)); then
    if ((BARE)); then
      echo "# check: no netem on lo; ping -c 3 $target average in [$lo, $hi] ms"
    else
      local want="no netem"
      [[ $rtt == 0 && $rate == none ]] || want="delay ${lo}ms +-10%"
      local down="no delay and no rate"
      [[ $rate == none ]] || want+=" and rate $rate +-10%" down="no delay and rate $rate +-10%"
      echo "# check: tc on eth0 of parties 0..$((n - 1)) reports $want," \
        "on vp0..vp$((n - 1)) $down; ping -c 3 from party 0 to $target average in [$lo, $hi] ms"
    fi
    MEASURED=NA
    return
  fi
  if ((!BARE)); then
    for ((i = 0; i < n; i++)); do check_qdisc "$i" "$rtt" "$rate"; done
  elif ! command -v tc >/dev/null; then
    warn "tc not found, cannot check that lo has no netem"
  elif [[ $(tc qdisc show dev lo) == *netem* ]]; then
    die "netem active on lo: $(tc qdisc show dev lo)"
  fi
  local out
  if ! command -v ping >/dev/null; then
    ((BARE)) || die "ping not found"
    warn "ping not found, RTT not checked"
    MEASURED=NA
    return
  fi
  # A first ping resolves the neighbour, which would otherwise add a round trip.
  "${ping[@]}" -c 1 -q "$target" >/dev/null 2>&1 || true
  if out=$("${ping[@]}" -c 3 -i 0.2 -q "$target" 2>&1); then
    MEASURED=$(ping_avg_ms <<<"$out")
    [[ -n $MEASURED ]] || die "cannot parse ping output: $out"
    awk -v m="$MEASURED" -v lo="$lo" -v hi="$hi" 'BEGIN { exit !(m >= lo && m <= hi) }' ||
      die "ping RTT ${MEASURED}ms outside [$lo, $hi] ms for an asked RTT of ${rtt}ms"
  elif ((BARE)); then
    warn "ping failed, RTT not checked: ${out%%$'\n'*}"
    MEASURED=NA
  else
    die "ping failed: $out"
  fi
}

# One run of the n parties of a protocol; their CSV lines end up in $WORK/out.<i>. Sets
# RUN_OK to 1 if every party exited 0, else to 0 after showing their stderr.
run_parties() {
  local n=$1 batch=$2 instances=$3 proto=$4 seed=$5 sid peers i
  RUN_OK=1
  sid=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
  peers=$(for ((i = 0; i < n; i++)); do
    if ((BARE)); then
      printf '127.0.0.1:%d,' $((BASE_PORT + i))
    else
      printf '%s:%d,' "$(party_ip "$i")" "$BASE_PORT"
    fi
  done)
  peers=${peers%,}
  for ((i = 0; i < n; i++)); do
    local cmd=()
    ((BARE)) || cmd=(nsenter -t "${HOLDERS[i]}" -n)
    [[ -n $CORES ]] && cmd+=(taskset -c "${CORE_LIST[i]}")
    cmd+=("$BIN" party --id "$i" --peers "$peers"
      --protocol "$proto" --parties "$n" --batch "$batch" --instances "$instances" --reps "$PARTY_REPS"
      --seed "$seed" --sid "$sid"
      --timeout "$TIMEOUT" "${EXTRA[@]}")
    if ((DRY_RUN)); then
      echo "$(show "${cmd[@]}") &"
    else
      "${cmd[@]}" >"$WORK/out.$i" 2>"$WORK/err.$i" &
      PIDS+=($!)
    fi
  done
  ((DRY_RUN)) && echo wait && return
  for i in "${!PIDS[@]}"; do wait "${PIDS[i]}" || RUN_OK=0; done
  PIDS=()
  if ((!RUN_OK)); then
    warn "$proto with $n parties, batch $batch, $instances instances, rep $seed aborted, left out:"
    for ((i = 0; i < n; i++)); do sed "s/^/party $i: /" "$WORK/err.$i" >&2; done
  fi
  return 0
}

# Appends the cell's summary to $OUT: per protocol, over the completed reps, the median,
# minimum and nearest-rank 90th percentile of the slowest party's time, the throughput in
# decryptions per second at the median, and their number.
summarize() {
  local n=$1 batch=$2 instances=$3 rtt=$4 rate=$5
  awk -F, -v OFS=, -v n="$n" -v batch="$batch" -v inst="$instances" -v rtt="$rtt" -v rate="$rate" \
    -v measured="$MEASURED" -v reps="$REPS" -v protos="$PROTOCOLS" '
    BEGIN { OFMT = "%.1f" }
    NR > 1 && $2 == n && $3 == batch && $4 == inst && $11 == rtt && $13 == rate {
      p = $1; k = p SUBSEP $5
      if (!(k in mx) || $7 + 0 > mx[k]) mx[k] = $7 + 0
      rows[k]++
      if ((p in bytes) && (bytes[p] != $9 || rounds[p] != $8)) {
        print "bench.sh: " p ": bytes_sent or rounds differ between parties or reps" > "/dev/stderr"
        failed = 1; exit 1
      }
      bytes[p] = $9; rounds[p] = $8
      if ($10 != "true") bad[p] = 1
    }
    END {
      if (failed) exit 1
      np = split(protos, ps, " ")
      for (i = 1; i <= np; i++) {
        p = ps[i]; c = 0
        for (r = 0; r < reps; r++) {
          k = p SUBSEP r
          if (!(k in rows)) continue
          if (rows[k] != n) {
            print "bench.sh: warning: " p " rep " r ": " rows[k] " of " n " parties reported, left out" > "/dev/stderr"
            continue
          }
          v[++c] = mx[k]
          for (j = c; j > 1 && v[j - 1] > v[j]; j--) { t = v[j]; v[j] = v[j - 1]; v[j - 1] = t }
        }
        if (!c) {
          print p, n, batch, inst, rtt, measured, rate, reps, "", "", "", "", 0, "", "", ""
          continue
        }
        med = c % 2 ? v[(c + 1) / 2] : (v[c / 2] + v[c / 2 + 1]) / 2
        p90 = v[int((9 * c + 9) / 10)]
        tp = med > 0 ? sprintf("%.0f", batch * inst * 1e6 / med) : ""
        print p, n, batch, inst, rtt, measured, rate, reps, med, v[1], p90, tp, c, rounds[p], bytes[p], (p in bad) ? "false" : "true"
      }
    }' "$RAW" >>"$OUT"
}

if ((!DRY_RUN)); then
  [[ -x $BIN ]] || die "no binary at $BIN"
  [[ ! -e $OUT && ! -e $RAW ]] || die "$OUT or $RAW exists already"
fi
((BARE)) || setup_netns
if ((!DRY_RUN)); then
  echo "protocol,n,batch,instances,rtt_ms_asked,rtt_ms_measured,rate,reps,online_us_median,online_us_min,online_us_p90,dec_per_s,reps_ok,rounds,bytes_sent,all_ok" >"$OUT"
  echo "protocol,n,batch,instances,rep,party,online_us,rounds,bytes_sent,plaintexts_ok,rtt_ms_asked,rtt_ms_measured,rate" >"$RAW"
  if ((EUID == 0)) && [[ -n ${SUDO_UID:-} ]]; then
    chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT" "$RAW" ||
      warn "cannot hand $OUT and $RAW to uid $SUDO_UID"
  fi
  WORK=$(mktemp -d "$(dirname "$OUT")/.bench-work.XXXXXX")
fi

for cell in "${CELLS[@]}"; do
  read -r rtt batch instances rate <<<"$cell"
  set_qdisc "$rtt" "$rate"
  for n in $PARTIES; do
    validate "$n" "$rtt" "$rate"
    echo "cell: n=$n batch=$batch instances=$instances rtt=${rtt}ms rate=$rate, ping: $MEASURED ms" >&2
    declare -A aborted=()
    for ((rep = 0; rep < REPS; rep++)); do
      for proto in $PROTOCOLS; do
        run_parties "$n" "$batch" "$instances" "$proto" "$rep"
        ((DRY_RUN)) && continue
        if ((!RUN_OK)); then
          aborted[$proto]=$((${aborted[$proto]:-0} + 1))
          continue
        fi
        for ((i = 0; i < n; i++)); do
          awk -F, -v OFS=, -v rep="$rep" -v rtt="$rtt" -v m="$MEASURED" -v rate="$rate" \
            -v keep="$WARMUP" 'NR > 1 && $5 == keep { $5 = rep; print $0, rtt, m, rate }' \
            "$WORK/out.$i" >>"$RAW"
        done
      done
    done
    ((DRY_RUN)) && continue
    for proto in "${!aborted[@]}"; do
      warn "$proto: ${aborted[$proto]} of $REPS repetitions aborted in this cell"
    done
    summarize "$n" "$batch" "$instances" "$rtt" "$rate"
    if tail -n "$(wc -w <<<"$PROTOCOLS")" "$OUT" | grep -q ',false$'; then
      warn "wrong plaintexts in this cell"
    fi
  done
done

((DRY_RUN)) || echo "bench.sh: wrote $OUT and $RAW" >&2

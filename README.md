# Modulus Operandi

Implementation for the paper *Modulus Operandi: Round-Optimal Modulus Conversion for MPC and
Threshold FHE* by Ivan Damgård, Sebastian Hasler, Sebastian Kolby and Stanislas Pawlak. It
benchmarks threshold decryption by modulus conversion (ModConv1, ModConv2) on SPDZ2k against the
decryption of Zyskind et al. (ZZLP25), with the preprocessing simulated by a seeded dealer inside
each party.

This is experimental research code, written mostly by AI (Claude). Do not use it on sensitive data:
it has not been audited, and since every party knows the dealer's seed, every party can reconstruct
every secret.

## Build and test

```sh
cargo build --release
cargo test
cargo clippy --all-targets --examples -- -D warnings
```

`cargo run --release --example compute` times a party's local computation per decryption.

## Benchmark

`scripts/bench.sh` measures the online phase over emulated networks, and its defaults reproduce the
two tables of the paper; the host setup this needs is under
[Reproducing the paper](#reproducing-the-paper). It builds in release and runs `party` processes,
one per party, for each party count of `--parties` (default 2, 4, 8 and 16) in two kinds of
configuration. A latency configuration is one instance of a batch of `--latency-batch` decryptions
(default 1) without a rate cap, at each RTT of `--rtts` (default 1, 10 and 100 ms). A throughput
configuration is `--instances` instances (default 256) of a batch of `--throughput-batch`
decryptions each (default 256), at each per-party rate of `--rates` (default 100 Mbit/s and
1 Gbit/s) and each RTT of `--throughput-rtts` (default 1 ms). Every option takes a list, and each
combination of party count and configuration is a *cell*. The default parties, RTTs and rates are
those of the evaluation of Zyskind et al. (CCS 2025), which we compare against, plus 2 parties.
`RTTS=0 THROUGHPUT_RTTS=0 RATES=none` gives a baseline without emulation.

The protocols alternate within each repetition, each run being a fresh set of processes with
`--reps 2`, whose first repetition, of the same configuration on the same dealt material, is an
untimed warm-up that the script leaves out. The measured repetition thus runs on connections whose
TCP windows have grown and on a heap already in use, as in a running service; cold, it is slower at
large batches, by about 10 % at 4 parties, 10 ms, 1 Gbit/s and 16 instances of 256, while batch 1 is
unaffected. `--no-warmup` (or `WARMUP=0`) runs `--reps 1` instead, for quick checks. Per cell and
protocol, it writes the median, minimum and nearest-rank 90th percentile over the repetitions of the
slowest party's `online_us` to `bench-<timestamp>.csv`, with the throughput `dec_per_s`,
batch · instances · 10⁶ divided by that median and rounded, and `reps_ok`, the number of repetitions
those are over; the per-party lines, without a throughput column, go next to it. A repetition in
which a party exits non-zero is left out with a warning rather than ending the run, and a cell with
none left gets empty statistics.

The parties sit in network namespaces of their own, one per party, each with a veth pair whose
other end is a port of a bridge, all inside a private network namespace that the script enters
after the build (`unshare -rn`, from util-linux, with unprivileged user namespaces enabled; as root,
e.g. under `sudo`, `unshare -n`). Party i has address `10.0.0.(i+1)`, and netem on its `eth0` delays
its outgoing packets by RTT/2 and caps them at the rate, so a message crosses one delayed link on
its way to the bridge, a round trip between two parties costs the RTT, and the `rate` column is
each party's own uplink. Each party's link is shaped in both directions at that rate with a deep
queue, netem on the bridge's end of the veth capping its downlink too, so that the bursts of
several senders to one party queue rather than drop; the delay is applied once, on the sender's
side. The veths have an MTU of 1500, unlike the 65536 of loopback. Connections also start with a
large initial window (`initcwnd` and `initrwnd` 1000 on each party's route), so that even the
warm-up does not spend its first round trips in slow start. Before each cell the script checks
every party's qdiscs, on both ends of its veth, with `tc`, and the RTT with `ping` from party 0 to
party 1. The host's network is never touched, and the namespaces vanish with the script; the output
files belong to the invoking user. Where namespaces are unavailable, or with `--no-netns`,
`ALLOW_BARE_LOOPBACK=1` runs all parties on `127.0.0.1` for RTT 0 and rate `none`, without netem.
The script states its mode on stderr.

Pinning is opt-in: `--cores 2,3,4,5` (or `CORES`, unset by default) runs party i under `taskset` on
the i-th core and refuses a cell with more parties than cores; unpinned, 16 parties may share
fewer cores. On a hybrid CPU, choose performance cores. The script states on stderr whether it pins.

```sh
scripts/bench.sh                    # the default grid
RTTS=0 THROUGHPUT_RTTS=0 RATES=none scripts/bench.sh  # baseline without emulation
scripts/bench.sh --parties "2 4" --rates "none 100mbit 1gbit" --reps 3
scripts/bench.sh --throughput-batch "64 256" --instances "16 64" --rates "100mbit"
scripts/bench.sh --dry-run          # print the commands
# bare loopback only:
ALLOW_BARE_LOOPBACK=1 RTTS=0 THROUGHPUT_RTTS=0 RATES=none scripts/bench.sh --no-netns
```

`--help` lists the options.

A sweep over the instance counts shows per protocol and cell the count that saturates the link,
as the one with the highest `dec_per_s`:

```sh
scripts/bench.sh --latency-batch "" --instances "1 2 4 8 16 32 64 128 256"
```

A party deals the material of one instance once per process and gives every instance a deep copy of
its own, which all repetitions reuse: the values do not affect the timed phase, and the copies keep
the memory footprint and the accesses those of distinct material. Every decryption within an
instance still has material of its own. Memory thus grows with the decryptions in flight: ZZLP25
holds about 85 KB per decryption in flight, ciphertext included, so 256 instances of 256 is about
5.6 GB per party. The dealer's time, about 170 µs per decryption for ZZLP25, is spent on one
instance only; it is not timed, but it and the copying have to fit within `--timeout`, which
`scripts/bench.sh` sets to 600 s (`TIMEOUT`).

### Reproducing the paper

The paper's numbers were measured on an Intel Xeon Silver 4314 (16 cores), by the defaults, as
root and with party i pinned to core i:

```sh
sudo modprobe bridge
sudo sysctl -w net.core.netdev_max_backlog=100000
export RUSTFLAGS=-Ctarget-cpu=native
sudo -E env PATH="$PATH" scripts/bench.sh --cores "$(seq -s, 0 15)"
```

The 16-party throughput cell of ZZLP25 needs about 90 GB of memory.

The paper's latency table is `online_us_median` of the summary CSV's rows with batch 1, and its
throughput table is `dec_per_s` of the rows with batch 256. Both tables of the paper show
`modconv1` and `zzlp25`.

## Running the binary directly

All parties as threads in one process:

```sh
target/release/modulus-operandi local --protocol modconv1 --reps 2
```

Prints one CSV line per party per repetition:
`protocol,n,batch,instances,rep,party,online_us,rounds,bytes_sent,plaintexts_ok`. `rounds` and
`bytes_sent` count the timed decryption only; bytes are payload bytes. `--protocol` is `modconv1`,
`modconv2` or `zzlp25` (digit bits `-b`, default 8). `--instances N` (default 1) runs N instances at
once and in lockstep, each on a batch of `--batch` decryptions (default 1); `online_us` runs until
the last instance's plaintexts, and a failed check in any instance aborts the party.
`--parties` is the number of parties (default 4). The defaults are the paper's latency configuration
at 4 parties, and `--batch 256 --instances 256` gives its throughput configuration. `--help` lists
the parameters and defaults.

Timing starts at a common instant agreed in two untimed rounds, which assumes one clock: one host,
or hosts with synchronized clocks.

Over TCP, one process per party, each with the same flags but `--id` (here four on loopback):

```sh
SID=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
PEERS=127.0.0.1:47000,127.0.0.1:47001,127.0.0.1:47002,127.0.0.1:47003
for i in 0 1 2 3; do
  target/release/modulus-operandi party --id $i --peers $PEERS --sid $SID \
    --protocol zzlp25 --reps 2 > party$i.csv &
done
wait
```

Each process prints its own CSV lines. Parties whose parameters or `--seed` differ abort at the
handshake. `--timeout` (seconds) bounds the connection setup, each round and each write.

## Status

Implemented: ModConv1, ModConv2 and ZZLP25 (`Mod` via `LTRand`, with dealt Sign and ModLTZ tables)
in `protocol:convopen` with commitments, MAC checks and the one-time MAC check on `w`, each instance
a state machine with one step per round, several instances streamed at once; `tests/attacks.rs`
covers a corrupted party; the TCP transport, the `party` subcommand and the benchmark script;
`examples/compute.rs`, the local computation per decryption.

Not implemented: the preprocessing phase of any protocol. Every party simulates an ideal dealer
from the common `--seed` before the timed phase, so only the online phase is measured.

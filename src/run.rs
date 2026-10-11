//! Running the benchmark: one party's repetitions, and all parties as threads over `net::mem`.
//! `main` runs a single party over `net::tcp` through `run_party`.
//!
//! The timing assumes that all parties read one wall clock: one host, or hosts with synchronized
//! clocks (see `common_start`).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::abb::{Ctx, Round, Tamper};
use crate::dec::Decryption;
use crate::dec::convopen::convopen_streamed;
use crate::dec::lwe::LweParams;
use crate::net::{Abort, Transport, mem};
use crate::prep::{Dealer, deal_instances};

#[derive(Clone, Debug)]
pub struct Config {
    pub n: usize,
    /// Decryptions per instance.
    pub batch: usize,
    /// Instances in flight at once, in lockstep, each on a copy of the same dealt batch.
    pub instances: usize,
    pub reps: u64,
    /// Seed of the simulated dealer.
    pub seed: u64,
    pub sid: [u8; 16],
    pub kappa: u32,
    pub lwe: LweParams,
    /// How long a party waits for a peer's message.
    pub timeout: Duration,
}

/// SHA-256 over the protocol and every parameter the parties must agree on, the dealer seed
/// included; the TCP handshake compares it. `beta` is ModConv1/2's, `b` ZZLP25's.
pub fn params_hash(cfg: &Config, protocol: &str, beta: Option<u128>, b: Option<u32>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"modulus-operandi params v2");
    h.update((protocol.len() as u64).to_le_bytes());
    h.update(protocol.as_bytes());
    let lwe = &cfg.lwe;
    for x in [
        cfg.n as u64,
        cfg.batch as u64,
        cfg.instances as u64,
        cfg.reps,
        lwe.k as u64,
        lwe.m as u64,
        cfg.kappa as u64,
        lwe.dim as u64,
        lwe.noise_bits as u64,
        cfg.seed,
    ] {
        h.update(x.to_le_bytes());
    }
    match beta {
        None => h.update([0]),
        Some(beta) => {
            h.update([1]);
            h.update(beta.to_le_bytes());
        }
    }
    match b {
        None => h.update([0]),
        Some(b) => {
            h.update([1]);
            h.update(b.to_le_bytes());
        }
    }
    h.finalize().into()
}

/// One party's measurement of one repetition.
#[derive(Clone, Debug)]
pub struct RepResult {
    pub party: usize,
    pub rep: u64,
    /// From the common start instant `start_ns` to this party's last instance's plaintexts, by the
    /// wall clock.
    pub online_us: u128,
    /// The common start instant, in ns since the Unix epoch; the same at every party.
    pub start_ns: u64,
    /// The protocol's rounds, however many instances ran in them.
    pub rounds: u32,
    /// Timed payload bytes only, over all instances.
    pub bytes_sent: u64,
    pub plaintexts_ok: bool,
    /// All instances' plaintexts, instance after instance.
    pub plaintexts: Vec<u64>,
    /// The dealer's plaintexts, in the same order.
    pub expected: Vec<u64>,
}

/// A party's results, or its abort.
pub type Outcome = Result<Vec<RepResult>, Abort>;

/// One instance's plaintexts as the party output them, before the repetition ended.
#[derive(Clone, Debug)]
pub struct Released {
    pub rep: u64,
    pub instance: usize,
    pub plaintexts: Vec<u64>,
    /// The dealer's plaintexts.
    pub expected: Vec<u64>,
}

/// Test-only deviations from the protocol, for `run_local_with`.
#[derive(Default)]
pub struct Faults {
    /// `tampers[i]`, if given, is installed at party `i`.
    pub tampers: Vec<Option<Tamper>>,
    /// A party that receives each round's frames before sending its own.
    pub rushing: Option<usize>,
    /// Skips the one-time MAC check on `w` at every party.
    pub skip_gamma_check: bool,
    /// `(i, t)`: party `i` sleeps for `t` before its first repetition, a start skew.
    pub delay: Option<(usize, Duration)>,
}

/// Untimed exchanges before the timed rounds of each repetition (see `common_start`).
pub const BARRIER_ROUNDS: u32 = 2;

/// Least slack for scheduling between the second barrier exchange and the start instant; under
/// the parallel test suite, 1 ms is too little.
const MIN_MARGIN: Duration = Duration::from_millis(10);

/// Spin rather than sleep for the last stretch before the start instant.
const SPIN: Duration = Duration::from_micros(200);

/// The wall clock, in ns since the Unix epoch.
fn now_ns() -> Result<u64, Abort> {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Abort::new(format!("wall clock before the Unix epoch: {e}")))?;
    u64::try_from(t.as_nanos()).map_err(|_| Abort::new("wall clock beyond 2^64 ns"))
}

/// One untimed exchange in which each party sends `v`; every party's value, own included.
fn share(ctx: &mut Ctx, v: u64) -> Result<Vec<u64>, Abort> {
    let mut round = Round::new();
    let s = round.push_ring(64, vec![v.into()]);
    ctx.exchange(&mut round)?;
    let id = ctx.id();
    Ok((0..ctx.n())
        .map(|j| {
            if j == id {
                v
            } else {
                round.ring(j, s)[0] as u64
            }
        })
        .collect())
}

/// Agrees on a start instant `S` from shared data only, so that every party computes the same, and
/// waits for it; returns `S` (ns since the Unix epoch). Two exchanges: each party sends its wall
/// clock `t_i`, then the time `c_i` at which it completed the first. With `t = max t_i`,
/// `C = max c_i` and `D = max (c_i - t)`, at least the one-way delay,
/// `S = C + 2D + max(MIN_MARGIN, D/10)`. The parties must share a wall clock; aborts if `S` has
/// passed when a party is ready, which would count start skew as online time.
fn common_start(ctx: &mut Ctx, timeout: Duration) -> Result<u64, Abort> {
    let t = share(ctx, now_ns()?)?;
    let t_max = t.into_iter().max().expect("n >= 1");
    let c = share(ctx, now_ns()?)?;
    let c_max = *c.iter().max().expect("n >= 1");
    let d = c
        .iter()
        .map(|&ci| ci.saturating_sub(t_max))
        .max()
        .expect("n >= 1");
    let margin = (d / 10).max(MIN_MARGIN.as_nanos() as u64);
    let start = c_max
        .saturating_add(d.saturating_mul(2))
        .saturating_add(margin);
    let ready = now_ns()?;
    if ready > start {
        return Err(Abort::new(format!(
            "ready {} µs after the common start instant (D = {} µs, margin {} µs): the start \
             skew would count as online time",
            (ready - start) / 1000,
            d / 1000,
            margin / 1000
        )));
    }
    if start - ready > timeout.as_nanos() as u64 {
        return Err(Abort::new(format!(
            "common start instant {} ms ahead, beyond the timeout",
            (start - ready) / 1_000_000
        )));
    }
    let spin = SPIN.as_nanos() as u64;
    loop {
        let now = now_ns()?;
        if now >= start {
            return Ok(start);
        }
        if start - now > spin {
            std::thread::sleep(Duration::from_nanos(start - now - spin));
        } else {
            std::hint::spin_loop();
        }
    }
}

/// Deals one instance's batch once and copies it for every instance (untimed, `deal_instances`);
/// then per repetition, on those copies: agree on a common start instant and wait for it (untimed,
/// `BARRIER_ROUNDS` exchanges, see `common_start`), then the timed decryption of all instances at
/// once from that instant. `tamper` and `skip_gamma_check` are for tests only.
pub fn run_party<D: Decryption>(
    transport: Box<dyn Transport + Send>,
    dec: &D,
    cfg: &Config,
    tamper: Option<Tamper>,
    skip_gamma_check: bool,
) -> Result<Vec<RepResult>, Abort> {
    run_party_released(
        transport,
        dec,
        cfg,
        tamper,
        skip_gamma_check,
        &mut Vec::new(),
    )
}

/// `run_party`, which also appends each instance's plaintexts to `released` as the party outputs
/// them, where they stay should a later instance abort.
pub fn run_party_released<D: Decryption>(
    transport: Box<dyn Transport + Send>,
    dec: &D,
    cfg: &Config,
    tamper: Option<Tamper>,
    skip_gamma_check: bool,
    released: &mut Vec<Released>,
) -> Result<Vec<RepResult>, Abort> {
    assert!(cfg.instances >= 1);
    let id = transport.id();
    let mut dealer = Dealer::new(cfg.seed, cfg.n, id, cfg.kappa);
    let mut ctx = Ctx::new(transport, cfg.kappa, dealer.key_share(), cfg.sid);
    if let Some(f) = tamper {
        ctx.set_tamper(f);
    }
    if skip_gamma_check {
        ctx.skip_gamma_check();
    }
    let mats = deal_instances(&mut dealer, dec, &cfg.lwe, cfg.instances, cfg.batch);
    let expected: Vec<u64> = mats.iter().flat_map(|m| m.expected.clone()).collect();
    let mut out = Vec::new();
    for rep in 0..cfg.reps {
        let start_ns = common_start(&mut ctx, cfg.timeout)?;
        let (r0, b0) = (ctx.round(), ctx.bytes_sent());
        let mut ctxs: Vec<Ctx> = (0..cfg.instances).map(|j| ctx.fork(j as u32)).collect();
        let first = released.len();
        convopen_streamed(&mut ctxs, dec, &mats, |j, plaintexts| {
            released.push(Released {
                rep,
                instance: j,
                plaintexts,
                expected: mats[j].expected.clone(),
            })
        })?;
        let online_ns = now_ns()?
            .checked_sub(start_ns)
            .ok_or_else(|| Abort::new("wall clock went back during the timed decryption"))?;
        let end = ctxs[0].round();
        assert!(ctxs.iter().all(|c| c.round() == end));
        ctx.skip_to(end);
        let mut done = released[first..].to_vec();
        done.sort_by_key(|r| r.instance);
        assert_eq!(done.len(), cfg.instances);
        let plaintexts: Vec<u64> = done.into_iter().flat_map(|r| r.plaintexts).collect();
        out.push(RepResult {
            party: id,
            rep,
            online_us: (online_ns / 1000).into(),
            start_ns,
            rounds: end - r0,
            bytes_sent: ctx.bytes_sent() - b0,
            plaintexts_ok: plaintexts == expected,
            plaintexts,
            expected: expected.clone(),
        });
    }
    Ok(out)
}

/// Runs all parties as threads, with the test-only `faults`. Returns each party's outcome, in id
/// order.
pub fn run_local_with<D: Decryption + Sync>(dec: &D, cfg: &Config, faults: Faults) -> Vec<Outcome> {
    run_local_released(dec, cfg, faults)
        .into_iter()
        .map(|(res, _)| res)
        .collect()
}

/// `run_local_with`, with each party's released plaintexts (see `run_party_released`).
pub fn run_local_released<D: Decryption + Sync>(
    dec: &D,
    cfg: &Config,
    faults: Faults,
) -> Vec<(Outcome, Vec<Released>)> {
    let mut tampers = faults.tampers;
    tampers.resize_with(cfg.n, || None);
    let mut transports = mem::network(cfg.n, cfg.timeout);
    if let Some(i) = faults.rushing {
        transports[i].set_rushing();
    }
    let skip = faults.skip_gamma_check;
    let delay = faults.delay;
    std::thread::scope(|scope| {
        let handles: Vec<_> = transports
            .into_iter()
            .zip(tampers)
            .enumerate()
            .map(|(i, (t, tamper))| {
                scope.spawn(move || {
                    if let Some((_, d)) = delay.filter(|&(j, _)| j == i) {
                        std::thread::sleep(d);
                    }
                    let mut released = Vec::new();
                    let res =
                        run_party_released(Box::new(t), dec, cfg, tamper, skip, &mut released);
                    (res, released)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("party thread panicked"))
            .collect()
    })
}

/// Runs all parties as threads; on success, the results ordered by repetition, then party.
pub fn run_local<D: Decryption + Sync>(
    dec: &D,
    cfg: &Config,
) -> Result<Vec<RepResult>, (usize, Abort)> {
    let mut all = Vec::new();
    for (id, res) in run_local_with(dec, cfg, Faults::default())
        .into_iter()
        .enumerate()
    {
        all.extend(res.map_err(|e| (id, e))?);
    }
    all.sort_by_key(|r| (r.rep, r.party));
    Ok(all)
}

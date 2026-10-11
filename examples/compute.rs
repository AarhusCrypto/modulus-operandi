//! Local computation per decryption, next to the online time over the in-process transport.
//!
//! `phase` times `⟨c, ⟦s⟧⟩` alone. `compute` is a party's `convopen` time minus its time inside the
//! transport's `send`/`recv`, the maximum over parties; `online` is the slowest party's total,
//! as in the CSV; `dealer` is a party's (untimed) dealing of one instance, which the benchmark does
//! once per process (`prep::deal_instances`). Medians over the repetitions, after one warm-up
//! repetition.
//!
//! `cargo run --release --example compute [-- --parties 4 --reps 11 --batches 1,10,100,1000]`

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use modulus_operandi::abb::{Ctx, Round};
use modulus_operandi::conv::modconv12::Variant;
use modulus_operandi::dec::Decryption;
use modulus_operandi::dec::convopen::convopen;
use modulus_operandi::dec::lwe::{self, LweParams};
use modulus_operandi::dec::modconv::ModConvDecryption;
use modulus_operandi::dec::zzlp25::Zzlp25;
use modulus_operandi::net::mem::{self, MemTransport};
use modulus_operandi::net::{Abort, Payload, Transport};
use modulus_operandi::prep::{Dealer, deal};

#[derive(Parser)]
struct Cli {
    /// Number of parties.
    #[arg(long, default_value_t = 4)]
    parties: usize,
    /// Measured repetitions per protocol and batch, after one warm-up.
    #[arg(long, default_value_t = 11)]
    reps: u64,
    #[arg(long, value_delimiter = ',', default_value = "1,10,100,1000")]
    batches: Vec<usize>,
}

const KAPPA: u32 = 64;
const SEED: u64 = 0;

/// Forwards to the in-process transport and adds the time spent in it to `spent` (ns).
struct Timed {
    inner: MemTransport,
    spent: Arc<AtomicU64>,
}

impl Timed {
    fn time<T>(&self, start: Instant, r: T) -> T {
        let ns = start.elapsed().as_nanos() as u64;
        self.spent.fetch_add(ns, Ordering::Relaxed);
        r
    }
}

impl Transport for Timed {
    fn id(&self) -> usize {
        self.inner.id()
    }

    fn n(&self) -> usize {
        self.inner.n()
    }

    fn send(&mut self, round: u32, instance: u32, out: &[Payload]) -> Result<(), Abort> {
        let start = Instant::now();
        let r = self.inner.send(round, instance, out);
        self.time(start, r)
    }

    fn recv(&mut self, round: u32, instance: u32) -> Result<Vec<Payload>, Abort> {
        let start = Instant::now();
        let r = self.inner.recv(round, instance);
        self.time(start, r)
    }
}

/// One party's repetition, in ns: online total, time in the transport, dealing.
#[derive(Clone, Copy)]
struct Sample {
    online: u64,
    transport: u64,
    dealer: u64,
}

fn party<D: Decryption>(
    t: Timed,
    dec: &D,
    lwe: &LweParams,
    batch: usize,
    reps: u64,
) -> Vec<Sample> {
    let (id, n) = (t.id(), t.n());
    let spent = t.spent.clone();
    let mut dealer = Dealer::new(SEED, n, id, KAPPA);
    let mut ctx = Ctx::new(Box::new(t), KAPPA, dealer.key_share(), [0; 16]);
    let mut out = Vec::new();
    for rep in 0..=reps {
        let start = Instant::now();
        let mat = deal(&mut dealer, dec, lwe, batch);
        let dealt = start.elapsed().as_nanos() as u64;
        ctx.exchange(&mut Round::new()).expect("barrier");
        let s0 = spent.load(Ordering::Relaxed);
        let start = Instant::now();
        let pt = convopen(&mut ctx, dec, &mat.ct, &mat.dec, &mat.open).expect("convopen");
        let online = start.elapsed().as_nanos() as u64;
        assert_eq!(pt, mat.expected, "wrong plaintexts");
        if rep > 0 {
            out.push(Sample {
                online,
                transport: spent.load(Ordering::Relaxed) - s0,
                dealer: dealt,
            });
        }
    }
    out
}

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[v.len() / 2]
}

/// Medians over the repetitions of the per-repetition maxima over parties, in ns per batch:
/// (compute, online, dealer).
fn measure<D: Decryption + Sync>(
    dec: &D,
    lwe: &LweParams,
    n: usize,
    batch: usize,
    reps: u64,
) -> (u64, u64, u64) {
    let nets = mem::network(n, Duration::from_secs(600));
    let per_party: Vec<Vec<Sample>> = std::thread::scope(|scope| {
        let handles: Vec<_> = nets
            .into_iter()
            .map(|inner| {
                let t = Timed {
                    inner,
                    spent: Arc::new(AtomicU64::new(0)),
                };
                scope.spawn(move || party(t, dec, lwe, batch, reps))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let max_over = |f: &dyn Fn(&Sample) -> u64| -> u64 {
        let per_rep = (0..reps as usize)
            .map(|r| per_party.iter().map(|p| f(&p[r])).max().unwrap())
            .collect();
        median(per_rep)
    };
    (
        max_over(&|s| s.online - s.transport),
        max_over(&|s| s.online),
        max_over(&|s| s.dealer),
    )
}

/// ns per decryption of `⟨c, ⟦s⟧⟩` (with the public `b` added), median over repetitions.
fn phase_ns(lwe: &LweParams, n: usize, batch: usize, reps: u64) -> f64 {
    let mut dealer = Dealer::new(SEED, n, 0, KAPPA);
    dealer.begin_batch();
    let sk = lwe::keygen(lwe, dealer.rng());
    let ct: Vec<_> = (0..batch)
        .map(|_| lwe::encrypt(lwe, &sk, 0, dealer.rng()))
        .collect();
    let s: Vec<u128> = sk.iter().map(|&x| x as u128).collect();
    let key = dealer.share(lwe.k, &s);
    let iters = 1000usize.div_ceil(batch);
    let run = || {
        let start = Instant::now();
        for _ in 0..iters {
            black_box(lwe::phase(black_box(&ct), &key, 0, dealer.key_share()));
        }
        start.elapsed().as_nanos() as u64
    };
    run();
    let t = median((0..reps.max(1)).map(|_| run()).collect());
    t as f64 / (iters * batch) as f64
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    if cli.parties < 2 || cli.reps == 0 {
        return Err("need n >= 2 and reps >= 1".into());
    }
    // ν = l - 2.
    let (k, m) = (64, 1);
    let lwe = LweParams::new(k, m, 1024, k - m - 2)?;
    let mc1 = ModConvDecryption::modconv12(lwe, Variant::ModConv1, None, cli.parties)?;
    let mc2 = ModConvDecryption::modconv12(lwe, Variant::ModConv2, None, cli.parties)?;
    let zz = Zzlp25::new(lwe, 8)?;
    println!(
        "n = {}, k = {}, m = {}, kappa = {KAPPA}, lwe-dim = {}, nu = {}, b = {}; medians of {} reps",
        cli.parties, lwe.k, lwe.m, lwe.dim, lwe.noise_bits, zz.b, cli.reps
    );
    println!(
        "{:<9} {:>6} {:>13} {:>15} {:>11} {:>11} {:>9} {:>14}",
        "protocol",
        "batch",
        "phase ns/dec",
        "compute ns/dec",
        "compute us",
        "online us",
        "compute%",
        "dealer ns/dec"
    );
    for &batch in &cli.batches {
        let phase = phase_ns(&lwe, cli.parties, batch, cli.reps);
        let rows = [
            ("modconv1", measure(&mc1, &lwe, cli.parties, batch, cli.reps)),
            ("modconv2", measure(&mc2, &lwe, cli.parties, batch, cli.reps)),
            ("zzlp25", measure(&zz, &lwe, cli.parties, batch, cli.reps)),
        ];
        for (name, (compute, online, dealer)) in rows {
            let b = batch as f64;
            println!(
                "{:<9} {:>6} {:>13.0} {:>15.0} {:>11.1} {:>11.1} {:>8.1}% {:>14.0}",
                name,
                batch,
                phase,
                compute as f64 / b,
                compute as f64 / 1e3,
                online as f64 / 1e3,
                100.0 * compute as f64 / online as f64,
                dealer as f64 / b
            );
        }
    }
    Ok(())
}

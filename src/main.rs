use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use modulus_operandi::conv::modconv12::Variant;
use modulus_operandi::dec::Decryption;
use modulus_operandi::dec::lwe::LweParams;
use modulus_operandi::dec::modconv::ModConvDecryption;
use modulus_operandi::dec::zzlp25::Zzlp25;
use modulus_operandi::net::tcp::TcpTransport;
use modulus_operandi::run::{Config, params_hash, run_local, run_party};
use rand::Rng;

#[derive(Parser)]
#[command(
    version,
    about = "Benchmark of threshold decryption by modulus conversion on SPDZ2k"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run all parties as threads in this process.
    Local(Common),
    /// Run one party over TCP; every party gets the same flags but --id.
    Party {
        /// This party's index into --peers.
        #[arg(long)]
        id: usize,
        /// Every party's address, host:port, in id order (comma-separated).
        #[arg(long, value_delimiter = ',', required = true)]
        peers: Vec<String>,
        #[command(flatten)]
        common: Common,
    },
}

enum Mode {
    Local,
    Party { id: usize, peers: Vec<String> },
}

#[derive(Clone, Copy, ValueEnum)]
enum Protocol {
    Modconv1,
    Modconv2,
    Zzlp25,
}

#[derive(Args)]
struct Common {
    #[arg(long, value_enum)]
    protocol: Protocol,
    /// Number of parties.
    #[arg(long, default_value_t = 4)]
    parties: usize,
    /// Decryptions per batch, i.e. per instance.
    #[arg(long, default_value_t = 1)]
    batch: usize,
    /// Instances started together and run in lockstep, each on a copy of the same dealt batch.
    #[arg(long, default_value_t = 1)]
    instances: usize,
    #[arg(long, default_value_t = 1)]
    reps: u64,
    /// Seed of the simulated dealer.
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// Session id, 32 hex digits (random if absent; required by party).
    #[arg(long)]
    sid: Option<String>,
    /// Ciphertext modulus 2^k.
    #[arg(short = 'k', default_value_t = 64)]
    k: u32,
    /// Plaintext modulus 2^m.
    #[arg(short = 'm', default_value_t = 1)]
    m: u32,
    #[arg(long, default_value_t = 64)]
    kappa: u32,
    #[arg(long, default_value_t = 1024)]
    lwe_dim: usize,
    /// Noise bound ν, |e| < 2^ν [default: l - 2].
    #[arg(long)]
    noise_bits: Option<u32>,
    /// ModConv1/2: number of intervals [default: smallest 2-power meeting the precondition].
    #[arg(long)]
    beta: Option<u128>,
    /// ZZLP25: digit bits.
    #[arg(short = 'b', default_value_t = 8)]
    b: u32,
    /// Seconds allowed for a peer's message or a write, and for the TCP connection setup.
    #[arg(long, default_value_t = 60)]
    timeout: u64,
}

fn parse_sid(s: &str) -> Result<[u8; 16], String> {
    if s.len() != 32 || !s.is_ascii() {
        return Err(format!("--sid must be 32 hex digits, got {s:?}"));
    }
    let mut sid = [0u8; 16];
    for (i, byte) in sid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| format!("--sid: {e}"))?;
    }
    Ok(sid)
}

fn run(c: Common, mode: Mode) -> Result<(), String> {
    if c.parties < 2 {
        return Err("need at least 2 parties".into());
    }
    if c.batch == 0 || c.instances == 0 || c.instances > u32::MAX as usize {
        return Err("need --batch >= 1 and 1 <= --instances < 2^32".into());
    }
    if c.k + c.kappa > 128 {
        return Err(format!("need k + κ <= 128, got {} + {}", c.k, c.kappa));
    }
    if c.kappa < 1 {
        return Err("need κ >= 1".into());
    }
    let l = c.k.checked_sub(c.m).ok_or("need m < k")?;
    let noise_bits = match c.noise_bits {
        Some(nu) => nu,
        None => l.checked_sub(2).ok_or("default ν = l - 2 needs l >= 2")?,
    };
    let lwe = LweParams::new(c.k, c.m, c.lwe_dim, noise_bits)?;
    if let Mode::Party { id, peers } = &mode {
        if peers.len() != c.parties {
            return Err(format!("--parties is {} but --peers has {}", c.parties, peers.len()));
        }
        if *id >= c.parties {
            return Err(format!("--id must be below {}, got {id}", c.parties));
        }
    }
    let sid = match (&c.sid, &mode) {
        (Some(s), _) => parse_sid(s)?,
        (None, Mode::Local) => {
            let mut sid = [0u8; 16];
            rand::rng().fill_bytes(&mut sid);
            sid
        }
        (None, Mode::Party { .. }) => {
            return Err("party needs --sid, the same at every party".into());
        }
    };
    let cfg = Config {
        n: c.parties,
        batch: c.batch,
        instances: c.instances,
        reps: c.reps,
        seed: c.seed,
        sid,
        kappa: c.kappa,
        lwe,
        timeout: Duration::from_secs(c.timeout),
    };
    match c.protocol {
        Protocol::Modconv1 => {
            let dec = ModConvDecryption::modconv12(lwe, Variant::ModConv1, c.beta, c.parties)?;
            let params = params_hash(&cfg, "modconv1", Some(dec.conv.beta), None);
            report("modconv1", &dec, &cfg, &mode, params)
        }
        Protocol::Modconv2 => {
            let dec = ModConvDecryption::modconv12(lwe, Variant::ModConv2, c.beta, c.parties)?;
            let params = params_hash(&cfg, "modconv2", Some(dec.conv.beta), None);
            report("modconv2", &dec, &cfg, &mode, params)
        }
        Protocol::Zzlp25 => {
            if c.beta.is_some() {
                return Err("--beta does not apply to zzlp25".into());
            }
            let dec = Zzlp25::new(lwe, c.b)?;
            let params = params_hash(&cfg, "zzlp25", None, Some(dec.b));
            report("zzlp25", &dec, &cfg, &mode, params)
        }
    }
}

/// Runs all parties (`local`) or this one (`party`) and prints the CSV; `params` is the
/// handshake's parameter hash.
fn report<D: Decryption + Sync>(
    name: &str,
    dec: &D,
    cfg: &Config,
    mode: &Mode,
    params: [u8; 32],
) -> Result<(), String> {
    let results = match mode {
        Mode::Local => run_local(dec, cfg).map_err(|(id, e)| format!("party {id}: {e}"))?,
        Mode::Party { id, peers } => {
            let fail = |e| format!("party {id}: {e}");
            let t =
                TcpTransport::connect(*id, peers, cfg.sid, params, cfg.timeout).map_err(fail)?;
            let wire = t.bytes_sent();
            let res = run_party(Box::new(t), dec, cfg, None, false).map_err(fail)?;
            eprintln!(
                "party {id}: {} bytes sent in frames, headers included",
                wire.load(Ordering::Relaxed)
            );
            res
        }
    };
    println!("protocol,n,batch,instances,rep,party,online_us,rounds,bytes_sent,plaintexts_ok");
    for r in results {
        println!(
            "{name},{},{},{},{},{},{},{},{},{}",
            cfg.n,
            cfg.batch,
            cfg.instances,
            r.rep,
            r.party,
            r.online_us,
            r.rounds,
            r.bytes_sent,
            r.plaintexts_ok
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    let res = match Cli::parse().cmd {
        Cmd::Local(c) => run(c, Mode::Local),
        Cmd::Party { id, peers, common } => run(common, Mode::Party { id, peers }),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

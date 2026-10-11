//! Shared by the end-to-end and attack tests.
#![allow(dead_code)]

use std::time::Duration;

use modulus_operandi::dec::lwe::LweParams;
use modulus_operandi::run::Config;

pub fn config(n: usize, batch: usize, reps: u64) -> Config {
    Config {
        n,
        batch,
        instances: 1,
        reps,
        seed: 7,
        sid: [3; 16],
        kappa: 64,
        lwe: LweParams::new(64, 1, 256, 61).unwrap(),
        timeout: Duration::from_secs(30),
    }
}

/// Bytes a party sends in one decryption of a batch whose Π opens values mod `2^{k'}` for each
/// `k'` in `openings` (`realization.tex`, Communication): per decryption and peer, the share and
/// check share of each of Π's openings (`k' + κ` bits each) and of `v + w`, and the shares of `ŵ`
/// and `γŵ` (`k + κ` bits each); per batch and peer, `⟨γ⟩` and, for each of the two commit rounds,
/// a commitment and its `ρ`. Each instance is a batch of its own.
pub fn bytes_for(cfg: &Config, openings: &[u32]) -> u64 {
    let t = (cfg.lwe.k + cfg.kappa).div_ceil(8) as usize;
    let mut per_dec = 4 * t;
    for &k in openings {
        per_dec += 2 * (k + cfg.kappa).div_ceil(8) as usize;
    }
    let per_peer = cfg.batch * per_dec + t + 2 * (32 + 32);
    (per_peer * (cfg.n - 1) * cfg.instances) as u64
}

/// ModConv1/2: Π opens `y` mod `2^l`.
pub fn expected_bytes(cfg: &Config) -> u64 {
    bytes_for(cfg, &[cfg.lwe.l()])
}

/// ZZLP25 with `d` digits: Π opens `z'` mod `2^l` and `y + r'` mod `2^{d+1}`.
pub fn expected_bytes_zzlp25(cfg: &Config, d: u32) -> u64 {
    bytes_for(cfg, &[cfg.lwe.l(), d + 1])
}

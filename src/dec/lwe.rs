//! LWE with ciphertext modulus `2^k` and plaintext modulus `2^m`, the plaintext in the top `m` bits.

use crate::abb::Shared;
use crate::prg::Stream;
use crate::ring::Ring;

#[derive(Clone, Copy, Debug)]
pub struct LweParams {
    /// Ciphertext modulus `2^k`, `k <= 64`.
    pub k: u32,
    /// Plaintext modulus `2^m`.
    pub m: u32,
    pub dim: usize,
    /// `ν`: every noise term satisfies `|e| < 2^ν`.
    pub noise_bits: u32,
}

impl LweParams {
    pub fn new(k: u32, m: u32, dim: usize, noise_bits: u32) -> Result<LweParams, String> {
        if k > 64 {
            return Err(format!("k = {k} exceeds 64 (ciphertext entries are u64)"));
        }
        if m == 0 || m >= k {
            return Err(format!("need 1 <= m < k, got m = {m}, k = {k}"));
        }
        if dim == 0 {
            return Err("the LWE dimension must be positive".into());
        }
        if noise_bits + 1 > k - m {
            return Err(format!(
                "need ν + 1 <= l = k - m, got ν = {noise_bits}, l = {}",
                k - m
            ));
        }
        Ok(LweParams {
            k,
            m,
            dim,
            noise_bits,
        })
    }

    /// `l = k - m`: the plaintext is scaled by `2^l`.
    pub fn l(&self) -> u32 {
        self.k - self.m
    }

    /// The largest `e + E` with `E = 2^ν`, i.e. `2^{ν+1} - 1`.
    pub fn max_shifted_noise(&self) -> u128 {
        (1u128 << (self.noise_bits + 1)) - 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub a: Vec<u64>,
    pub b: u64,
}

/// A binary secret key.
pub fn keygen(p: &LweParams, rng: &mut Stream) -> Vec<u64> {
    (0..p.dim).map(|_| rng.bit() as u64).collect()
}

/// `b = ⟨a, s⟩ + e + μ·2^l mod 2^k` with `e` uniform in `(-2^ν, 2^ν)`.
pub fn encrypt(p: &LweParams, s: &[u64], mu: u64, rng: &mut Stream) -> Ciphertext {
    let r = Ring::new(p.k);
    let a: Vec<u64> = (0..p.dim).map(|_| rng.bits(p.k) as u64).collect();
    let bound = 1u128 << p.noise_bits;
    let e = r.sub(rng.below(2 * bound - 1), bound - 1);
    let mut b = r.add(e, (mu as u128) << p.l());
    for (&ai, &si) in a.iter().zip(s) {
        b = r.add(b, r.mul(ai as u128, si as u128));
    }
    Ciphertext { a, b: b as u64 }
}

/// The phase `μ·2^l + e` of a ciphertext, in the clear.
pub fn phase_clear(p: &LweParams, ct: &Ciphertext, s: &[u64]) -> u128 {
    let r = Ring::new(p.k);
    let mut z = ct.b as u128;
    for (&ai, &si) in ct.a.iter().zip(s) {
        z = r.sub(z, r.mul(ai as u128, si as u128));
    }
    z
}

/// The shared phase `⟦b - ⟨a, s⟩⟧` per ciphertext, from the key sharing `key` (one entry per
/// coordinate). `party` and `delta_share` serve the public constant `b`.
pub fn phase(ct: &[Ciphertext], key: &Shared, party: usize, delta_share: u128) -> Shared {
    let (r, rk) = (key.ring(), Ring::new(key.k));
    let mut val = Vec::with_capacity(ct.len());
    let mut mac = Vec::with_capacity(ct.len());
    for c in ct {
        let b = rk.mask(c.b as u128);
        val.push(r.sub(if party == 0 { b } else { 0 }, dot(&c.a, &key.val)));
        mac.push(r.sub(r.mul(delta_share, b), dot(&c.a, &key.mac)));
    }
    Shared::new(key.k, key.kappa, val, mac)
}

/// `⟨a, k⟩ mod 2^128`, the two halves of `a` side by side: two independent memory streams, which
/// keep the multiplier busy while `a` comes from memory (the second call finds it in cache).
fn dot(a: &[u64], k: &[u128]) -> u128 {
    let n = a.len();
    assert_eq!(k.len(), n);
    let k = &k[..n];
    let h = n / 2;
    let mut s = 0u128;
    for j in 0..h {
        let (x, y) = (a[j] as u128, a[h + j] as u128);
        s = s.wrapping_add(x.wrapping_mul(k[j]).wrapping_add(y.wrapping_mul(k[h + j])));
    }
    for j in 2 * h..n {
        s = s.wrapping_add((a[j] as u128).wrapping_mul(k[j]));
    }
    s
}

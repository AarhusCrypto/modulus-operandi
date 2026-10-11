//! The ideal preprocessing functionality, simulated inside every party from a common seed.
//!
//! Clear values come from `("dealer", …)` streams. Party `σ < N-1` takes its shares from its own
//! `("share", σ, …)` stream and party `N-1` gets the difference. Every party runs the whole dealing
//! and keeps only its own shares. One batch is dealt per process and copied for every instance and
//! repetition (`deal_instances`).

use crate::abb::{Shared, Table};
use crate::dec::Decryption;
use crate::dec::convopen::OpenMaterial;
use crate::dec::lwe::{self, Ciphertext, LweParams};
use crate::prg::{Part, Stream};
use crate::ring::Ring;

pub struct Dealer {
    seed: u64,
    n: usize,
    id: usize,
    kappa: u32,
    delta: u128,
    key_share: u128,
    dealer: Stream,
    shares: Vec<Stream>,
}

impl Dealer {
    /// Deals the MAC key `Δ` for the session, shared by all instances; call `begin_batch` before
    /// dealing a batch.
    pub fn new(seed: u64, n: usize, id: usize, kappa: u32) -> Dealer {
        assert!(n >= 2 && id < n);
        let mut dealer = Stream::new(seed, &[Part::S("dealer"), Part::S("mac-key")]);
        let mut shares: Vec<Stream> = (0..n - 1)
            .map(|s| {
                Stream::new(
                    seed,
                    &[Part::S("share"), Part::N(s as u64), Part::S("mac-key")],
                )
            })
            .collect();
        // Key shares are κ-bit; `Δ` is their sum in the integers (mod 2^128), so that every
        // `Σ_σ ⟨Δ⟩^σ · c ≡ Δ · c` mod `2^{k+κ}`, as the MAC check and `add_const` need.
        let ring = Ring::new(kappa);
        let mut rest = dealer.bits(kappa);
        let mut key_shares = Vec::with_capacity(n);
        for stream in shares.iter_mut() {
            let share = stream.bits(kappa);
            rest = ring.sub(rest, share);
            key_shares.push(share);
        }
        key_shares.push(rest);
        let delta = key_shares.iter().fold(0u128, |a, &x| a.wrapping_add(x));
        let own = key_shares[id];
        Dealer {
            seed,
            n,
            id,
            kappa,
            delta,
            key_share: own,
            dealer,
            shares,
        }
    }

    /// Re-keys the streams for the batch, the same for every instance and repetition.
    pub fn begin_batch(&mut self) {
        let seed = self.seed;
        self.dealer = Stream::new(seed, &[Part::S("dealer"), Part::S("batch")]);
        self.shares = (0..self.n - 1)
            .map(|s| {
                Stream::new(
                    seed,
                    &[Part::S("share"), Part::N(s as u64), Part::S("batch")],
                )
            })
            .collect();
    }

    pub fn n(&self) -> usize {
        self.n
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn kappa(&self) -> u32 {
        self.kappa
    }

    /// This party's share of `Δ`.
    pub fn key_share(&self) -> u128 {
        self.key_share
    }

    /// The clear MAC key `Δ = Σ_σ ⟨Δ⟩^σ`; for tests only, never handed to protocol code.
    pub fn delta(&self) -> u128 {
        self.delta
    }

    /// The dealer's stream, for sampling clear values.
    pub fn rng(&mut self) -> &mut Stream {
        &mut self.dealer
    }

    /// Splits `x` into `n` additive shares over `ring` and returns party `id`'s.
    fn split(shares: &mut [Stream], n: usize, id: usize, ring: Ring, x: u128) -> u128 {
        let mut rest = x;
        let mut own = 0;
        for (s, stream) in shares.iter_mut().enumerate() {
            let share = stream.bits(ring.bits());
            rest = ring.sub(rest, share);
            if s == id {
                own = share;
            }
        }
        if id == n - 1 { rest } else { own }
    }

    /// Additive shares of each `x[i]` in `Z_{2^bits}`, without MACs.
    pub fn additive(&mut self, bits: u32, x: &[u128]) -> Vec<u128> {
        let ring = Ring::new(bits);
        x.iter()
            .map(|&v| Self::split(&mut self.shares, self.n, self.id, ring, ring.mask(v)))
            .collect()
    }

    /// Authenticated sharings of the given `x̂ ∈ Z_{2^{k+κ}}`.
    pub fn share_hat(&mut self, k: u32, x_hat: &[u128]) -> Shared {
        let ring = Ring::new(k + self.kappa);
        let mut val = Vec::with_capacity(x_hat.len());
        let mut mac = Vec::with_capacity(x_hat.len());
        for &xh in x_hat {
            let xh = ring.mask(xh);
            let m = ring.mul(self.delta, xh);
            val.push(Self::split(&mut self.shares, self.n, self.id, ring, xh));
            mac.push(Self::split(&mut self.shares, self.n, self.id, ring, m));
        }
        Shared::new(k, self.kappa, val, mac)
    }

    /// Authenticated sharings of the given `x ∈ Z_{2^k}`, with uniformly random upper `κ` bits.
    pub fn share(&mut self, k: u32, x: &[u128]) -> Shared {
        let ring = Ring::new(k);
        let x_hat: Vec<u128> = x
            .iter()
            .map(|&v| {
                let upper = self.dealer.bits(self.kappa);
                ring.mask(v) | upper.checked_shl(k).unwrap_or(0)
            })
            .collect();
        self.share_hat(k, &x_hat)
    }

    /// A table of `width` authenticated sharings per decryption, as `share`: entry `x` of
    /// decryption `i` shares `f(i, x) ∈ Z_{2^k}`. Dealt a decryption at a time.
    pub fn share_table(
        &mut self,
        k: u32,
        batch: usize,
        width: usize,
        f: impl Fn(usize, usize) -> u128,
    ) -> Table {
        Table::from_rows(k, self.kappa, width, batch, |i| {
            let row: Vec<u128> = (0..width).map(|x| f(i, x)).collect();
            self.share(k, &row)
        })
    }

    /// `len` fresh extra masks `⟦r⟧`, `r ∈ Z_{2^κ}`.
    pub fn extra_mask(&mut self, len: usize) -> Shared {
        self.share(0, &vec![0; len])
    }
}

/// One party's material for one batch, i.e. one instance of the protocol.
#[derive(Clone)]
pub struct Material<M> {
    /// Public: the ciphertexts to decrypt.
    pub ct: Vec<Ciphertext>,
    /// Public: their plaintexts, for the self-check.
    pub expected: Vec<u64>,
    /// The decryption's preprocessing (key sharing, the conversion's material and extra masks).
    pub dec: M,
    /// The material of `convopen`: `r_0`, `ŵ`, `γŵ` and `γ`.
    pub open: OpenMaterial,
}

/// Deals a batch: a fresh LWE key, `batch` ciphertexts of random plaintexts, and all
/// preprocessing, `γ` included. The same for every call with the same seed.
pub fn deal<D: Decryption>(
    dealer: &mut Dealer,
    dec: &D,
    lwe: &LweParams,
    batch: usize,
) -> Material<D::Material> {
    dealer.begin_batch();
    let sk = lwe::keygen(lwe, dealer.rng());
    let mut ct = Vec::with_capacity(batch);
    let mut expected = Vec::with_capacity(batch);
    for _ in 0..batch {
        let mu = dealer.rng().bits(lwe.m) as u64;
        ct.push(lwe::encrypt(lwe, &sk, mu, dealer.rng()));
        expected.push(mu);
    }
    let dec_mat = dec.deal(dealer, &sk, batch);
    let open = OpenMaterial::deal(dealer, dec.out_bits(), batch);
    Material {
        ct,
        expected,
        dec: dec_mat,
        open,
    }
}

/// The material of `instances` instances: one batch dealt once and deep-copied, each copy in
/// allocations of its own, so that the memory footprint and the accesses are those of distinct
/// material, whose values the timed phase does not depend on.
pub fn deal_instances<D: Decryption>(
    dealer: &mut Dealer,
    dec: &D,
    lwe: &LweParams,
    instances: usize,
    batch: usize,
) -> Vec<Material<D::Material>> {
    assert!(instances >= 1);
    let one = deal(dealer, dec, lwe, batch);
    let mut mats: Vec<_> = (1..instances).map(|_| one.clone()).collect();
    mats.push(one);
    mats
}

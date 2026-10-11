//! Seeded ChaCha20 streams, domain-separated by structured labels.

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{Rng, SeedableRng};
use sha2::{Digest, Sha256};

use crate::ring::{Ring, Word};

/// One component of a structured label, e.g. `[S("share"), N(party), N(batch)]`.
#[derive(Clone, Copy, Debug)]
pub enum Part<'a> {
    S(&'a str),
    N(u64),
}

/// ChaCha20 keyed by `SHA-256(seed ‖ label)`; the label encoding is injective.
pub struct Stream {
    rng: ChaCha20Rng,
}

impl Stream {
    pub fn new(seed: u64, label: &[Part]) -> Stream {
        let mut h = Sha256::new();
        h.update(seed.to_le_bytes());
        for part in label {
            match part {
                Part::S(s) => {
                    h.update([0u8]);
                    h.update((s.len() as u64).to_le_bytes());
                    h.update(s.as_bytes());
                }
                Part::N(x) => {
                    h.update([1u8]);
                    h.update(x.to_le_bytes());
                }
            }
        }
        let key: [u8; 32] = h.finalize().into();
        Stream {
            rng: ChaCha20Rng::from_seed(key),
        }
    }

    pub fn u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    pub fn u128(&mut self) -> u128 {
        let lo = self.rng.next_u64() as u128;
        let hi = self.rng.next_u64() as u128;
        lo | (hi << 64)
    }

    /// Uniform in `Z_{2^bits}`.
    pub fn bits(&mut self, bits: u32) -> u128 {
        let ring = Ring::new(bits);
        ring.mask(self.u128())
    }

    /// Uniform in `[0, bound)`, by rejection sampling; `bound > 0`.
    pub fn below(&mut self, bound: u128) -> u128 {
        assert!(bound > 0);
        let width = u128::BITS - (bound - 1).leading_zeros();
        loop {
            let x = u128::low_mask(width) & self.u128();
            if x < bound {
                return x;
            }
        }
    }

    pub fn bit(&mut self) -> bool {
        self.rng.next_u64() & 1 == 1
    }
}

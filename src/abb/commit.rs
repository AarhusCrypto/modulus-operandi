//! The commitment scheme: `Commit(a; ρ) = SHA-256(sid ‖ party ‖ round ‖ instance ‖ ρ ‖ encode(a))`.
//!
//! `party`, `round` and `instance` are 4 bytes each, little-endian; `encode` is `Section::encode`, which is
//! injective since every party knows the layout of the tuple. Revealing sends `(a, ρ)`.

use std::ops::Range;

use sha2::{Digest, Sha256};

use super::round::{Section, encode_ring};

/// Length of a commitment and of its randomness `ρ`.
pub const LEN: usize = 32;

/// Ring elements per chunk of `hash`'s encoding.
const CHUNK: usize = 1024;

/// `Commit(a; ρ)` by `party` in round `round` of protocol instance `instance` of session `sid`.
pub fn hash<'a>(
    sid: &[u8; 16],
    party: usize,
    round: u32,
    instance: u32,
    rho: &[u8; LEN],
    a: impl IntoIterator<Item = &'a Section>,
) -> [u8; LEN] {
    let mut h = Sha256::new();
    h.update(sid);
    h.update((party as u32).to_le_bytes());
    h.update(round.to_le_bytes());
    h.update(instance.to_le_bytes());
    h.update(rho);
    // Ring sections are encoded a chunk at a time, into a buffer that stays in cache.
    let mut buf = Vec::new();
    for s in a {
        match s {
            Section::Ring { bits, vals } => {
                for c in vals.chunks(CHUNK) {
                    buf.clear();
                    encode_ring(*bits, c, &mut buf);
                    h.update(&buf);
                }
            }
            Section::Bytes(b) => h.update(b),
        }
    }
    h.finalize().into()
}

/// What a party committed to in one exchange.
pub struct Commitment {
    pub(crate) round: u32,
    pub(crate) section: usize,
    pub(crate) tuple: Vec<Section>,
    pub(crate) rho: [u8; LEN],
    /// Test path only: the tuple as hashed for each peer, when the tamper hook ran on it.
    pub(crate) per_peer: Option<Vec<Vec<Section>>>,
}

/// A pending reveal: the sections holding the tuple and `ρ`, and the commitments to check them
/// against.
pub struct Reveal {
    pub(crate) commit_round: u32,
    pub(crate) tuple: Range<usize>,
    pub(crate) rho: usize,
    pub(crate) theirs: Vec<[u8; LEN]>,
}

impl Reveal {
    /// The sections of the round that hold the revealed tuple.
    pub fn sections(&self) -> Range<usize> {
        self.tuple.clone()
    }
}

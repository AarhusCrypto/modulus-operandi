//! Point-to-point transports.

pub mod mem;
pub mod tcp;

use std::fmt;
use std::sync::Arc;

/// Ends a party: a failed check, a missing or malformed message, or a timeout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Abort(pub String);

impl Abort {
    pub fn new(reason: impl Into<String>) -> Abort {
        Abort(reason.into())
    }
}

impl fmt::Display for Abort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "abort: {}", self.0)
    }
}

impl std::error::Error for Abort {}

/// A frame's payload, shared by the peers it goes to.
pub type Payload = Arc<Vec<u8>>;

/// Every frame is tagged `(round, instance)`. `round` counts the party's protocol rounds over the
/// whole session and never resets; `instance` is the protocol instance the frame belongs to.
pub trait Transport {
    fn id(&self) -> usize;
    fn n(&self) -> usize;
    /// Hands `out[j]` to every peer j != id, without waiting for the peers; `out` has length `n`,
    /// the entry at `id` is ignored. A peer that has gone is not an error here: `recv` reports it
    /// once the frames it sent before are used up, so that a party first finishes the checks it
    /// has the frames for.
    fn send(&mut self, round: u32, instance: u32, out: &[Payload]) -> Result<(), Abort>;
    /// The next frame from each peer, in id order, which must carry the tag `(round, instance)`;
    /// the entry at `id` is empty.
    fn recv(&mut self, round: u32, instance: u32) -> Result<Vec<Payload>, Abort>;
    /// Test-only: a rushing party receives every peer's frame of a round before sending its own.
    fn rushing(&self) -> bool {
        false
    }
}

/// The abort for a frame from party `j` tagged `got` where `want` was due.
pub(crate) fn wrong_tag(j: usize, got: (u32, u32), want: (u32, u32)) -> Abort {
    Abort::new(format!(
        "party {j} sent round {} instance {}, expected round {} instance {}",
        got.0, got.1, want.0, want.1
    ))
}

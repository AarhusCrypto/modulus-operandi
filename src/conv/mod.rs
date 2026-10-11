//! Modulus conversion protocols.

pub mod modconv12;

use crate::abb::{Ctx, Round, Shared, Step};
use crate::net::Abort;
use crate::prep::Dealer;

/// The online phase is a state machine with one step per round: `start` yields the first
/// round's sections, and `step`, given that round as exchanged, the next round's or the result.
pub trait Conversion {
    type Params;
    /// One party's preprocessing for one conversion, all decryptions of a batch.
    type Material: Clone;
    /// One instance's online phase between two rounds.
    type State;
    fn deal(dealer: &mut Dealer, p: &Self::Params, batch: usize) -> Self::Material;
    /// Starts converting `⟦x⟧_q`.
    fn start(
        ctx: &mut Ctx,
        p: &Self::Params,
        x_q: &Shared,
        mat: &Self::Material,
    ) -> (Self::State, Round);
    /// The next round, or `⟦x⟧_t`. Openings go into the log, unchecked.
    fn step(
        ctx: &mut Ctx,
        p: &Self::Params,
        st: Self::State,
        round: Round,
        mat: &Self::Material,
    ) -> Result<Step<Self::State, Shared>, Abort>;
}

//! Threshold decryption.

pub mod convopen;
pub mod lwe;
pub mod modconv;
pub mod zzlp25;

use crate::abb::{Ctx, Round, Shared, Step};
use crate::net::Abort;
use crate::prep::Dealer;
use lwe::Ciphertext;

/// The online phase is a state machine with one step per round, as in `Conversion`.
pub trait Decryption {
    /// One party's preprocessing for one batch; a clone is a deep copy (see `prep::deal_instances`).
    type Material: Clone;
    /// One instance's online phase between two rounds.
    type State;
    /// Deals the material for `batch` decryptions under the clear secret key `sk`.
    fn deal(&self, dealer: &mut Dealer, sk: &[u64], batch: usize) -> Self::Material;
    /// The width `k` of `⟦v⟧`, i.e. of the pad `w`.
    fn out_bits(&self) -> u32;
    /// Starts decrypting `ct`.
    fn start(&self, ctx: &mut Ctx, ct: &[Ciphertext], mat: &Self::Material)
    -> (Self::State, Round);
    /// The next round, or `⟦v⟧`; its openings are in the log.
    fn step(
        &self,
        ctx: &mut Ctx,
        st: Self::State,
        round: Round,
        mat: &Self::Material,
    ) -> Result<Step<Self::State, Shared>, Abort>;
    /// The plaintexts.
    fn decode(&self, v: &[u128]) -> Vec<u64>;
}

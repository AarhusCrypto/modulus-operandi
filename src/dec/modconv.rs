//! Threshold decryption through a conversion (BFV/TFHE route): `⟦z⟧` over `2^k`, add `E = 2^ν`,
//! reduce to `q = 2^l`, convert `⟦e + E⟧` to `t = 2^k`, subtract, which gives `⟦μ·2^l⟧`.

use super::Decryption;
use super::lwe::{self, Ciphertext, LweParams};
use crate::abb::{Ctx, Round, Shared, Step};
use crate::conv::Conversion;
use crate::conv::modconv12::{ModConv12, ModConvParams, Variant};
use crate::net::Abort;
use crate::prep::Dealer;

#[derive(Clone)]
pub struct DecMaterial<M> {
    /// Sharing of the LWE key, one entry per coordinate.
    pub key: Shared,
    pub conv: M,
}

pub struct ModConvDecryption<C: Conversion> {
    pub lwe: LweParams,
    pub conv: C::Params,
}

impl ModConvDecryption<ModConv12> {
    /// ModConv1 or ModConv2 from `2^l` to `2^k`; `beta = None` takes the smallest 2-power that
    /// meets the precondition at the noise bound.
    pub fn modconv12(
        lwe: LweParams,
        variant: Variant,
        beta: Option<u128>,
        n: usize,
    ) -> Result<Self, String> {
        let (l, k, max_x) = (lwe.l(), lwe.k, lwe.max_shifted_noise());
        let beta = match beta {
            Some(b) => b,
            None => ModConvParams::smallest_beta(variant, n, l, k, max_x)?,
        };
        let conv = ModConvParams::new(variant, beta, n, l, k, max_x)?;
        Ok(ModConvDecryption { lwe, conv })
    }
}

/// Between two rounds: `⟦e + E⟧` over `2^k`, and the conversion's state.
pub struct ModConvState<S> {
    x: Shared,
    conv: S,
}

impl<C: Conversion> Decryption for ModConvDecryption<C> {
    type Material = DecMaterial<C::Material>;
    type State = ModConvState<C::State>;

    fn deal(&self, dealer: &mut Dealer, sk: &[u64], batch: usize) -> Self::Material {
        let s: Vec<u128> = sk.iter().map(|&x| x as u128).collect();
        let key = dealer.share(self.lwe.k, &s);
        let conv = C::deal(dealer, &self.conv, batch);
        DecMaterial { key, conv }
    }

    fn out_bits(&self) -> u32 {
        self.lwe.k
    }

    fn start(
        &self,
        ctx: &mut Ctx,
        ct: &[Ciphertext],
        mat: &Self::Material,
    ) -> (Self::State, Round) {
        let mut x = lwe::phase(ct, &mat.key, ctx.id(), ctx.key());
        ctx.add_scalar(&mut x, 1 << self.lwe.noise_bits);
        let (conv, round) = C::start(ctx, &self.conv, &x.reduce(self.lwe.l()), &mat.conv);
        (ModConvState { x, conv }, round)
    }

    fn step(
        &self,
        ctx: &mut Ctx,
        st: Self::State,
        round: Round,
        mat: &Self::Material,
    ) -> Result<Step<Self::State, Shared>, Abort> {
        let ModConvState { mut x, conv } = st;
        Ok(match C::step(ctx, &self.conv, conv, round, &mat.conv)? {
            Step::Next(conv, round) => Step::Next(ModConvState { x, conv }, round),
            Step::Done(noise_t) => {
                x.sub_assign(&noise_t);
                Step::Done(x)
            }
        })
    }

    fn decode(&self, v: &[u128]) -> Vec<u64> {
        v.iter().map(|&x| (x >> self.lwe.l()) as u64).collect()
    }
}

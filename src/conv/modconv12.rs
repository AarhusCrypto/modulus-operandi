//! ModConv1 and ModConv2 (`protocol:modconv1`, `protocol:modconv2`) from `q = 2^{q_bits}` to
//! `t = 2^{t_bits}`, `q | t`. Both share the online phase; they differ in the dealt corrections.

use super::Conversion;
use crate::abb::{Ctx, Opening, Round, Shared, Step, Table};
use crate::net::Abort;
use crate::prep::Dealer;
use crate::ring::Ring;

/// Largest `β` accepted, since every party stores `β` corrections per decryption.
pub const MAX_BETA: u128 = 1 << 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    ModConv1,
    ModConv2,
}

#[derive(Clone, Copy, Debug)]
pub struct ModConvParams {
    pub variant: Variant,
    pub beta: u128,
    /// Number of parties (ModConv2's precondition depends on it).
    pub n: usize,
    pub q_bits: u32,
    pub t_bits: u32,
}

impl ModConvParams {
    /// Checks `β` against the protocol's requirements and its precondition at the largest input
    /// `max_x`.
    pub fn new(
        variant: Variant,
        beta: u128,
        n: usize,
        q_bits: u32,
        t_bits: u32,
        max_x: u128,
    ) -> Result<ModConvParams, String> {
        if q_bits == 0 || q_bits > t_bits || t_bits > 127 {
            return Err(format!(
                "need 1 <= q_bits <= t_bits <= 127, got {q_bits}, {t_bits}"
            ));
        }
        let q = 1u128 << q_bits;
        let min_beta = match variant {
            Variant::ModConv1 => 2,
            Variant::ModConv2 => n as u128 + 1,
        };
        if beta < min_beta {
            return Err(format!("{variant:?} needs β >= {min_beta}, got β = {beta}"));
        }
        if beta > q || beta > MAX_BETA || beta.checked_mul(q).is_none() {
            return Err(format!("β = {beta} too large for q = 2^{q_bits}"));
        }
        let bound = precondition_bound(variant, beta, n, q)
            .ok_or_else(|| format!("{variant:?}: N·q overflows for q = 2^{q_bits}"))?;
        if max_x > bound {
            return Err(format!(
                "{variant:?} with β = {beta}, q = 2^{q_bits}: precondition x <= {bound} fails for inputs up to {max_x}"
            ));
        }
        Ok(ModConvParams {
            variant,
            beta,
            n,
            q_bits,
            t_bits,
        })
    }

    /// The smallest 2-power `β` that `new` accepts.
    pub fn smallest_beta(
        variant: Variant,
        n: usize,
        q_bits: u32,
        t_bits: u32,
        max_x: u128,
    ) -> Result<u128, String> {
        let mut beta = 2u128;
        while beta <= MAX_BETA {
            if ModConvParams::new(variant, beta, n, q_bits, t_bits, max_x).is_ok() {
                return Ok(beta);
            }
            beta *= 2;
        }
        Err(format!(
            "no 2-power β meets the {variant:?} precondition for inputs up to {max_x} and q = 2^{q_bits}"
        ))
    }

    pub fn q(&self) -> u128 {
        1u128 << self.q_bits
    }

    /// `α(z) = ⌊βz/q⌋`, the index of the interval containing `z ∈ Z_q`.
    pub fn alpha(&self, z: u128) -> usize {
        debug_assert!(z < self.q());
        ((self.beta * z) >> self.q_bits) as usize
    }

    /// The corrections `u_0, …, u_{β-1}` for the masks `m^1, …, m^N` (ModConv2) or the mask `m`
    /// (ModConv1, a single entry).
    pub fn corrections(&self, masks: &[u128]) -> Vec<u128> {
        let t = Ring::new(self.t_bits);
        let q = self.q();
        let mut m = 0u128;
        for &ms in masks {
            m = t.add(m, ms);
        }
        // s = Σ α(m^σ); for ModConv1 that is α(m).
        let s: u128 = masks.iter().map(|&ms| self.alpha(ms) as u128).sum();
        match self.variant {
            Variant::ModConv1 => assert_eq!(masks.len(), 1),
            Variant::ModConv2 => assert_eq!(masks.len(), self.n),
        }
        let mut u = Vec::with_capacity(self.beta as usize);
        for i in 0..self.beta {
            let c = match self.variant {
                Variant::ModConv1 => (s > i) as u128,
                Variant::ModConv2 if s > i => (s - i).div_ceil(self.beta),
                Variant::ModConv2 => 0,
            };
            u.push(t.sub(m, t.mul(c, q)));
        }
        u
    }

    /// The online phase in the clear: `y - u_{α(y)} mod t`.
    pub fn convert_clear(&self, y: u128, u: &[u128]) -> u128 {
        Ring::new(self.t_bits).sub(y, u[self.alpha(y)])
    }
}

/// The largest `x` the precondition allows: `q - ⌈q/β⌉` (ModConv1), `q - ⌈Nq/β⌉` (ModConv2).
pub fn precondition_bound(variant: Variant, beta: u128, n: usize, q: u128) -> Option<u128> {
    let num = match variant {
        Variant::ModConv1 => q,
        Variant::ModConv2 => q.checked_mul(n as u128)?,
    };
    q.checked_sub(num.div_ceil(beta))
}

/// Per decryption: the corrections `⟦u_0⟧_t, …, ⟦u_{β-1}⟧_t` and the extra mask `⟦r_1⟧` of the
/// opening of `y`. `⟦m⟧_q` is `⟦u_0⟧_t` reduced mod `q` (`remark:modconv1-divisible`).
#[derive(Clone)]
pub struct ModConvMaterial {
    /// `β` entries per decryption.
    pub corrections: Table,
    pub r1: Shared,
}

pub struct ModConv12;

impl Conversion for ModConv12 {
    type Params = ModConvParams;
    type Material = ModConvMaterial;

    fn deal(dealer: &mut Dealer, p: &ModConvParams, batch: usize) -> ModConvMaterial {
        let count = match p.variant {
            Variant::ModConv1 => 1,
            Variant::ModConv2 => p.n,
        };
        let u: Vec<Vec<u128>> = (0..batch)
            .map(|_| {
                let masks: Vec<u128> = (0..count).map(|_| dealer.rng().bits(p.q_bits)).collect();
                p.corrections(&masks)
            })
            .collect();
        let corrections = dealer.share_table(p.t_bits, batch, p.beta as usize, |d, i| u[d][i]);
        let r1 = dealer.extra_mask(batch);
        ModConvMaterial { corrections, r1 }
    }

    /// The opening of `y`.
    type State = Opening;

    fn start(
        ctx: &mut Ctx,
        p: &ModConvParams,
        x_q: &Shared,
        mat: &ModConvMaterial,
    ) -> (Opening, Round) {
        assert_eq!(x_q.k, p.q_bits);
        let mut x_m = mat.corrections.column(0).reduce(p.q_bits);
        x_m.add_assign(x_q);
        let mut round = Round::new();
        let h = ctx.open(&mut round, &x_m, &mat.r1);
        (h, round)
    }

    fn step(
        ctx: &mut Ctx,
        p: &ModConvParams,
        h: Opening,
        round: Round,
        mat: &ModConvMaterial,
    ) -> Result<Step<Opening, Shared>, Abort> {
        let y = ctx.opened(&round, h);
        let idx: Vec<usize> = y.iter().map(|&v| p.alpha(v)).collect();
        let mut x_t = mat.corrections.select(&idx);
        x_t.neg_assign();
        ctx.add_const(&mut x_t, &y);
        Ok(Step::Done(x_t))
    }
}

//! `protocol:convopen`: a decryption followed by the opening of `⟦v⟧`, pipelined into the rounds
//! of the conversion plus three.
//!
//! Sections of the three rounds after Π, with `ℓ` the number of Π's openings:
//! - step 2: `[v + w share, commitment to (z_1, …, z_ℓ)]`;
//! - step 3: `[z_1, …, z_ℓ, ρ, commitment to (z_{v+w}, ŵ, γŵ, γ)]`;
//! - step 4: `[z_{v+w}, ŵ, γŵ, γ, ρ]`.
//!
//! `z_j` is the check share of Π's `j`-th opening; `ŵ`, `γŵ` and `z_{v+w}` hold one element per
//! decryption, `γ` one per batch.
//!
//! An instance is a state machine with one step per round (`ConvOpen`), so that several instances,
//! each on a `Material` of its own, can advance in lockstep (`convopen_streamed`).

use super::Decryption;
use super::lwe::Ciphertext;
use crate::abb::{Commitment, Ctx, Opening, Reveal, Round, Section, Shared, Step};
use crate::net::Abort;
use crate::prep::{Dealer, Material};
use crate::ring::Ring;

/// The material of the opening: `⟦r_0⟧`, `⟦w⟧_t` with `ŵ` uniform in `Z_{2^{k+κ}}`, `⟨γŵ⟩` per
/// decryption, and `⟨γ⟩` per batch.
#[derive(Clone)]
pub struct OpenMaterial {
    pub r0: Shared,
    pub w: Shared,
    pub gamma_w: Vec<u128>,
    pub gamma: u128,
}

impl OpenMaterial {
    pub fn deal(dealer: &mut Dealer, k: u32, batch: usize) -> OpenMaterial {
        let bits = k + dealer.kappa();
        let r0 = dealer.extra_mask(batch);
        let w_hat: Vec<u128> = (0..batch).map(|_| dealer.rng().bits(bits)).collect();
        let gamma = dealer.rng().bits(bits);
        let ring = Ring::new(bits);
        let gw: Vec<u128> = w_hat.iter().map(|&w| ring.mul(gamma, w)).collect();
        let w = dealer.share_hat(k, &w_hat);
        let gamma_w = dealer.additive(bits, &gw);
        let gamma = dealer.additive(bits, &[gamma])[0];
        OpenMaterial {
            r0,
            w,
            gamma_w,
            gamma,
        }
    }
}

/// One instance of the protocol between two rounds: in Π's rounds (step 1), or after the
/// sections of step 2, 3 or 4 have been built.
pub struct ConvOpen<'a, D: Decryption> {
    dec: &'a D,
    mat: &'a D::Material,
    om: &'a OpenMaterial,
    /// Where Π's openings start in the log.
    start: usize,
    stage: Stage<D::State>,
}

enum Stage<S> {
    Pi(S),
    Open {
        h: Opening,
        c: Commitment,
    },
    Check {
        vw: Vec<u128>,
        rv: Reveal,
        c: Commitment,
    },
    Unmask {
        vw: Vec<u128>,
        rv: Reveal,
    },
}

impl<'a, D: Decryption> ConvOpen<'a, D> {
    /// Starts decrypting `ct`: the instance and Π's first round.
    pub fn start(
        ctx: &mut Ctx,
        dec: &'a D,
        ct: &[Ciphertext],
        mat: &'a D::Material,
        om: &'a OpenMaterial,
    ) -> (Self, Round) {
        let start = ctx.log().len();
        let (st, round) = dec.start(ctx, ct, mat);
        let co = ConvOpen {
            dec,
            mat,
            om,
            start,
            stage: Stage::Pi(st),
        };
        (co, round)
    }

    /// Given the round just exchanged, the next round's sections, or the plaintexts.
    pub fn step(self, ctx: &mut Ctx, round: Round) -> Result<Step<Self, Vec<u64>>, Abort> {
        let ConvOpen {
            dec,
            mat,
            om,
            start,
            stage,
        } = self;
        let bits = dec.out_bits() + ctx.kappa();
        let (stage, next) = match stage {
            // Step 1: the online phase of Π, its openings logged unchecked.
            Stage::Pi(st) => match dec.step(ctx, st, round, mat)? {
                Step::Next(st, next) => (Stage::Pi(st), next),
                Step::Done(mut v) => {
                    // Step 2: open ⟦v⟧ + ⟦w⟧ with extra mask ⟦r_0⟧; commit to the check shares
                    // of Π's openings.
                    let pi = start..ctx.log().len();
                    let mut r2 = Round::new();
                    v.add_assign(&om.w);
                    let h = ctx.open(&mut r2, &v, &om.r0);
                    let z_pi = ctx.check_shares(pi);
                    let c = ctx.commit(&mut r2, z_pi)?;
                    (Stage::Open { h, c }, r2)
                }
            },
            // Step 3: reveal and check the check shares of Π's openings; commit to the check
            // share on v + w and to the shares of ŵ, γŵ and γ.
            Stage::Open { h, c } => {
                let vw = ctx.opened(&round, h);
                assert_eq!(ctx.log().len(), start + 1);
                let mut r3 = Round::new();
                let rv = ctx.reveal(&mut r3, c, &round);
                let mut tuple = ctx.check_shares(start..start + 1);
                tuple.push(Section::Ring {
                    bits,
                    vals: om.w.val.clone(),
                });
                tuple.push(Section::Ring {
                    bits,
                    vals: om.gamma_w.clone(),
                });
                tuple.push(Section::Ring {
                    bits,
                    vals: vec![om.gamma],
                });
                let c = ctx.commit(&mut r3, tuple)?;
                (Stage::Check { vw, rv, c }, r3)
            }
            // Step 4: reveal the check share on v + w and the shares of ŵ, γŵ and γ.
            Stage::Check { vw, rv, c } => {
                ctx.verify_reveal(&round, &rv)?;
                ctx.check_macs(&round, rv.sections())?;
                let mut r4 = Round::new();
                let rv = ctx.reveal(&mut r4, c, &round);
                (Stage::Unmask { vw, rv }, r4)
            }
            // After step 4: check them and output.
            Stage::Unmask { vw, rv } => {
                ctx.verify_reveal(&round, &rv)?;
                let s = rv.sections().start;
                ctx.check_macs(&round, s..s + 1)?;
                let id = ctx.id();
                let w = round.sum(id, s + 1);
                let gamma_w = round.sum(id, s + 2);
                let gamma = round.sum(id, s + 3)[0];
                let ring = Ring::new(bits);
                if !ctx.gamma_check_skipped() {
                    for d in 0..w.len() {
                        if gamma_w[d] != ring.mul(gamma, w[d]) {
                            return Err(Abort::new(format!(
                                "round {}: one-time MAC check on w failed (instance {}, \
                                 decryption {d})",
                                ctx.round() - 1,
                                ctx.instance()
                            )));
                        }
                    }
                }
                let r = Ring::new(dec.out_bits());
                let out: Vec<u128> = vw
                    .iter()
                    .zip(&w)
                    .map(|(&a, &b)| r.sub(a, r.mask(b)))
                    .collect();
                return Ok(Step::Done(dec.decode(&out)));
            }
        };
        let co = ConvOpen {
            dec,
            mat,
            om,
            start,
            stage,
        };
        Ok(Step::Next(co, next))
    }
}

/// Decrypts `ct` in one instance and returns the plaintexts, or aborts.
pub fn convopen<D: Decryption>(
    ctx: &mut Ctx,
    dec: &D,
    ct: &[Ciphertext],
    mat: &D::Material,
    om: &OpenMaterial,
) -> Result<Vec<u64>, Abort> {
    let (mut co, mut round) = ConvOpen::start(ctx, dec, ct, mat, om);
    loop {
        ctx.exchange(&mut round)?;
        match co.step(ctx, round)? {
            Step::Next(c, r) => (co, round) = (c, r),
            Step::Done(pt) => return Ok(pt),
        }
    }
}

/// Decrypts the batch `mats[j]` in instance `j`, on `ctxs[j]`, all instances in flight at once:
/// per round, instance by instance, wait for its frames, compute, and hand its next round to the
/// transport. Every party runs this order, so each connection carries the frames in the order
/// they are needed. `release(j, plaintexts)` gets instance `j`'s plaintexts as soon as it outputs
/// them; any abort ends all instances.
pub fn convopen_streamed<D: Decryption>(
    ctxs: &mut [Ctx],
    dec: &D,
    mats: &[Material<D::Material>],
    mut release: impl FnMut(usize, Vec<u64>),
) -> Result<(), Abort> {
    assert_eq!(ctxs.len(), mats.len());
    let mut live = Vec::with_capacity(mats.len());
    for (ctx, m) in ctxs.iter_mut().zip(mats) {
        let (co, round) = ConvOpen::start(ctx, dec, &m.ct, &m.dec, &m.open);
        ctx.post(&round)?;
        live.push(Some((co, round)));
    }
    while live.iter().any(Option::is_some) {
        for (j, slot) in live.iter_mut().enumerate() {
            let Some((co, mut round)) = slot.take() else {
                continue;
            };
            let ctx = &mut ctxs[j];
            ctx.collect(&mut round)?;
            match co.step(ctx, round)? {
                Step::Next(co, next) => {
                    ctx.post(&next)?;
                    *slot = Some((co, next));
                }
                Step::Done(pt) => release(j, pt),
            }
        }
    }
    Ok(())
}

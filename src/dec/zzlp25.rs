//! ZZLP25's Π_Decrypt (their Fig. 3), with `Mod_{l,k}` (Proc. 1) via `LTRand_{l,k}` (Proc. 3).
//!
//! `⟦z⟧_k = ⟨c, ⟦s⟧⟩ + 2^{l-1}`. Open `z' = z + r mod 2^l`; per base-`2^b` digit, look up
//! `⟦Sign(z'_i - r_i)⟧_{d+1}`, and let `⟦y⟧_{d+1} = Σ_i 2^i ⟦Sign(z'_i - r_i)⟧_{d+1}`. Open `y + r'`
//! mod `2^{d+1}` and look up `⟦u⟧_m = ⟦ModLTZ_{d+1}(y)⟧_m`, i.e. `u = (z' < r)` by their Eq. (4).
//! Then `⟦e⟧_k = z' - ⟦r⟧_k + 2^l ⟦u⟧` and `⟦v⟧_k = ⟦z⟧_k - ⟦e⟧_k = ⟦μ·2^l⟧_k`.

use super::Decryption;
use super::lwe::{self, Ciphertext, LweParams};
use crate::abb::{Ctx, Opening, Round, Shared, Step, Table};
use crate::net::Abort;
use crate::prep::Dealer;
use crate::ring::Ring;

/// Largest table index width accepted (`b` and `d + 1`), since every party stores the tables.
pub const MAX_TABLE_BITS: u32 = 24;

#[derive(Clone, Copy, Debug)]
pub struct Zzlp25 {
    pub lwe: LweParams,
    /// Digit bits `b`.
    pub b: u32,
    /// Number of digits `d = ⌈l/b⌉`.
    pub d: u32,
    /// Bits of the top digit, `b' = l - (d-1)b`.
    pub b_top: u32,
}

/// One party's material for a batch. Every `Shared` has one entry per decryption.
#[derive(Clone)]
pub struct Zzlp25Material {
    /// Sharing of the LWE key, one entry per coordinate.
    pub key: Shared,
    /// `⟦r⟧_k`, `r` uniform in `[2^l]`.
    pub r: Shared,
    /// Entry `x` of `sign[i]` is `⟦Sign(x - r_i)⟧_{d+1}` for `x ∈ [2^b]` (`[2^{b'}]` for the top
    /// digit), `r_i` the `i`-th digit of `r`.
    pub sign: Vec<Table>,
    /// The ModLTZ gate's mask `⟦r'⟧_{d+1}`, `r'` uniform in `Z_{2^{d+1}}`.
    pub r_ltz: Shared,
    /// Entry `x` is `⟦ModLTZ_{d+1}(x - r')⟧_m` for `x ∈ Z_{2^{d+1}}`.
    pub ltz: Table,
    /// Extra masks of the openings of `z'` and of `y + r'`.
    pub r1: Shared,
    pub r2: Shared,
}

impl Zzlp25 {
    /// Checks the parameters; the noise must satisfy `ν <= l - 1`, so that `e + 2^{l-1} ∈ [0, 2^l)`.
    pub fn new(lwe: LweParams, b: u32) -> Result<Zzlp25, String> {
        let (k, m, l) = (lwe.k, lwe.m, lwe.l());
        if m == 0 || l == 0 {
            return Err(format!("need 1 <= m < k, got m = {m}, k = {k}"));
        }
        if lwe.noise_bits + 1 > l {
            return Err(format!(
                "ZZLP25 needs ν <= l - 1, got ν = {}, l = {l}",
                lwe.noise_bits
            ));
        }
        if b == 0 {
            return Err("need b >= 1".into());
        }
        let d = l.div_ceil(b);
        if d + 1 > k {
            return Err(format!("need d + 1 <= k, got d = {d}, k = {k}"));
        }
        if b.min(l) > MAX_TABLE_BITS || d + 1 > MAX_TABLE_BITS {
            return Err(format!(
                "tables too large: b = {b}, d + 1 = {} (at most {MAX_TABLE_BITS} bits each)",
                d + 1
            ));
        }
        Ok(Zzlp25 {
            lwe,
            b,
            d,
            b_top: l - (d - 1) * b,
        })
    }

    pub fn l(&self) -> u32 {
        self.lwe.l()
    }

    /// Bits of digit `i`: `b`, or `b'` for the top digit.
    pub fn digit_bits(&self, i: u32) -> u32 {
        if i + 1 == self.d { self.b_top } else { self.b }
    }

    /// Digit `i` of `x ∈ [2^l]` in base `2^b`.
    pub fn digit(&self, x: u128, i: u32) -> usize {
        Ring::new(self.digit_bits(i)).mask(x >> (i * self.b)) as usize
    }

    /// `Sign(x - r_i)` mod `2^{d+1}`, with `-1` as `2^{d+1} - 1`.
    pub fn sign_entry(&self, x: usize, r_i: usize) -> u128 {
        let ring = Ring::new(self.d + 1);
        match x.cmp(&r_i) {
            std::cmp::Ordering::Less => ring.neg(1),
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }

    /// `ModLTZ_{d+1}(y)`: 1 iff `y ∈ [2^d, 2^{d+1})`.
    pub fn mod_ltz(&self, y: u128) -> u128 {
        (Ring::new(self.d + 1).mask(y) >> self.d) & 1
    }

    /// Entry `x` of the ModLTZ table for the mask `r'`: `ModLTZ_{d+1}(x - r')`.
    pub fn ltz_entry(&self, x: u128, r_ltz: u128) -> u128 {
        self.mod_ltz(Ring::new(self.d + 1).sub(x, r_ltz))
    }

    /// Their Eq. (4) in the clear: `(z' < r)` from the signs of the digit differences.
    pub fn lt_clear(&self, z1: u128, r: u128) -> u128 {
        let ring = Ring::new(self.d + 1);
        let mut y = 0;
        for i in 0..self.d {
            let s = self.sign_entry(self.digit(z1, i), self.digit(r, i));
            y = ring.add(y, ring.mul(s, 1 << i));
        }
        self.mod_ltz(y)
    }

    /// `Mod_{l,k}` in the clear: `e = z' - r + 2^l u mod 2^k`, `z' = z + r mod 2^l`, `u = (z' < r)`.
    pub fn mod_clear(&self, z: u128, r: u128) -> u128 {
        let (k, l) = (self.lwe.k, self.l());
        let z1 = Ring::new(l).add(z, r);
        let ring = Ring::new(k);
        ring.add(ring.sub(z1, r), self.lt_clear(z1, r) << l)
    }
}

/// Between two rounds: `⟦z⟧_k` and the pending opening, of `z'` (while `z1` is `None`) or of
/// `y + r'`.
pub struct Zzlp25State {
    z: Shared,
    z1: Option<Vec<u128>>,
    h: Opening,
}

impl Decryption for Zzlp25 {
    type Material = Zzlp25Material;
    type State = Zzlp25State;

    fn deal(&self, dealer: &mut Dealer, sk: &[u64], batch: usize) -> Zzlp25Material {
        let (k, m, l, d) = (self.lwe.k, self.lwe.m, self.l(), self.d);
        let s: Vec<u128> = sk.iter().map(|&x| x as u128).collect();
        let key = dealer.share(k, &s);
        let r: Vec<u128> = (0..batch).map(|_| dealer.rng().bits(l)).collect();
        let r_ltz: Vec<u128> = (0..batch).map(|_| dealer.rng().bits(d + 1)).collect();
        let sign = (0..d)
            .map(|i| {
                dealer.share_table(d + 1, batch, 1 << self.digit_bits(i), |j, x| {
                    self.sign_entry(x, self.digit(r[j], i))
                })
            })
            .collect();
        let ltz = dealer.share_table(m, batch, 1 << (d + 1), |j, x| {
            self.ltz_entry(x as u128, r_ltz[j])
        });
        let r = dealer.share(k, &r);
        let r_ltz = dealer.share(d + 1, &r_ltz);
        let r1 = dealer.extra_mask(batch);
        let r2 = dealer.extra_mask(batch);
        Zzlp25Material {
            key,
            r,
            sign,
            r_ltz,
            ltz,
            r1,
            r2,
        }
    }

    fn out_bits(&self) -> u32 {
        self.lwe.k
    }

    fn start(
        &self,
        ctx: &mut Ctx,
        ct: &[Ciphertext],
        mat: &Zzlp25Material,
    ) -> (Zzlp25State, Round) {
        let l = self.l();
        let mut z = lwe::phase(ct, &mat.key, ctx.id(), ctx.key());
        ctx.add_scalar(&mut z, 1 << (l - 1));

        // LTRand, step 1: open z' = z + r mod 2^l.
        let mut round = Round::new();
        let h = ctx.open(&mut round, &z.add(&mat.r).reduce(l), &mat.r1);
        (Zzlp25State { z, z1: None, h }, round)
    }

    fn step(
        &self,
        ctx: &mut Ctx,
        st: Zzlp25State,
        round: Round,
        mat: &Zzlp25Material,
    ) -> Result<Step<Zzlp25State, Shared>, Abort> {
        let (k, d) = (self.lwe.k, self.d);
        let Zzlp25State { mut z, z1, h } = st;
        let batch = z.len();
        let mut idx = vec![0usize; batch];
        let Some(z1) = z1 else {
            let z1 = ctx.opened(&round, h);

            // Steps 2-4: ⟦y⟧_{d+1} = Σ_i 2^i ⟦Sign(z'_i - r_i)⟧_{d+1}.
            let mut y = Shared::new(d + 1, ctx.kappa(), vec![0; batch], vec![0; batch]);
            for i in 0..d {
                for j in 0..batch {
                    idx[j] = self.digit(z1[j], i);
                }
                y.add_scaled(&mat.sign[i as usize].select(&idx), 1 << i);
            }

            // Step 5: the ModLTZ gate: open y + r' mod 2^{d+1}, ...
            y.add_assign(&mat.r_ltz);
            let mut round = Round::new();
            let h = ctx.open(&mut round, &y, &mat.r2);
            let st = Zzlp25State { z, z1: Some(z1), h };
            return Ok(Step::Next(st, round));
        };

        // ... and look up ⟦u⟧_m.
        let y1 = ctx.opened(&round, h);
        for j in 0..batch {
            idx[j] = y1[j] as usize;
        }
        let u = mat.ltz.select(&idx);

        // Mod: ⟦e⟧_k = z' - ⟦r⟧_k + 2^l ⟦u⟧, the last term by lifting ⟦u⟧_m to 2^k.
        let mut e = u.lift(k);
        e.sub_assign(&mat.r);
        ctx.add_const(&mut e, &z1);
        z.sub_assign(&e);
        Ok(Step::Done(z))
    }

    fn decode(&self, v: &[u128]) -> Vec<u64> {
        v.iter().map(|&x| (x >> self.l()) as u64).collect()
    }
}

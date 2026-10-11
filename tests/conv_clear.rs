//! ModConv1/2 in the clear: correctness, and the boundary of each precondition. ZZLP25's `Mod`
//! via `LTRand` in the clear.

use modulus_operandi::conv::modconv12::{ModConvParams, Variant, precondition_bound};
use modulus_operandi::dec::lwe::LweParams;
use modulus_operandi::dec::zzlp25::Zzlp25;
use modulus_operandi::prg::{Part, Stream};
use modulus_operandi::ring::Ring;

fn params(variant: Variant, beta: u128, n: usize, q_bits: u32, t_bits: u32) -> ModConvParams {
    ModConvParams::new(variant, beta, n, q_bits, t_bits, 0).unwrap()
}

fn masks(p: &ModConvParams) -> usize {
    match p.variant {
        Variant::ModConv1 => 1,
        Variant::ModConv2 => p.n,
    }
}

/// Runs the conversion in the clear on `x` with the masks `ms`; true if it returns `x`.
fn converts(p: &ModConvParams, x: u128, ms: &[u128]) -> bool {
    let u = p.corrections(ms);
    let m: u128 = ms.iter().sum();
    let y = (x + m) % p.q();
    p.convert_clear(y, &u) == x
}

/// The largest `X` such that every `x <= X` converts correctly under every mask, by exhaustion.
fn true_threshold(p: &ModConvParams) -> u128 {
    let q = p.q();
    let count = masks(p) as u32;
    let mut first_fail = q;
    for idx in 0..q.pow(count) {
        let ms: Vec<u128> = (0..count).map(|j| idx / q.pow(j) % q).collect();
        let u = p.corrections(&ms);
        let m: u128 = ms.iter().sum();
        for x in 0..first_fail {
            if p.convert_clear((x + m) % q, &u) != x {
                first_fail = x;
                break;
            }
        }
    }
    first_fail - 1
}

#[test]
fn random_inputs_within_the_precondition() {
    let mut s = Stream::new(0, &[Part::S("conv")]);
    for (q_bits, t_bits) in [(8, 16), (20, 64), (63, 64), (100, 120)] {
        for n in [2, 3, 8] {
            for (variant, beta) in [
                (Variant::ModConv1, 2),
                (Variant::ModConv1, 7),
                (Variant::ModConv2, n as u128 + 1),
                (Variant::ModConv2, 2 * n as u128),
                (Variant::ModConv2, 64),
            ] {
                let p = params(variant, beta, n, q_bits, t_bits);
                let bound = precondition_bound(variant, beta, n, p.q()).unwrap();
                for _ in 0..300 {
                    let ms: Vec<u128> = (0..masks(&p)).map(|_| s.bits(q_bits)).collect();
                    let x = if s.bit() {
                        bound - s.below(4.min(bound + 1))
                    } else {
                        s.below(bound + 1)
                    };
                    assert!(
                        converts(&p, x, &ms),
                        "{variant:?} β={beta} n={n} x={x} masks={ms:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn modconv1_precondition_holds_and_is_sharp() {
    let q_bits = 6;
    for beta in 2..=64u128 {
        let p = params(Variant::ModConv1, beta, 2, q_bits, 9);
        let bound = precondition_bound(Variant::ModConv1, beta, 2, p.q()).unwrap();
        assert_eq!(true_threshold(&p), bound, "β = {beta}");
    }
    // An explicit failing input just beyond the bound at full size: m at the top of I_0.
    for beta in [2u128, 4, 5, 1 << 10] {
        let p = params(Variant::ModConv1, beta, 2, 63, 64);
        let bound = precondition_bound(Variant::ModConv1, beta, 2, p.q()).unwrap();
        let m = p.q().div_ceil(beta) - 1;
        assert!(converts(&p, bound, &[m]));
        assert!(!converts(&p, bound + 1, &[m]));
    }
}

#[test]
fn modconv2_precondition_holds_and_slack_is_below_n() {
    for (n, q_bits) in [(2usize, 5u32), (3, 4)] {
        let q = 1u128 << q_bits;
        for beta in (n as u128 + 1)..=q {
            let p = params(Variant::ModConv2, beta, n, q_bits, q_bits + 3);
            let bound = precondition_bound(Variant::ModConv2, beta, n, q).unwrap();
            let t = true_threshold(&p);
            assert!(
                t >= bound && t < bound + n as u128,
                "n={n} β={beta}: bound {bound}, true {t}"
            );
            if q.is_multiple_of(beta) {
                // With β | q, the true threshold is exactly q - N(q/β - 1) - 1.
                assert_eq!(t, bound + n as u128 - 1, "n={n} β={beta}");
            }
        }
    }
    // Explicit failing input at full size with β | q: every m^σ at the top of I_0, and
    // x = q - N(q/β - 1), i.e. N - 1 beyond the precondition's bound plus one.
    for n in [2usize, 3, 8] {
        for beta in [2 * n as u128, 1 << 10] {
            let beta = beta.next_power_of_two();
            let p = params(Variant::ModConv2, beta, n, 63, 64);
            let bound = precondition_bound(Variant::ModConv2, beta, n, p.q()).unwrap();
            let ms = vec![p.q() / beta - 1; n];
            assert!(converts(&p, bound + n as u128 - 1, &ms));
            assert!(!converts(&p, bound + n as u128, &ms));
        }
    }
}

#[test]
fn construction_checks_beta() {
    let max_x = (1u128 << 62) - 1; // ν = l - 2 with l = 63
    assert!(ModConvParams::new(Variant::ModConv1, 1, 3, 63, 64, 0).is_err());
    assert!(ModConvParams::new(Variant::ModConv1, 2, 3, 63, 64, max_x).is_ok());
    assert!(ModConvParams::new(Variant::ModConv1, 2, 3, 63, 64, max_x + 1).is_ok());
    assert!(ModConvParams::new(Variant::ModConv1, 2, 3, 63, 64, (1 << 62) + 1).is_err());
    assert!(ModConvParams::new(Variant::ModConv2, 3, 3, 63, 64, 0).is_err());
    assert!(ModConvParams::new(Variant::ModConv2, 4, 3, 63, 64, 0).is_ok());
    assert!(ModConvParams::new(Variant::ModConv2, 4, 3, 63, 64, max_x).is_err());
    assert!(ModConvParams::new(Variant::ModConv2, 6, 3, 63, 64, max_x).is_ok());
    assert!(ModConvParams::new(Variant::ModConv1, 65, 3, 6, 64, 0).is_err());
    for n in [2usize, 3, 4, 5, 8] {
        assert_eq!(
            ModConvParams::smallest_beta(Variant::ModConv1, n, 63, 64, max_x),
            Ok(2)
        );
        let b2 = ModConvParams::smallest_beta(Variant::ModConv2, n, 63, 64, max_x).unwrap();
        assert_eq!(b2, (2 * n as u128).next_power_of_two());
    }
}

fn zzlp25(k: u32, m: u32, b: u32) -> Zzlp25 {
    let l = k - m;
    Zzlp25::new(LweParams::new(k, m, 1, l - 1).unwrap(), b).unwrap()
}

/// `LTRand` and `Mod` in the clear on `z` and the mask `r`: `u = (z' < r)` and `e = z mod 2^l`.
fn check_mod(p: &Zzlp25, z: u128, r: u128) {
    let l = p.l();
    let z1 = (z + r) % (1 << l);
    assert_eq!(p.lt_clear(z1, r), (z1 < r) as u128, "{p:?} z'={z1} r={r}");
    assert_eq!(p.mod_clear(z, r), z % (1 << l), "{p:?} z={z} r={r}");
}

#[test]
fn zzlp25_mod_exhaustively_at_small_k() {
    let mut partial_top_digit = false;
    for (k, m) in [(4, 1), (6, 1), (6, 3), (8, 1), (8, 3), (10, 2)] {
        for b in [1, 2, 3, 8] {
            let p = zzlp25(k, m, b);
            let l = k - m;
            assert_eq!(p.d, l.div_ceil(b));
            assert_eq!(p.b_top, l - (p.d - 1) * b);
            partial_top_digit |= p.b_top < b && p.d > 1;
            for z in 0..1u128 << k {
                for r in 0..1u128 << l {
                    check_mod(&p, z, r);
                }
            }
        }
    }
    assert!(partial_top_digit);
}

#[test]
fn zzlp25_mod_on_random_inputs() {
    let mut s = Stream::new(0, &[Part::S("zzlp25")]);
    let p = zzlp25(64, 1, 8);
    assert_eq!((p.d, p.b_top), (8, 7));
    for (k, m, b) in [
        (64, 1, 8),
        (64, 1, 3),
        (64, 1, 5),
        (64, 8, 8),
        (64, 8, 4),
        (40, 3, 7),
    ] {
        let p = zzlp25(k, m, b);
        let l = k - m;
        for _ in 0..20_000 {
            let z = s.bits(k);
            let r = s.bits(l);
            check_mod(&p, z, r);
            // z' = r, r - 1 and r + 1, and the extreme masks.
            let lr = Ring::new(l);
            for z1 in [r, lr.sub(r, 1), lr.add(r, 1)] {
                check_mod(&p, lr.sub(z1, r) | (z >> l << l), r);
            }
            check_mod(&p, z, 0);
            check_mod(&p, z, lr.neg(1));
        }
    }
}

#[test]
fn zzlp25_construction_checks_parameters() {
    let lwe = LweParams::new(64, 1, 1, 62).unwrap();
    assert!(Zzlp25::new(lwe, 0).is_err());
    // l = 63: b = 2 needs a ModLTZ table of 2^33 entries.
    assert!(Zzlp25::new(lwe, 2).is_err());
    assert!(Zzlp25::new(lwe, 3).is_ok());
    // b > l: a single digit of l bits.
    let p = Zzlp25::new(LweParams::new(8, 3, 1, 4).unwrap(), 9).unwrap();
    assert_eq!((p.d, p.b_top), (1, 5));
    // A digit table of 2^25 entries.
    assert!(Zzlp25::new(LweParams::new(64, 30, 1, 30).unwrap(), 25).is_err());
}

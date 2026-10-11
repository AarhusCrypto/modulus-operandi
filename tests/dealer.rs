#![allow(clippy::needless_range_loop)]

use modulus_operandi::abb::Shared;
use modulus_operandi::conv::modconv12::Variant;
use modulus_operandi::dec::lwe::{LweParams, phase_clear};
use modulus_operandi::dec::modconv::ModConvDecryption;
use modulus_operandi::dec::zzlp25::Zzlp25;
use modulus_operandi::prep::{Dealer, deal, deal_instances};
use modulus_operandi::ring::Ring;

/// Reconstructs the values `x̂` from all parties' sharings and checks `Σ mac ≡ Δ · Σ val`.
fn open(parts: &[&Shared], delta: u128) -> Vec<u128> {
    let r = parts[0].ring();
    let mut out = Vec::new();
    for i in 0..parts[0].len() {
        let (mut v, mut m) = (0, 0);
        for p in parts {
            assert_eq!((p.k, p.kappa), (parts[0].k, parts[0].kappa));
            v = r.add(v, p.val[i]);
            m = r.add(m, p.mac[i]);
        }
        assert_eq!(m, r.mul(delta, v), "MAC identity fails at entry {i}");
        out.push(v);
    }
    out
}

fn check_dealing(variant: Variant, n: usize, kappa: u32) {
    let lwe = LweParams::new(64, 2, 32, 10).unwrap();
    let dec = ModConvDecryption::modconv12(lwe, variant, None, n).unwrap();
    let batch = 5;
    let mut dealers: Vec<Dealer> = (0..n).map(|id| Dealer::new(42, n, id, kappa)).collect();
    let delta = dealers[0].delta();
    // Δ is the sum of the κ-bit key shares in the integers.
    let key_sum = dealers
        .iter()
        .fold(0u128, |a, d| a.wrapping_add(d.key_share()));
    assert_eq!(key_sum, delta);
    assert!(
        dealers
            .iter()
            .all(|d| d.key_share() == Ring::new(kappa).mask(d.key_share()))
    );
    let mats: Vec<_> = dealers
        .iter_mut()
        .map(|d| deal(d, &dec, &lwe, batch))
        .collect();
    for m in &mats[1..] {
        assert_eq!(m.ct, mats[0].ct);
        assert_eq!(m.expected, mats[0].expected);
    }

    // The key sharing reconstructs to a key under which the ciphertexts decrypt.
    let key: Vec<u64> = open(&mats.iter().map(|m| &m.dec.key).collect::<Vec<_>>(), delta)
        .iter()
        .map(|&x| Ring::new(lwe.k).mask(x) as u64)
        .collect();
    for (ct, &mu) in mats[0].ct.iter().zip(&mats[0].expected) {
        let rounded = (phase_clear(&lwe, ct, &key) + (1 << (lwe.l() - 1))) >> lwe.l();
        assert_eq!(Ring::new(lwe.m).mask(rounded), mu as u128);
    }

    // Corrections: u_i = m - c_i q mod t with one m per decryption and c_i non-increasing in i,
    // so u_i - u_0 = (c_0 - c_i) q with c_0 - c_i non-decreasing and at most N.
    let p = dec.conv;
    let t = Ring::new(p.t_bits);
    let us: Vec<Vec<u128>> = (0..p.beta as usize)
        .map(|i| {
            let cols: Vec<Shared> = mats
                .iter()
                .map(|m| m.dec.conv.corrections.column(i))
                .collect();
            open(&cols.iter().collect::<Vec<_>>(), delta)
                .iter()
                .map(|&x| t.mask(x))
                .collect()
        })
        .collect();
    for d in 0..batch {
        let mut prev = 0;
        for u in &us {
            let diff = t.sub(u[d], us[0][d]);
            assert_eq!(diff % p.q(), 0);
            let c = diff / p.q();
            assert!(c >= prev && c <= n as u128);
            prev = c;
        }
    }

    // Extra masks have k = 0, and the pad's one-time MAC is γŵ.
    let r1: Vec<&Shared> = mats.iter().map(|m| &m.dec.conv.r1).collect();
    let r0: Vec<&Shared> = mats.iter().map(|m| &m.open.r0).collect();
    for parts in [r1, r0] {
        assert_eq!(parts[0].k, 0);
        open(&parts, delta);
    }
    let w_hat = open(&mats.iter().map(|m| &m.open.w).collect::<Vec<_>>(), delta);
    let r = Ring::new(lwe.k + kappa);
    let gamma = mats.iter().fold(0, |a, m| r.add(a, m.open.gamma));
    for d in 0..batch {
        let gw = mats.iter().fold(0, |a, m| r.add(a, m.open.gamma_w[d]));
        assert_eq!(gw, r.mul(gamma, w_hat[d]));
    }

    // add_const keeps the MAC identity, which needs Δ = Σ ⟨Δ⟩^σ in the integers.
    let c: Vec<u128> = (0..batch as u128).map(|i| (i << 60) | 0xabcdef).collect();
    let added: Vec<Shared> = mats
        .iter()
        .zip(&dealers)
        .enumerate()
        .map(|(id, (m, d))| m.open.w.add_const(&c, id, d.key_share()))
        .collect();
    let vals = open(&added.iter().collect::<Vec<_>>(), delta);
    for d in 0..batch {
        assert_eq!(vals[d], r.add(w_hat[d], Ring::new(lwe.k).mask(c[d])));
    }

    // lift and reduce keep the MAC identity and act on the values as expected.
    let w: Vec<&Shared> = mats.iter().map(|m| &m.open.w).collect();
    for k2 in [0, 1, lwe.l(), lwe.k] {
        let red: Vec<Shared> = w.iter().map(|s| s.reduce(k2)).collect();
        let vals = open(&red.iter().collect::<Vec<_>>(), delta);
        for d in 0..batch {
            assert_eq!(vals[d], Ring::new(k2 + kappa).mask(w_hat[d]));
        }
        let back: Vec<Shared> = red.iter().map(|s| s.lift(lwe.k)).collect();
        let lifted = open(&back.iter().collect::<Vec<_>>(), delta);
        for d in 0..batch {
            let x = Ring::new(k2).mask(w_hat[d]);
            assert_eq!(
                Ring::new(lwe.k).mask(lifted[d]),
                Ring::new(lwe.k).mask(x << (lwe.k - k2))
            );
        }
    }
    let r1: Vec<Shared> = mats.iter().map(|m| m.dec.conv.r1.lift(lwe.l())).collect();
    let lifted = open(&r1.iter().collect::<Vec<_>>(), delta);
    assert!(lifted.iter().all(|&x| Ring::new(lwe.l()).mask(x) == 0));
}

#[test]
fn dealt_sharings_reconstruct_and_carry_macs() {
    for n in [2, 3, 5] {
        for kappa in [64, 40, 16] {
            check_dealing(Variant::ModConv1, n, kappa);
            check_dealing(Variant::ModConv2, n, kappa);
        }
    }
}

#[test]
fn dealing_differs_per_party_and_instances_get_equal_copies() {
    let lwe = LweParams::new(64, 1, 16, 10).unwrap();
    let dec = ModConvDecryption::modconv12(lwe, Variant::ModConv2, None, 3).unwrap();
    let mut d0 = Dealer::new(1, 3, 0, 64);
    let mut d1 = Dealer::new(1, 3, 1, 64);
    let a = deal(&mut d0, &dec, &lwe, 4);
    let b = deal(&mut d1, &dec, &lwe, 4);
    assert_ne!(a.open.w.val, b.open.w.val);
    // Every instance gets the same material, γ included, each in allocations of its own.
    let mats = deal_instances(&mut d0, &dec, &lwe, 3, 4);
    assert_eq!(mats.len(), 3);
    for (i, x) in mats.iter().enumerate() {
        for y in &mats[i + 1..] {
            assert_eq!(x.ct, y.ct);
            assert_eq!(x.expected, y.expected);
            assert_eq!(x.dec.key, y.dec.key);
            assert_eq!(x.dec.conv.corrections, y.dec.conv.corrections);
            assert_eq!(x.dec.conv.r1, y.dec.conv.r1);
            assert_eq!((&x.open.r0, &x.open.w), (&y.open.r0, &y.open.w));
            assert_eq!(x.open.gamma_w, y.open.gamma_w);
            assert_eq!(x.open.gamma, y.open.gamma);
            assert_ne!(x.ct.as_ptr(), y.ct.as_ptr());
            assert_ne!(x.ct[0].a.as_ptr(), y.ct[0].a.as_ptr());
            assert_ne!(x.dec.key.val.as_ptr(), y.dec.key.val.as_ptr());
            assert_ne!(x.open.w.val.as_ptr(), y.open.w.val.as_ptr());
            assert_ne!(x.open.gamma_w.as_ptr(), y.open.gamma_w.as_ptr());
        }
    }
    assert_eq!(mats[0].ct, a.ct);
}

fn check_zzlp25_dealing(n: usize, kappa: u32, lwe: LweParams, b: u32) {
    let p = Zzlp25::new(lwe, b).unwrap();
    let (k, m, l, d) = (lwe.k, lwe.m, lwe.l(), p.d);
    let batch = 4;
    let mut dealers: Vec<Dealer> = (0..n).map(|id| Dealer::new(5, n, id, kappa)).collect();
    let delta = dealers[0].delta();
    let mats: Vec<_> = dealers
        .iter_mut()
        .map(|dl| deal(dl, &p, &lwe, batch))
        .collect();
    let open_mod = |parts: Vec<&Shared>, bits: u32| -> Vec<u128> {
        assert_eq!(parts[0].k, bits);
        open(&parts, delta)
            .iter()
            .map(|&x| Ring::new(bits).mask(x))
            .collect()
    };

    // The masks: r ∈ [2^l] over 2^k, r' over 2^{d+1}.
    let r = open_mod(mats.iter().map(|x| &x.dec.r).collect(), k);
    assert!(r.iter().all(|&x| x >> l == 0));
    let r_ltz = open_mod(mats.iter().map(|x| &x.dec.r_ltz).collect(), d + 1);

    // Sign tables: 2^b entries (2^{b'} for the top digit) of Sign(x - r_i) mod 2^{d+1}.
    assert_eq!(mats[0].dec.sign.len(), d as usize);
    let top = Ring::new(d + 1).neg(1);
    for i in 0..d {
        let table = &mats[0].dec.sign[i as usize];
        assert_eq!(table.width(), 1 << p.digit_bits(i));
        for x in 0..table.width() {
            let cols: Vec<Shared> = mats
                .iter()
                .map(|mt| mt.dec.sign[i as usize].column(x))
                .collect();
            let vals = open_mod(cols.iter().collect(), d + 1);
            for j in 0..batch {
                let ri = p.digit(r[j], i);
                let want = match x.cmp(&ri) {
                    std::cmp::Ordering::Less => top,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                assert_eq!(vals[j], want, "digit {i}, entry {x}, decryption {j}");
            }
        }
    }

    // The ModLTZ table: 2^{d+1} entries of ModLTZ_{d+1}(x - r') mod 2^m.
    assert_eq!(mats[0].dec.ltz.width(), 1 << (d + 1));
    for x in 0..1u128 << (d + 1) {
        let cols: Vec<Shared> = mats
            .iter()
            .map(|mt| mt.dec.ltz.column(x as usize))
            .collect();
        let vals = open_mod(cols.iter().collect(), m);
        for j in 0..batch {
            let diff = Ring::new(d + 1).sub(x, r_ltz[j]);
            assert_eq!(vals[j], (diff >= 1 << d) as u128);
        }
        // Lifted to 2^k it is 2^l u, with the MAC identity intact.
        let lifted: Vec<Shared> = mats
            .iter()
            .map(|mt| mt.dec.ltz.column(x as usize).lift(k))
            .collect();
        let lv = open_mod(lifted.iter().collect(), k);
        for j in 0..batch {
            assert_eq!(lv[j], vals[j] << l);
        }
    }

    // Two extra masks of Π, with k = 0.
    for parts in [
        mats.iter().map(|x| &x.dec.r1).collect::<Vec<_>>(),
        mats.iter().map(|x| &x.dec.r2).collect(),
    ] {
        assert_eq!((parts[0].k, parts[0].len()), (0, batch));
        open(&parts, delta);
    }
}

#[test]
fn zzlp25_tables_reconstruct_and_carry_macs() {
    for n in [2, 3, 5] {
        for kappa in [64, 40] {
            // l = 7 in digits of 3, 3, 1 bits; l = 7 in one digit; m = 4 for a wider ModLTZ output.
            check_zzlp25_dealing(n, kappa, LweParams::new(8, 1, 8, 5).unwrap(), 3);
            check_zzlp25_dealing(n, kappa, LweParams::new(8, 1, 8, 5).unwrap(), 8);
            check_zzlp25_dealing(n, kappa, LweParams::new(16, 4, 8, 10).unwrap(), 4);
        }
    }
    // The default parameters: k = 64, m = 1, b = 8, so d = 8 and b' = 7.
    check_zzlp25_dealing(3, 64, LweParams::new(64, 1, 8, 61).unwrap(), 8);
}

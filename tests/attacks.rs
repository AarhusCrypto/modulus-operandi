//! One corrupted party deviates; every honest party must abort or output the correct plaintexts.
//!
//! With one repetition, rounds 0 to `B - 1` are the barrier (`B = BARRIER_ROUNDS`) and the timed
//! rounds follow. Π takes rounds `B` to `B + ℓ - 1`, one opening each (`ℓ = 1` for ModConv1/2: `y`;
//! `ℓ = 2` for ZZLP25: `z'`, then `y + r'`), and `dec::convopen` lays out the three rounds after
//! them as:
//! - round `B + ℓ`: `[v + w, commitment]`, committing to `(z_1, …, z_ℓ)`;
//! - round `B + ℓ + 1`: `[z_1, …, z_ℓ, ρ, commitment]`, committing to `(z_{v+w}, ŵ, γŵ, γ)`;
//! - round `B + ℓ + 2`: `[z_{v+w}, ŵ, γŵ, γ, ρ]`.

mod common;

use std::ops::Range;

use common::{bytes_for, config};
use modulus_operandi::abb::{Section, Site, Tamper};
use modulus_operandi::conv::modconv12::Variant;
use modulus_operandi::dec::modconv::ModConvDecryption;
use modulus_operandi::dec::zzlp25::Zzlp25;
use modulus_operandi::net::Abort;
use modulus_operandi::ring::Ring;
use modulus_operandi::run::{
    BARRIER_ROUNDS, Config, Faults, RepResult, run_local_released, run_local_with,
};

const CORRUPT: usize = 1;

#[derive(Clone, Copy, Debug)]
enum Proto {
    ModConv1,
    ModConv2,
    Zzlp25,
}

const PROTOS: [Proto; 3] = [Proto::ModConv1, Proto::ModConv2, Proto::Zzlp25];

impl Proto {
    /// The moduli bits `k'` of Π's openings, in order.
    fn openings(self) -> Vec<u32> {
        match self {
            Proto::ModConv1 | Proto::ModConv2 => vec![l()],
            Proto::Zzlp25 => vec![l(), zzlp25().d + 1],
        }
    }

    /// `ℓ`, the number of Π's openings.
    fn ell(self) -> u32 {
        self.openings().len() as u32
    }

    /// The exchange of `convopen`'s step `s ∈ {2, 3, 4}`.
    fn step(self, s: u32) -> u32 {
        BARRIER_ROUNDS + self.ell() + s - 2
    }
}

/// The exchange of Π's opening `j ∈ 1..=ℓ`.
fn opening(j: u32) -> u32 {
    BARRIER_ROUNDS + j - 1
}

fn cfg() -> Config {
    config(3, 3, 1)
}

fn zzlp25() -> Zzlp25 {
    Zzlp25::new(cfg().lwe, 8).unwrap()
}

/// Runs one batch with `faults`; the honest parties' outcomes.
fn honest(p: Proto, faults: Faults) -> Vec<Result<RepResult, Abort>> {
    let cfg = cfg();
    let res = match p {
        Proto::ModConv1 | Proto::ModConv2 => {
            let variant = match p {
                Proto::ModConv1 => Variant::ModConv1,
                _ => Variant::ModConv2,
            };
            let dec = ModConvDecryption::modconv12(cfg.lwe, variant, None, cfg.n).unwrap();
            run_local_with(&dec, &cfg, faults)
        }
        Proto::Zzlp25 => run_local_with(&zzlp25(), &cfg, faults),
    };
    res.into_iter()
        .enumerate()
        .filter(|&(i, _)| i != CORRUPT)
        .map(|(_, r)| r.map(|mut reps| reps.remove(0)))
        .collect()
}

fn corrupt(tamper: Tamper) -> Faults {
    let mut tampers: Vec<Option<Tamper>> = (0..cfg().n).map(|_| None).collect();
    tampers[CORRUPT] = Some(tamper);
    Faults {
        tampers,
        ..Faults::default()
    }
}

/// Every honest party aborts or outputs the correct plaintexts; returns the aborts.
fn assert_safe(p: Proto, faults: Faults) -> Vec<Abort> {
    let mut aborts = Vec::new();
    for r in honest(p, faults) {
        match r {
            Ok(r) => assert!(r.plaintexts_ok, "{p:?}: wrong plaintexts {r:?}"),
            Err(e) => aborts.push(e),
        }
    }
    aborts
}

/// Every honest party aborts with a reason containing `reason`.
fn assert_aborts(p: Proto, faults: Faults, reason: &str) {
    let aborts = assert_safe(p, faults);
    assert_eq!(
        aborts.len(),
        cfg().n - 1,
        "{p:?}: an honest party did not abort"
    );
    for e in aborts {
        assert!(e.0.contains(reason), "{p:?}: expected {reason:?}, got {e}");
    }
}

/// Adds `delta` to every element of a ring section, at `(round, section)` of the sent sections or,
/// with `commit`, of the committed tuple; to every peer, or only to `to`.
fn add(round: u32, section: usize, commit: bool, to: Option<usize>, delta: u128) -> Tamper {
    Box::new(move |at: &Site, sec: &mut Section| {
        if at.round == round
            && at.section == section
            && at.commit == commit
            && to.is_none_or(|p| p == at.peer)
            && let Section::Ring { bits, vals } = sec
        {
            let r = Ring::new(*bits);
            for v in vals.iter_mut() {
                *v = r.add(*v, delta);
            }
        }
    })
}

/// Flips a bit of a byte section (a commitment or `ρ`).
fn flip(round: u32, section: usize) -> Tamper {
    Box::new(move |at: &Site, sec: &mut Section| {
        if at.round == round
            && at.section == section
            && !at.commit
            && let Section::Bytes(b) = sec
        {
            b[0] ^= 1;
        }
    })
}

/// A rushing party that sends, in each `(round, sections)`, what party `from` sent in them.
fn copy(from: usize, what: Vec<(u32, Range<usize>)>) -> Faults {
    let tamper: Tamper = Box::new(move |at: &Site, sec: &mut Section| {
        if at.commit {
            return;
        }
        for (round, sections) in &what {
            if at.round == *round && sections.contains(&at.section) {
                let received = at.received.expect("the copier is rushing");
                *sec = received.received(from, at.section).clone();
            }
        }
    });
    let mut faults = corrupt(tamper);
    faults.rushing = Some(CORRUPT);
    faults
}

fn l() -> u32 {
    cfg().lwe.l()
}

fn k() -> u32 {
    cfg().lwe.k
}

/// A reveal that does not open the commitment of `convopen`'s step `s ∈ {2, 3}`.
fn bad_reveal(p: Proto, s: u32) -> String {
    format!(
        "round {}: party 1's reveal does not open its commitment of round {}",
        p.step(s + 1),
        p.step(s)
    )
}

fn mac_fails(round: u32) -> String {
    format!("round {round}: MAC check failed")
}

const GAMMA_FAILS: &str = "one-time MAC check on w failed";

#[test]
fn honest_run() {
    let cfg = cfg();
    for p in PROTOS {
        for r in honest(p, Faults::default()) {
            let r = r.unwrap();
            assert!(r.plaintexts_ok);
            assert_eq!(r.rounds, p.ell() + 3);
            assert_eq!(r.bytes_sent, bytes_for(&cfg, &p.openings()));
        }
    }
    // With κ = 64, k = 64 and l = 63: 96 bytes per decryption and peer for ModConv1/2, 116 for
    // ZZLP25 (d + 1 = 9), and 144 per batch and peer.
    assert_eq!(bytes_for(&cfg, &[l()]), ((96 * 3 + 144) * 2) as u64);
    assert_eq!(bytes_for(&cfg, &[l(), 9]), ((116 * 3 + 144) * 2) as u64);
}

#[test]
fn error_on_an_opening_of_pi_aborts_before_w_is_opened() {
    assert_eq!((Proto::ModConv1.step(3), Proto::Zzlp25.step(3)), (4, 5));
    for p in PROTOS {
        // Opening j of Π is section 0 of its round; the MAC check on Π's openings is one round
        // after the opening of v + w, i.e. in round B + ℓ + 1 (4 for ModConv1/2, 5 for ZZLP25).
        for j in 1..=p.ell() {
            let tamper = corrupt(add(opening(j), 0, false, None, 1));
            assert_aborts(p, tamper, &mac_fails(p.step(3)));
        }
    }
}

#[test]
fn error_on_v_plus_w_aborts() {
    for p in PROTOS {
        let tamper = corrupt(add(p.step(2), 0, false, None, 1));
        assert_aborts(p, tamper, &mac_fails(p.step(4)));
    }
}

#[test]
fn error_on_a_check_share_aborts() {
    for p in PROTOS {
        // Committed and revealed consistently, so only the MAC check can catch it.
        for j in 0..p.ell() as usize {
            let tamper = corrupt(add(p.step(2), j, true, None, 1));
            assert_aborts(p, tamper, &mac_fails(p.step(3)));
        }
        let tamper = corrupt(add(p.step(3), 0, true, None, 1));
        assert_aborts(p, tamper, &mac_fails(p.step(4)));
    }
}

#[test]
fn wrong_rho_aborts() {
    for p in PROTOS {
        let ell = p.ell() as usize;
        assert_aborts(p, corrupt(flip(p.step(3), ell)), &bad_reveal(p, 2));
        assert_aborts(p, corrupt(flip(p.step(4), 4)), &bad_reveal(p, 3));
    }
}

#[test]
fn reveal_inconsistent_with_the_commitment_aborts() {
    for p in PROTOS {
        for s in 0..p.ell() as usize {
            let tamper = corrupt(add(p.step(3), s, false, None, 1));
            assert_aborts(p, tamper, &bad_reveal(p, 2));
        }
        for s in 0..4 {
            let tamper = corrupt(add(p.step(4), s, false, None, 1));
            assert_aborts(p, tamper, &bad_reveal(p, 3));
        }
    }
}

#[test]
fn copied_commitment_aborts() {
    for p in PROTOS {
        let ell = p.ell() as usize;
        // Party 1 rushes, copies party 2's commitment and then party 2's reveal (a, ρ).
        let faults = copy(2, vec![(p.step(3), ell + 1..ell + 2), (p.step(4), 0..5)]);
        assert_aborts(p, faults, &bad_reveal(p, 3));
        let faults = copy(2, vec![(p.step(2), 1..2), (p.step(3), 0..ell + 1)]);
        assert_aborts(p, faults, &bad_reveal(p, 2));
    }
}

#[test]
fn different_shares_to_different_peers_abort() {
    for p in PROTOS {
        for j in 1..=p.ell() {
            let tamper = corrupt(add(opening(j), 0, false, Some(2), 1));
            assert_aborts(p, tamper, &mac_fails(p.step(3)));
        }
        let tamper = corrupt(add(p.step(2), 0, false, Some(2), 1));
        assert_aborts(p, tamper, &mac_fails(p.step(4)));
        // A different ŵ committed to and revealed to party 2 only: party 2 aborts, while party 0,
        // which saw the honest ŵ, may output (no broadcast, so the abort need not be unanimous).
        let res = honest(p, corrupt(add(p.step(3), 1, true, Some(2), 1 << l())));
        assert!(res[0].as_ref().unwrap().plaintexts_ok);
        let e = res[1].as_ref().unwrap_err();
        let reason = format!("round {}: {GAMMA_FAILS}", p.step(4));
        assert!(e.0.contains(&reason), "{e}");
    }
}

#[test]
fn error_zero_mod_the_opening_modulus_aborts_or_is_harmless() {
    for p in PROTOS {
        // Π's openings are mod 2^{k'}, v + w mod 2^k; the checks sum to Δ · 2^{k'} mod 2^{k'+κ}.
        for (j, kj) in p.openings().into_iter().enumerate() {
            let tamper = corrupt(add(opening(j as u32 + 1), 0, false, None, 1 << kj));
            let aborts = assert_safe(p, tamper);
            assert_eq!(aborts.len(), 2);
        }
        let aborts = assert_safe(p, corrupt(add(p.step(2), 0, false, None, 1 << k())));
        assert_eq!(aborts.len(), 2);
    }
}

#[test]
fn attack_on_w_aborts_on_the_gamma_check() {
    for p in PROTOS {
        // Commit to ⟨ŵ⟩ + 2^l and reveal it consistently; v + w was opened with ⟨ŵ⟩.
        let reason = format!("round {}: {GAMMA_FAILS}", p.step(4));
        assert_aborts(p, corrupt(add(p.step(3), 1, true, None, 1 << l())), &reason);
    }
}

#[test]
fn attack_on_w_succeeds_without_the_gamma_check() {
    let m = cfg().lwe.m;
    for p in PROTOS {
        // The pipelining of ZZLP25 as described: the honest parties output v - 2^l, i.e. the
        // plaintexts minus one, and do not abort.
        let mut faults = corrupt(add(p.step(3), 1, true, None, 1 << l()));
        faults.skip_gamma_check = true;
        for r in honest(p, faults) {
            let r = r.expect("no abort without the γ check");
            let shifted: Vec<u64> = r
                .expected
                .iter()
                .map(|&mu| (mu + (1 << m) - 1) % (1 << m))
                .collect();
            assert_eq!(r.plaintexts, shifted);
            assert_ne!(r.plaintexts, r.expected);
        }
    }
}

#[test]
fn error_on_gamma_w_or_gamma_aborts() {
    for p in PROTOS {
        let reason = format!("round {}: {GAMMA_FAILS}", p.step(4));
        assert_aborts(p, corrupt(add(p.step(3), 2, true, None, 1)), &reason);
        assert_aborts(p, corrupt(add(p.step(3), 3, true, None, 1)), &reason);
    }
}

/// Two instances in flight, the corrupted party's tamper hook in `faults` acting on instance 1
/// only: every honest party aborts with a reason containing `reason`, naming instance 1, and the
/// plaintexts it output before, which are instance 0's and only those, are correct. Returns how
/// many honest parties output them.
fn assert_aborts_in_instance_1(p: Proto, mut faults: Faults, reason: &str) -> usize {
    let mut cfg = cfg();
    cfg.instances = 2;
    let mut tamper = faults.tampers[CORRUPT].take().expect("a tamper hook");
    faults.tampers[CORRUPT] = Some(Box::new(move |at: &Site, sec: &mut Section| {
        if at.instance == 1 {
            tamper(at, sec);
        }
    }));
    let res = match p {
        Proto::ModConv1 | Proto::ModConv2 => {
            let variant = match p {
                Proto::ModConv1 => Variant::ModConv1,
                _ => Variant::ModConv2,
            };
            let dec = ModConvDecryption::modconv12(cfg.lwe, variant, None, cfg.n).unwrap();
            run_local_released(&dec, &cfg, faults)
        }
        Proto::Zzlp25 => run_local_released(&zzlp25(), &cfg, faults),
    };
    let mut released = 0;
    for (i, (res, out)) in res.into_iter().enumerate() {
        if i == CORRUPT {
            continue;
        }
        let e = res.expect_err("an honest party did not abort");
        assert!(e.0.contains(reason), "{p:?}: expected {reason:?}, got {e}");
        assert!(e.0.contains("instance 1"), "{p:?}: {e}");
        for r in &out {
            assert_eq!(r.instance, 0, "{p:?}: instance 1 output");
            assert_eq!(r.plaintexts, r.expected, "{p:?}: wrong plaintexts");
        }
        released += out.len();
    }
    released
}

#[test]
fn attacks_on_one_of_two_instances_abort_and_leave_the_other_correct() {
    let honest = cfg().n - 1;
    for p in PROTOS {
        // Caught in round B + ℓ + 1, before instance 0 outputs.
        for j in 1..=p.ell() {
            let faults = corrupt(add(opening(j), 0, false, None, 1));
            assert_eq!(
                assert_aborts_in_instance_1(p, faults, &mac_fails(p.step(3))),
                0
            );
        }
        // Caught in the last round, after instance 0 has output in it.
        let faults = corrupt(add(p.step(2), 0, false, None, 1));
        let out = assert_aborts_in_instance_1(p, faults, &mac_fails(p.step(4)));
        assert_eq!(out, honest);
        let reason = format!("round {}: {GAMMA_FAILS}", p.step(4));
        let faults = corrupt(add(p.step(3), 1, true, None, 1 << l()));
        assert_eq!(assert_aborts_in_instance_1(p, faults, &reason), honest);
        let faults = corrupt(flip(p.step(4), 4));
        let out = assert_aborts_in_instance_1(p, faults, &bad_reveal(p, 3));
        assert_eq!(out, honest);
        // A rushing party copies party 2's commitment and reveal, in instance 1 only.
        let ell = p.ell() as usize;
        let faults = copy(2, vec![(p.step(3), ell + 1..ell + 2), (p.step(4), 0..5)]);
        let out = assert_aborts_in_instance_1(p, faults, &bad_reveal(p, 3));
        assert_eq!(out, honest);
    }
}

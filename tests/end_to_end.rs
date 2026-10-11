//! All parties as threads over `net::mem`.

mod common;

use std::time::Duration;

use common::{config, expected_bytes, expected_bytes_zzlp25};
use modulus_operandi::abb::{Section, Site, Tamper};
use modulus_operandi::conv::modconv12::Variant;
use modulus_operandi::dec::lwe::LweParams;
use modulus_operandi::dec::modconv::ModConvDecryption;
use modulus_operandi::dec::zzlp25::Zzlp25;
use modulus_operandi::run::{BARRIER_ROUNDS, Faults, run_local, run_local_with};

fn tampered(tampers: Vec<Option<Tamper>>) -> Faults {
    Faults {
        tampers,
        ..Faults::default()
    }
}

#[test]
fn modconv1_and_modconv2_decrypt_in_four_rounds() {
    for variant in [Variant::ModConv1, Variant::ModConv2] {
        for n in [2, 3, 4, 8] {
            for batch in [1, 7, 100] {
                let cfg = config(n, batch, 2);
                let dec = ModConvDecryption::modconv12(cfg.lwe, variant, None, n).unwrap();
                let res = run_local(&dec, &cfg).unwrap();
                assert_eq!(res.len(), 2 * n);
                for r in res {
                    assert!(
                        r.plaintexts_ok,
                        "{variant:?} n={n} batch={batch}: wrong plaintexts"
                    );
                    assert_eq!(r.rounds, 4);
                    assert_eq!(r.bytes_sent, expected_bytes(&cfg));
                }
            }
        }
    }
}

#[test]
fn zzlp25_decrypts_in_five_rounds() {
    for n in [2, 3, 4, 8] {
        for batch in [1, 7, 100] {
            let cfg = config(n, batch, 1);
            let dec = Zzlp25::new(cfg.lwe, 8).unwrap();
            assert_eq!(dec.d, 8);
            for r in run_local(&dec, &cfg).unwrap() {
                assert!(r.plaintexts_ok, "n={n} batch={batch}: wrong plaintexts");
                assert_eq!(r.rounds, 5);
                assert_eq!(r.bytes_sent, expected_bytes_zzlp25(&cfg, dec.d));
            }
        }
    }
    // At the defaults: 116 bytes per decryption and peer, 144 per batch and peer.
    let cfg = config(3, 7, 1);
    assert_eq!(expected_bytes_zzlp25(&cfg, 8), ((116 * 7 + 144) * 2) as u64);
}

#[test]
fn zzlp25_other_parameters_decrypt() {
    // m = 8 (d = 7, b' = 8); b = 4 (d = 16, b' = 3); m = 8, b = 5 (d = 12, b' = 1); and the
    // largest noise ZZLP25 allows, ν = l - 1.
    for (m, b, nu, batch) in [(8, 8, 54, 20), (1, 4, 61, 3), (8, 5, 54, 5), (1, 8, 62, 20)] {
        let mut cfg = config(3, batch, 2);
        cfg.lwe = LweParams::new(64, m, 64, nu).unwrap();
        let dec = Zzlp25::new(cfg.lwe, b).unwrap();
        for r in run_local(&dec, &cfg).unwrap() {
            assert!(r.plaintexts_ok, "m={m} b={b}: wrong plaintexts");
            assert_eq!(r.rounds, 5);
            assert_eq!(r.bytes_sent, expected_bytes_zzlp25(&cfg, dec.d));
        }
    }
}

#[test]
fn other_parameters_decrypt() {
    // Several plaintext bits, a smaller κ, and an explicit non-2-power β.
    let mut cfg = config(3, 20, 1);
    cfg.kappa = 40;
    cfg.lwe = LweParams::new(48, 4, 64, 30).unwrap();
    for (variant, beta) in [
        (Variant::ModConv1, Some(3)),
        (Variant::ModConv2, Some(5)),
        (Variant::ModConv2, None),
    ] {
        let dec = ModConvDecryption::modconv12(cfg.lwe, variant, beta, cfg.n).unwrap();
        for r in run_local(&dec, &cfg).unwrap() {
            assert!(r.plaintexts_ok && r.rounds == 4);
        }
    }
}

#[test]
fn malformed_messages_abort_everyone() {
    let cfg = config(3, 4, 1);
    let dec = ModConvDecryption::modconv12(cfg.lwe, Variant::ModConv2, None, 3).unwrap();
    // A ring element out of range, sent to party 2 only, in the opening of y (the first timed
    // round).
    let out_of_range: Tamper = Box::new(|at: &Site, sec| {
        if at.round == BARRIER_ROUNDS
            && at.peer == 2
            && !at.commit
            && let Section::Ring { vals, .. } = sec
        {
            vals[0] = u128::MAX;
        }
    });
    let res = run_local_with(&dec, &cfg, tampered(vec![None, Some(out_of_range)]));
    let err = res[2].as_ref().unwrap_err();
    assert!(err.0.contains("out of range"), "{err}");
    assert!(res.iter().all(|r| r.is_err()));
    // A missing element.
    let short: Tamper = Box::new(|at: &Site, sec| {
        if at.round == BARRIER_ROUNDS + 1
            && !at.commit
            && let Section::Ring { vals, .. } = sec
        {
            vals.pop();
        }
    });
    let res = run_local_with(&dec, &cfg, tampered(vec![Some(short)]));
    assert!(res[1].as_ref().unwrap_err().0.contains("bytes"));
    assert!(res.iter().all(|r| r.is_err()));
    // An extra element.
    let extra: Tamper = Box::new(|at: &Site, sec| {
        if at.round == BARRIER_ROUNDS + 1
            && !at.commit
            && let Section::Ring { vals, .. } = sec
        {
            vals.push(0);
        }
    });
    let res = run_local_with(&dec, &cfg, tampered(vec![None, None, Some(extra)]));
    assert!(res.iter().all(|r| r.is_err()));
    // A short commitment.
    let short_commitment: Tamper = Box::new(|at: &Site, sec| {
        if at.round == BARRIER_ROUNDS + 1
            && !at.commit
            && let Section::Bytes(b) = sec
        {
            b.pop();
        }
    });
    let res = run_local_with(&dec, &cfg, tampered(vec![Some(short_commitment)]));
    assert!(res[1].as_ref().unwrap_err().0.contains("bytes"));
    assert!(res.iter().all(|r| r.is_err()));
}

#[test]
fn ctx_counts_rounds_and_bytes_like_the_transport() {
    use modulus_operandi::abb::{Ctx, Round};
    use modulus_operandi::net::mem;
    use std::sync::atomic::Ordering;

    let nets = mem::network(3, Duration::from_secs(10));
    let counters: Vec<_> = nets.iter().map(|t| t.bytes_sent()).collect();
    let res: Vec<(u32, u64)> = std::thread::scope(|scope| {
        let hs: Vec<_> = nets
            .into_iter()
            .map(|t| {
                scope.spawn(move || {
                    let mut ctx = Ctx::new(Box::new(t), 64, 0, [0; 16]);
                    let mut r = Round::new();
                    ctx.exchange(&mut r).unwrap();
                    let mut r = Round::new();
                    let s = r.push_ring(13, vec![ctx.id() as u128; 5]);
                    let b = r.push_bytes(vec![7; 3]);
                    ctx.exchange(&mut r).unwrap();
                    assert_eq!(r.sum(ctx.id(), s), vec![3; 5]);
                    for j in (0..3).filter(|&j| j != ctx.id()) {
                        assert_eq!(r.ring(j, s), &[j as u128; 5]);
                        assert_eq!(r.bytes(j, b), &[7; 3]);
                    }
                    (ctx.round(), ctx.bytes_sent())
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (i, (rounds, bytes)) in res.into_iter().enumerate() {
        assert_eq!(rounds, 2);
        assert_eq!(bytes, 2 * (5 * 2 + 3));
        assert_eq!(counters[i].load(Ordering::Relaxed), bytes);
    }
}

#[test]
fn parties_start_the_timed_phase_together() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let cfg = config(3, 1, 2);
    let dec = ModConvDecryption::modconv12(cfg.lwe, Variant::ModConv2, None, cfg.n).unwrap();
    let skew = Duration::from_millis(50);
    for delay in [None, Some((2, skew))] {
        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let faults = Faults {
            delay,
            ..Faults::default()
        };
        let res: Vec<_> = run_local_with(&dec, &cfg, faults)
            .into_iter()
            .map(Result::unwrap)
            .collect();
        for rep in 0..cfg.reps as usize {
            let start = res[0][rep].start_ns;
            if delay.is_some() {
                assert!(u128::from(start) >= (before + skew).as_nanos());
            }
            for r in res.iter().map(|reps| &reps[rep]) {
                assert!(r.plaintexts_ok);
                assert_eq!(r.start_ns, start, "party {} rep {rep}", r.party);
                assert!(
                    r.online_us < 10_000,
                    "delay {delay:?}: party {} rep {rep} took {} µs",
                    r.party,
                    r.online_us
                );
            }
        }
    }
}

#[test]
fn several_instances_decrypt_in_the_rounds_of_one() {
    let n = 3;
    for instances in [1, 2, 5] {
        for batch in [1, 7] {
            let mut cfg = config(n, batch, 2);
            cfg.instances = instances;
            let check = |res: Vec<modulus_operandi::run::RepResult>, rounds, bytes| {
                assert_eq!(res.len(), 2 * n);
                for r in res {
                    assert!(r.plaintexts_ok, "instances={instances} batch={batch}");
                    assert_eq!(r.plaintexts.len(), instances * batch);
                    assert_eq!(r.rounds, rounds);
                    assert_eq!(r.bytes_sent, bytes);
                }
            };
            for variant in [Variant::ModConv1, Variant::ModConv2] {
                let dec = ModConvDecryption::modconv12(cfg.lwe, variant, None, n).unwrap();
                check(run_local(&dec, &cfg).unwrap(), 4, expected_bytes(&cfg));
            }
            let dec = Zzlp25::new(cfg.lwe, 8).unwrap();
            let bytes = expected_bytes_zzlp25(&cfg, dec.d);
            check(run_local(&dec, &cfg).unwrap(), 5, bytes);
        }
    }
    // Per instance the bytes of one batch.
    let mut cfg = config(3, 7, 1);
    cfg.instances = 5;
    assert_eq!(
        expected_bytes_zzlp25(&cfg, 8),
        ((116 * 7 + 144) * 2 * 5) as u64
    );
}

#[test]
fn a_frame_of_the_wrong_instance_aborts() {
    use modulus_operandi::net::{Abort, Payload, Transport, mem};
    use modulus_operandi::run::run_party;

    /// Tags every timed frame of instance 0 as instance 1 and vice versa.
    struct Swapped(mem::MemTransport);
    impl Transport for Swapped {
        fn id(&self) -> usize {
            self.0.id()
        }
        fn n(&self) -> usize {
            self.0.n()
        }
        fn send(&mut self, round: u32, instance: u32, out: &[Payload]) -> Result<(), Abort> {
            let swapped = if round >= BARRIER_ROUNDS {
                1 - instance
            } else {
                instance
            };
            self.0.send(round, swapped, out)
        }
        fn recv(&mut self, round: u32, instance: u32) -> Result<Vec<Payload>, Abort> {
            self.0.recv(round, instance)
        }
    }

    let mut cfg = config(3, 2, 1);
    cfg.instances = 2;
    let dec = ModConvDecryption::modconv12(cfg.lwe, Variant::ModConv1, None, cfg.n).unwrap();
    let res: Vec<_> = std::thread::scope(|scope| {
        let hs: Vec<_> = mem::network(cfg.n, cfg.timeout)
            .into_iter()
            .map(|t| {
                let (dec, cfg) = (&dec, &cfg);
                scope.spawn(move || {
                    let t: Box<dyn Transport + Send> = if t.id() == 1 {
                        Box::new(Swapped(t))
                    } else {
                        Box::new(t)
                    };
                    run_party(t, dec, cfg, None, false)
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let want = format!(
        "party 1 sent round {BARRIER_ROUNDS} instance 1, expected round {BARRIER_ROUNDS} instance 0"
    );
    // The party that reads the mislabelled frame first names it; the other may find that party
    // gone before it reads its own.
    assert!(res.iter().all(|r| r.is_err()), "{res:?}");
    assert!(
        res.iter()
            .any(|r| r.as_ref().unwrap_err().0.contains(&want)),
        "{res:?}"
    );
}

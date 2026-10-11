//! All parties as threads over loopback TCP, each on a listener bound before any party starts.

mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::{config, expected_bytes, expected_bytes_zzlp25};
use modulus_operandi::conv::modconv12::Variant;
use modulus_operandi::dec::Decryption;
use modulus_operandi::dec::modconv::ModConvDecryption;
use modulus_operandi::dec::zzlp25::Zzlp25;
use modulus_operandi::net::Abort;
use modulus_operandi::net::tcp::TcpTransport;
use modulus_operandi::run::{BARRIER_ROUNDS, Config, RepResult, params_hash, run_local, run_party};

/// `n` listeners on ephemeral loopback ports, and their addresses.
fn listeners(n: usize) -> (Vec<TcpListener>, Vec<String>) {
    let ls: Vec<_> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let peers = ls
        .iter()
        .map(|l| l.local_addr().unwrap().to_string())
        .collect();
    (ls, peers)
}

/// A party's results and the bytes its transport wrote, or its abort.
type Outcome = Result<(Vec<RepResult>, u64), Abort>;

/// Runs party `i` with `cfgs[i]` and `params[i]` for every listener given.
fn run_tcp<D: Decryption + Sync>(
    dec: &D,
    cfgs: &[Config],
    params: &[[u8; 32]],
    ls: Vec<Option<TcpListener>>,
    peers: &[String],
) -> Vec<Option<Outcome>> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = ls
            .into_iter()
            .enumerate()
            .map(|(i, l)| {
                l.map(|l| {
                    let cfg = &cfgs[i];
                    let p = params[i];
                    scope.spawn(move || {
                        let t = TcpTransport::with_listener(l, i, peers, cfg.sid, p, cfg.timeout)?;
                        let wire = t.bytes_sent();
                        let res = run_party(Box::new(t), dec, cfg, None, false)?;
                        Ok((res, wire.load(Ordering::Relaxed)))
                    })
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.map(|h| h.join().expect("party thread panicked")))
            .collect()
    })
}

/// All `n` parties with the same configuration.
fn run_honest<D: Decryption + Sync>(
    dec: &D,
    cfg: &Config,
    params: [u8; 32],
) -> Vec<(Vec<RepResult>, u64)> {
    let (ls, peers) = listeners(cfg.n);
    let cfgs = vec![cfg.clone(); cfg.n];
    run_tcp(
        dec,
        &cfgs,
        &vec![params; cfg.n],
        ls.into_iter().map(Some).collect(),
        &peers,
    )
    .into_iter()
    .map(|r| r.unwrap().unwrap())
    .collect()
}

/// Correct plaintexts, `rounds` rounds and `bytes` payload bytes per repetition, as over `mem`,
/// and on the wire one 12-byte header per frame (per round, instance and peer) on top, and the
/// barrier rounds, each a frame with one 8-byte time per peer.
fn check<D: Decryption + Sync>(dec: &D, cfg: &Config, params: [u8; 32], rounds: u32, bytes: u64) {
    let mem = run_local(dec, cfg).unwrap();
    for (i, (res, wire)) in run_honest(dec, cfg, params).into_iter().enumerate() {
        assert_eq!(res.len() as u64, cfg.reps);
        for r in &res {
            assert!(r.plaintexts_ok, "party {i} rep {}: wrong plaintexts", r.rep);
            assert_eq!(r.rounds, rounds);
            assert_eq!(r.bytes_sent, bytes);
            let m = mem.iter().find(|m| (m.party, m.rep) == (i, r.rep)).unwrap();
            assert_eq!(r.bytes_sent, m.bytes_sent);
        }
        let barrier = cfg.reps * BARRIER_ROUNDS as u64 * (cfg.n as u64 - 1);
        let instances = cfg.instances as u64;
        let frames = cfg.reps * rounds as u64 * instances * (cfg.n as u64 - 1) + barrier;
        assert_eq!(wire, cfg.reps * bytes + 8 * barrier + 12 * frames);
    }
}

#[test]
fn every_protocol_decrypts_over_tcp() {
    let cfg = config(4, 5, 2);
    for variant in [Variant::ModConv1, Variant::ModConv2] {
        let dec = ModConvDecryption::modconv12(cfg.lwe, variant, None, cfg.n).unwrap();
        let params = params_hash(
            &cfg,
            &format!("{variant:?}").to_lowercase(),
            Some(dec.conv.beta),
            None,
        );
        check(&dec, &cfg, params, 4, expected_bytes(&cfg));
    }
    let dec = Zzlp25::new(cfg.lwe, 8).unwrap();
    let params = params_hash(&cfg, "zzlp25", None, Some(dec.b));
    check(&dec, &cfg, params, 5, expected_bytes_zzlp25(&cfg, dec.d));
}

#[test]
fn several_instances_decrypt_over_tcp() {
    let mut cfg = config(4, 5, 2);
    cfg.instances = 3;
    let dec = Zzlp25::new(cfg.lwe, 8).unwrap();
    let params = params_hash(&cfg, "zzlp25", None, Some(dec.b));
    check(&dec, &cfg, params, 5, expected_bytes_zzlp25(&cfg, dec.d));
}

/// Runs four parties where `odd` gets `odd_cfg`; every party must abort, and the others must name
/// `odd` and `what`.
fn mismatch(odd: usize, odd_cfg: impl Fn(&mut Config), what: &str) {
    let mut cfg = config(4, 1, 1);
    cfg.timeout = Duration::from_secs(10);
    let dec = ModConvDecryption::modconv12(cfg.lwe, Variant::ModConv2, None, cfg.n).unwrap();
    let mut cfgs = vec![cfg.clone(); cfg.n];
    odd_cfg(&mut cfgs[odd]);
    let params: Vec<_> = cfgs
        .iter()
        .map(|c| params_hash(c, "modconv2", Some(dec.conv.beta), None))
        .collect();
    let (ls, peers) = listeners(cfg.n);
    let res = run_tcp(
        &dec,
        &cfgs,
        &params,
        ls.into_iter().map(Some).collect(),
        &peers,
    );
    for (i, r) in res.into_iter().enumerate() {
        let err = r
            .unwrap()
            .err()
            .unwrap_or_else(|| panic!("party {i} did not abort"));
        assert!(err.0.contains(what), "party {i}: {err}");
        if i != odd {
            assert!(err.0.contains(&format!("party {odd}")), "party {i}: {err}");
        }
    }
}

#[test]
fn a_different_seed_aborts_the_handshake() {
    mismatch(3, |c| c.seed += 1, "parameter hash differs");
}

#[test]
fn a_different_instance_count_aborts_the_handshake() {
    mismatch(2, |c| c.instances = 2, "parameter hash differs");
}

#[test]
fn a_different_sid_aborts_the_handshake() {
    mismatch(0, |c| c.sid[5] ^= 1, "sid differs");
}

#[test]
fn a_party_that_never_connects_aborts_the_others_after_the_deadline() {
    let mut cfg = config(3, 1, 1);
    cfg.timeout = Duration::from_secs(1);
    let dec = ModConvDecryption::modconv12(cfg.lwe, Variant::ModConv1, None, cfg.n).unwrap();
    let params = params_hash(&cfg, "modconv1", Some(dec.conv.beta), None);
    let cfgs = vec![cfg.clone(); cfg.n];
    // Party 1 listens but never runs (its connections wait in the backlog), then does not even
    // listen (connecting to it is refused).
    for keep_listening in [true, false] {
        let (mut ls, peers) = listeners(cfg.n);
        let absent = ls.remove(1);
        let ls = vec![Some(ls.remove(0)), None, Some(ls.remove(0))];
        let held = keep_listening.then_some(absent);
        let start = Instant::now();
        let res = run_tcp(&dec, &cfgs, &[params; 3], ls, &peers);
        let elapsed = start.elapsed();
        drop(held);
        assert!(elapsed >= cfg.timeout && elapsed < Duration::from_secs(10));
        for i in [0, 2] {
            let err = res[i].as_ref().unwrap().as_ref().unwrap_err();
            assert!(err.0.contains("party 1"), "party {i}: {err}");
            assert!(
                err.0.contains("timeout") || err.0.contains("deadline"),
                "party {i}: {err}"
            );
        }
    }
}

/// Party 1 of two is played by a raw socket that completes the handshake, sends `bytes` and
/// closes; party 0 must abort with `what`.
fn malformed(bytes: &[u8], what: &str) {
    let cfg = config(2, 1, 1);
    let dec = ModConvDecryption::modconv12(cfg.lwe, Variant::ModConv1, None, cfg.n).unwrap();
    let params = params_hash(&cfg, "modconv1", Some(dec.conv.beta), None);
    let (mut ls, peers) = listeners(2);
    let l0 = ls.remove(0);
    let res = std::thread::scope(|scope| {
        let h = scope.spawn(|| {
            let t = TcpTransport::with_listener(l0, 0, &peers, cfg.sid, params, cfg.timeout)?;
            run_party(Box::new(t), &dec, &cfg, None, false)
        });
        let mut s = TcpStream::connect(&peers[0]).unwrap();
        let mut hello = 1u32.to_le_bytes().to_vec();
        hello.extend_from_slice(&cfg.sid);
        hello.extend_from_slice(&params);
        s.write_all(&hello).unwrap();
        let mut reply = [0u8; 52];
        s.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[4..], &hello[4..]);
        s.write_all(bytes).unwrap();
        // Close only our side and drain, so that the kernel sends a FIN after `bytes`, not a
        // reset for unread data.
        s.shutdown(Shutdown::Write).unwrap();
        let _ = s.read_to_end(&mut Vec::new());
        h.join().unwrap()
    });
    let err = res.unwrap_err();
    assert!(err.0.contains(what) && err.0.contains("party 1"), "{err}");
}

/// A frame header: payload length, round and instance.
fn header(len: u32, round: u32, instance: u32) -> Vec<u8> {
    [
        len.to_le_bytes(),
        round.to_le_bytes(),
        instance.to_le_bytes(),
    ]
    .concat()
}

#[test]
fn malformed_frames_abort() {
    malformed(&header(1 << 31, 0, 0), "more than");
    malformed(&[header(100, 0, 0), vec![0; 10]].concat(), "mid-frame");
    malformed(&header(0, 0, 0)[..9], "mid-frame");
    malformed(
        &header(0, 5, 0),
        "sent round 5 instance 0, expected round 0 instance 0",
    );
    malformed(
        &header(0, 0, 2),
        "sent round 0 instance 2, expected round 0 instance 0",
    );
    malformed(&[], "connection closed (waiting for round 0 instance 0)");
}

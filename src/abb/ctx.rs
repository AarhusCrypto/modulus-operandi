//! Per-instance context: the party's transport and key share, shared by all its instances, and
//! the instance's own round and log of unchecked openings.

use std::cell::RefCell;
use std::ops::Range;
use std::rc::Rc;

use rand::TryRng;
use rand::rngs::SysRng;

use super::commit::{self, Commitment, Reveal};
use super::round::{Round, Section};
use super::shared::Shared;
use crate::net::{Abort, Payload, Transport};
use crate::ring::Ring;

/// Where the tamper hook runs: section `section` of round `round` of instance `instance` as sent
/// to `peer`, or, with `commit`, element `section` of the tuple that this party commits to in that
/// round, as hashed for `peer` (and later revealed to it).
pub struct Site<'a> {
    pub round: u32,
    pub instance: u32,
    pub section: usize,
    pub peer: usize,
    pub commit: bool,
    /// A rushing party's view of the peers' contributions to this round (not at commit time).
    pub received: Option<&'a Round>,
}

/// Test-only hook that may change what this party contributes for one peer.
pub type Tamper = Box<dyn FnMut(&Site, &mut Section) + Send>;

/// One opening, kept until its check shares are computed: per opened value, the opened masked value `x̂ + 2^k' r`
/// mod `2^{k'+κ}` and this party's MAC share of it.
#[derive(Clone, Debug)]
pub struct Opened {
    pub k: u32,
    pub value: Vec<u128>,
    pub mac: Vec<u128>,
}

/// A pending opening: the section it occupies and this party's masked shares.
#[must_use]
pub struct Opening {
    section: usize,
    k: u32,
    mac: Vec<u128>,
}

/// What the instances of a party share: the transport, the payload bytes sent, the tamper hook.
struct Net {
    transport: Box<dyn Transport + Send>,
    bytes_sent: u64,
    tamper: Option<Tamper>,
}

/// One protocol instance's view of the party. Instances run on one thread, so they share the
/// transport through an `Rc`.
pub struct Ctx {
    net: Rc<RefCell<Net>>,
    kappa: u32,
    key: u128,
    sid: [u8; 16],
    instance: u32,
    round: u32,
    log: Vec<Opened>,
    skip_gamma_check: bool,
}

impl Ctx {
    /// Instance 0 at round 0. `key` is this party's share of the MAC key `Δ`, in `Z_{2^κ}`.
    pub fn new(transport: Box<dyn Transport + Send>, kappa: u32, key: u128, sid: [u8; 16]) -> Ctx {
        assert!((1..=128).contains(&kappa));
        assert_eq!(key, Ring::new(kappa).mask(key));
        Ctx {
            net: Rc::new(RefCell::new(Net {
                transport,
                bytes_sent: 0,
                tamper: None,
            })),
            kappa,
            key,
            sid,
            instance: 0,
            round: 0,
            log: Vec::new(),
            skip_gamma_check: false,
        }
    }

    /// A context for instance `instance` over the same transport, at this context's round, with
    /// an empty log.
    pub fn fork(&self, instance: u32) -> Ctx {
        Ctx {
            net: self.net.clone(),
            instance,
            log: Vec::new(),
            ..*self
        }
    }

    /// Moves this context on to round `round`, e.g. to where its forks have got to.
    pub fn skip_to(&mut self, round: u32) {
        assert!(round >= self.round);
        self.round = round;
    }

    pub fn id(&self) -> usize {
        self.net.borrow().transport.id()
    }

    pub fn n(&self) -> usize {
        self.net.borrow().transport.n()
    }

    pub fn instance(&self) -> u32 {
        self.instance
    }

    pub fn kappa(&self) -> u32 {
        self.kappa
    }

    /// This party's share of `Δ`.
    pub fn key(&self) -> u128 {
        self.key
    }

    pub fn sid(&self) -> [u8; 16] {
        self.sid
    }

    /// This instance's rounds so far in this session: the round its next exchange belongs to.
    pub fn round(&self) -> u32 {
        self.round
    }

    /// Payload bytes the party has sent so far in this session, over all instances.
    pub fn bytes_sent(&self) -> u64 {
        self.net.borrow().bytes_sent
    }

    /// Openings not yet MAC-checked.
    pub fn log(&self) -> &[Opened] {
        &self.log
    }

    /// Installs the tamper hook (tests only), for every instance of the party.
    pub fn set_tamper(&mut self, f: Tamper) {
        self.net.borrow_mut().tamper = Some(f);
    }

    /// Test-only: disables the one-time MAC check on `w`, to show the attack it prevents; forks
    /// inherit it.
    pub fn skip_gamma_check(&mut self) {
        self.skip_gamma_check = true;
    }

    pub fn gamma_check_skipped(&self) -> bool {
        self.skip_gamma_check
    }

    /// `Shared::add_const_assign` with this party's id and key share.
    pub fn add_const(&self, x: &mut Shared, c: &[u128]) {
        x.add_const_assign(c, self.id(), self.key);
    }

    /// `Shared::add_scalar_assign` with this party's id and key share.
    pub fn add_scalar(&self, x: &mut Shared, c: u128) {
        x.add_scalar_assign(c, self.id(), self.key);
    }

    /// Sends this party's sections to every peer and decodes theirs: `post`, then `collect`.
    pub fn exchange(&mut self, round: &mut Round) -> Result<(), Abort> {
        self.post(round)?;
        self.collect(round)
    }

    /// Hands this instance's sections of the current round to the transport, which sends them
    /// without blocking; a rushing party sends them in `collect` instead.
    pub fn post(&mut self, round: &Round) -> Result<(), Abort> {
        if self.net.borrow().transport.rushing() {
            return Ok(());
        }
        self.send(round, false)
    }

    /// Receives and decodes the peers' sections of the current round, and moves on to the next.
    /// A rushing party receives first, so that its tamper hook sees the peers' contributions.
    pub fn collect(&mut self, round: &mut Round) -> Result<(), Abort> {
        let (id, r, i) = (self.id(), self.round, self.instance);
        let (frames, rushing) = {
            let mut net = self.net.borrow_mut();
            (net.transport.recv(r, i)?, net.transport.rushing())
        };
        round
            .receive(id, &frames)
            .map_err(|e| Abort::new(format!("round {r}: {e} (instance {i})")))?;
        if rushing {
            self.send(round, true)?;
        }
        self.round += 1;
        Ok(())
    }

    /// Sends each peer its frame of the current round, with the tamper hook applied; without the
    /// hook, every peer gets the same encoding.
    fn send(&mut self, round: &Round, rushing: bool) -> Result<(), Abort> {
        let (id, n, r, i) = (self.id(), self.n(), self.round, self.instance);
        let mut net = self.net.borrow_mut();
        let out: Vec<Payload> = match net.tamper.as_mut() {
            None => {
                assert!(!round.has_per_peer());
                let frame = Payload::new(Round::encode(round.sections()));
                (0..n)
                    .map(|j| {
                        if j == id {
                            Payload::default()
                        } else {
                            frame.clone()
                        }
                    })
                    .collect()
            }
            Some(f) => tampered_frames(f, round, id, n, r, i, rushing),
        };
        net.bytes_sent += out.iter().map(|o| o.len() as u64).sum::<u64>();
        net.transport.send(r, i, &out)
    }

    /// Adds to `round` a commitment to `tuple`, with `ρ` from the OS RNG.
    pub fn commit(&mut self, round: &mut Round, tuple: Vec<Section>) -> Result<Commitment, Abort> {
        let (id, n, r, i) = (self.id(), self.n(), self.round, self.instance);
        let mut rho = [0u8; commit::LEN];
        SysRng
            .try_fill_bytes(&mut rho)
            .map_err(|e| Abort::new(format!("OS RNG: {e}")))?;
        let own = Section::Bytes(commit::hash(&self.sid, id, r, i, &rho, &tuple).to_vec());
        let (section, per_peer) = match &mut self.net.borrow_mut().tamper {
            None => (round.push(own), None),
            Some(f) => {
                let mut tuples = vec![Vec::new(); n];
                let mut hashes = vec![Section::Bytes(Vec::new()); n];
                for j in (0..n).filter(|&j| j != id) {
                    let mut t = tuple.clone();
                    for (s, sec) in t.iter_mut().enumerate() {
                        let site = Site {
                            round: r,
                            instance: i,
                            section: s,
                            peer: j,
                            commit: true,
                            received: None,
                        };
                        f(&site, sec);
                    }
                    hashes[j] =
                        Section::Bytes(commit::hash(&self.sid, id, r, i, &rho, &t).to_vec());
                    tuples[j] = t;
                }
                (round.push_per_peer(own, hashes), Some(tuples))
            }
        };
        Ok(Commitment {
            round: r,
            section,
            tuple,
            rho,
            per_peer,
        })
    }

    /// Adds to `round` the reveal `(a, ρ)` of `c`; `sent` is the exchanged round that carried it.
    pub fn reveal(&self, round: &mut Round, c: Commitment, sent: &Round) -> Reveal {
        let (id, n) = (self.id(), self.n());
        let mut theirs = vec![[0u8; commit::LEN]; n];
        for (j, h) in theirs.iter_mut().enumerate() {
            if j != id {
                h.copy_from_slice(sent.bytes(j, c.section));
            }
        }
        let first = round.len();
        match c.per_peer {
            None => {
                for sec in c.tuple {
                    round.push(sec);
                }
            }
            Some(mut tuples) => {
                for (s, sec) in c.tuple.into_iter().enumerate() {
                    let mut to = Vec::with_capacity(n);
                    for (j, t) in tuples.iter_mut().enumerate() {
                        let placeholder = Section::Bytes(Vec::new());
                        to.push(if j == id {
                            placeholder
                        } else {
                            std::mem::replace(&mut t[s], placeholder)
                        });
                    }
                    round.push_per_peer(sec, to);
                }
            }
        }
        let tuple = first..round.len();
        let rho = round.push_bytes(c.rho.to_vec());
        Reveal {
            commit_round: c.round,
            tuple,
            rho,
            theirs,
        }
    }

    /// After the exchange: checks every peer's reveal against its commitment, hashed with the
    /// peer's own id and the commit round.
    pub fn verify_reveal(&self, round: &Round, rv: &Reveal) -> Result<(), Abort> {
        let id = self.id();
        for j in (0..self.n()).filter(|&j| j != id) {
            let mut rho = [0u8; commit::LEN];
            rho.copy_from_slice(round.bytes(j, rv.rho));
            let a = rv.tuple.clone().map(|s| round.received(j, s));
            if commit::hash(&self.sid, j, rv.commit_round, self.instance, &rho, a) != rv.theirs[j] {
                return Err(Abort::new(format!(
                    "round {}: party {j}'s reveal does not open its commitment of round {} \
                     (instance {})",
                    self.round - 1,
                    rv.commit_round,
                    self.instance
                )));
            }
        }
        Ok(())
    }

    /// Removes the openings `range` from the log and returns this party's check shares
    /// `z = ⟨Δ⟩ · x̂ - ⟨Δx̂⟩ mod 2^{k'+κ}`, one section per opening.
    pub fn check_shares(&mut self, range: Range<usize>) -> Vec<Section> {
        let mut out = Vec::with_capacity(range.len());
        for o in self.log.drain(range) {
            let r = Ring::new(o.k + self.kappa);
            let mut z = o.mac;
            for i in 0..z.len() {
                z[i] = r.sub(r.mul(self.key, o.value[i]), z[i]);
            }
            out.push(Section::Ring {
                bits: o.k + self.kappa,
                vals: z,
            });
        }
        out
    }

    /// After the exchange: the MAC check `Σ_σ z_σ ≡ 0` on the revealed check shares in `sections`.
    pub fn check_macs(&self, round: &Round, sections: Range<usize>) -> Result<(), Abort> {
        for s in sections {
            let sum = round.sum(self.id(), s);
            if let Some(d) = sum.iter().position(|&z| z != 0) {
                return Err(Abort::new(format!(
                    "round {}: MAC check failed (instance {}, section {s}, decryption {d})",
                    self.round - 1,
                    self.instance
                )));
            }
        }
        Ok(())
    }

    /// Adds to `round` this party's share of `x̂ + 2^k' r` mod `2^{k'+κ}`, where `k' = x.k` and `mask`
    /// is the extra mask `⟦r⟧` (a `Shared` with `k = 0`).
    pub fn open(&self, round: &mut Round, x: &Shared, mask: &Shared) -> Opening {
        assert_eq!(mask.k, 0);
        assert_eq!((x.kappa, mask.kappa), (self.kappa, self.kappa));
        assert_eq!(x.len(), mask.len());
        // x̂ + 2^k' r, the shift below 128 bits since κ >= 1.
        let r = Ring::new(x.k + self.kappa);
        let masked = |a: &[u128], m: &[u128]| -> Vec<u128> {
            a.iter().zip(m).map(|(&a, &m)| r.add(a, m << x.k)).collect()
        };
        let section = round.push_ring(x.k + self.kappa, masked(&x.val, &mask.val));
        Opening {
            section,
            k: x.k,
            mac: masked(&x.mac, &mask.mac),
        }
    }

    /// After the exchange: the opened values mod `2^k'`. Appends the opening to the log.
    pub fn opened(&mut self, round: &Round, h: Opening) -> Vec<u128> {
        let value = round.sum(self.id(), h.section);
        let r = Ring::new(h.k);
        let out = value.iter().map(|&v| r.mask(v)).collect();
        self.log.push(Opened {
            k: h.k,
            value,
            mac: h.mac,
        });
        out
    }
}

/// The frame for each peer under the tamper hook `f`, in round `r` of instance `i`; the entry at
/// `id` is empty.
fn tampered_frames(
    f: &mut Tamper,
    round: &Round,
    id: usize,
    n: usize,
    r: u32,
    i: u32,
    rushing: bool,
) -> Vec<Payload> {
    let mut out = vec![Payload::default(); n];
    for (j, o) in out.iter_mut().enumerate() {
        if j == id {
            continue;
        }
        let mut secs = round.sections_for(j);
        for (s, sec) in secs.iter_mut().enumerate() {
            let site = Site {
                round: r,
                instance: i,
                section: s,
                peer: j,
                commit: false,
                received: rushing.then_some(round),
            };
            f(&site, sec);
        }
        *o = Payload::new(Round::encode(&secs));
    }
    out
}

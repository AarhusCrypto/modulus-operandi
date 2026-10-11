//! One exchange, made of ordered sections that several sub-protocols may contribute to.

use crate::net::Payload;
use crate::ring::Ring;

/// What one step of a protocol instance yields once a round has been exchanged: its state and
/// the next round's sections, or its result.
pub enum Step<S, T> {
    Next(S, Round),
    Done(T),
}

/// A party's contribution to one section of a round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Section {
    /// Ring elements of `Z_{2^bits}`, each encoded in `⌈bits/8⌉` bytes.
    Ring { bits: u32, vals: Vec<u128> },
    /// Raw bytes, e.g. a commitment or its randomness.
    Bytes(Vec<u8>),
}

impl Section {
    fn encoded_len(&self) -> usize {
        match self {
            Section::Ring { bits, vals } => Ring::new(*bits).bytes() * vals.len(),
            Section::Bytes(b) => b.len(),
        }
    }

    /// Appends the encoding: each element in `⌈bits/8⌉` bytes, or the raw bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Section::Ring { bits, vals } => encode_ring(*bits, vals, out),
            Section::Bytes(b) => out.extend_from_slice(b),
        }
    }

    /// Decodes a peer's contribution with the same layout as `self`.
    fn decode_like(&self, b: &[u8]) -> Result<Section, String> {
        match self {
            Section::Ring { bits, vals } => {
                let r = Ring::new(*bits);
                let nb = r.bytes();
                let low = Ring::new(8 * nb as u32);
                let mut out = Vec::with_capacity(vals.len());
                for i in 0..vals.len() {
                    // 16 bytes at a time where they are there, the excess masked off.
                    let x = match b.get(i * nb..i * nb + 16) {
                        Some(w) => low.mask(u128::from_le_bytes(w.try_into().unwrap())),
                        None => {
                            let mut w = [0u8; 16];
                            w[..nb].copy_from_slice(&b[i * nb..(i + 1) * nb]);
                            u128::from_le_bytes(w)
                        }
                    };
                    if r.mask(x) != x {
                        return Err("ring element out of range".into());
                    }
                    out.push(x);
                }
                Ok(Section::Ring {
                    bits: *bits,
                    vals: out,
                })
            }
            Section::Bytes(_) => Ok(Section::Bytes(b.to_vec())),
        }
    }
}

/// Appends each of `vals` in `⌈bits/8⌉` bytes, little-endian, as `Ring::encode`.
pub(crate) fn encode_ring(bits: u32, vals: &[u128], out: &mut Vec<u8>) {
    let nb = Ring::new(bits).bytes();
    let start = out.len();
    out.resize(start + nb * vals.len(), 0);
    let dst = &mut out[start..];
    for (i, &x) in vals.iter().enumerate() {
        let b = x.to_le_bytes();
        match dst.get_mut(i * nb..i * nb + 16) {
            // All 16 bytes where they fit; the next element overwrites the excess.
            Some(w) => w.copy_from_slice(&b),
            None => dst[i * nb..(i + 1) * nb].copy_from_slice(&b[..nb]),
        }
    }
}

/// The sections a party sends in one exchange, and after the exchange those it received.
#[derive(Default)]
pub struct Round {
    own: Vec<Section>,
    /// Test path only: sections whose contribution differs per peer, `(s, contribution to peer j)`.
    per_peer: Vec<(usize, Vec<Section>)>,
    /// `peers[j][s]` is party j's contribution to section `s`; empty for the party itself.
    peers: Vec<Vec<Section>>,
}

impl Round {
    pub fn new() -> Round {
        Round::default()
    }

    pub fn push(&mut self, s: Section) -> usize {
        assert!(self.peers.is_empty(), "round already exchanged");
        self.own.push(s);
        self.own.len() - 1
    }

    pub fn push_ring(&mut self, bits: u32, vals: Vec<u128>) -> usize {
        self.push(Section::Ring { bits, vals })
    }

    pub fn push_bytes(&mut self, b: Vec<u8>) -> usize {
        self.push(Section::Bytes(b))
    }

    /// A section that sends `to[j]` to peer `j`; `own` is this party's contribution.
    pub(crate) fn push_per_peer(&mut self, own: Section, to: Vec<Section>) -> usize {
        let s = self.push(own);
        self.per_peer.push((s, to));
        s
    }

    pub fn len(&self) -> usize {
        self.own.len()
    }

    pub fn is_empty(&self) -> bool {
        self.own.is_empty()
    }

    pub(crate) fn has_per_peer(&self) -> bool {
        !self.per_peer.is_empty()
    }

    /// The sections as sent to peer `j`, before the tamper hook.
    pub(crate) fn sections_for(&self, j: usize) -> Vec<Section> {
        let mut secs = self.own.clone();
        for (s, to) in &self.per_peer {
            secs[*s] = to[j].clone();
        }
        secs
    }

    pub fn sections(&self) -> &[Section] {
        &self.own
    }

    pub fn own(&self, s: usize) -> &Section {
        &self.own[s]
    }

    pub fn received(&self, peer: usize, s: usize) -> &Section {
        &self.peers[peer][s]
    }

    /// Party `peer`'s ring elements in section `s`.
    pub fn ring(&self, peer: usize, s: usize) -> &[u128] {
        match self.received(peer, s) {
            Section::Ring { vals, .. } => vals,
            Section::Bytes(_) => panic!("section {s} holds bytes"),
        }
    }

    /// Party `peer`'s bytes in section `s`.
    pub fn bytes(&self, peer: usize, s: usize) -> &[u8] {
        match self.received(peer, s) {
            Section::Bytes(b) => b,
            Section::Ring { .. } => panic!("section {s} holds ring elements"),
        }
    }

    /// The sum over all parties (own contribution included) of ring section `s`.
    pub fn sum(&self, id: usize, s: usize) -> Vec<u128> {
        let (bits, mut acc) = match &self.own[s] {
            Section::Ring { bits, vals } => (*bits, vals.clone()),
            Section::Bytes(_) => panic!("section {s} holds bytes"),
        };
        let r = Ring::new(bits);
        for j in 0..self.peers.len() {
            if j == id {
                continue;
            }
            for (a, &x) in acc.iter_mut().zip(self.ring(j, s)) {
                *a = r.add(*a, x);
            }
        }
        acc
    }

    pub fn encoded_len(&self) -> usize {
        self.own.iter().map(Section::encoded_len).sum()
    }

    pub fn encode(sections: &[Section]) -> Vec<u8> {
        let mut out = Vec::with_capacity(sections.iter().map(Section::encoded_len).sum());
        for s in sections {
            s.encode(&mut out);
        }
        out
    }

    /// Decodes the peers' frames with the layout of the own sections; `frames[id]` is ignored.
    pub(crate) fn receive(&mut self, id: usize, frames: &[Payload]) -> Result<(), String> {
        let expected = self.encoded_len();
        let mut peers = Vec::with_capacity(frames.len());
        for (j, frame) in frames.iter().enumerate() {
            if j == id {
                peers.push(Vec::new());
                continue;
            }
            if frame.len() != expected {
                return Err(format!(
                    "party {j} sent {} bytes, expected {expected}",
                    frame.len()
                ));
            }
            let mut pos = 0;
            let mut secs = Vec::with_capacity(self.own.len());
            for (s, sec) in self.own.iter().enumerate() {
                let len = sec.encoded_len();
                let d = sec
                    .decode_like(&frame[pos..pos + len])
                    .map_err(|e| format!("party {j}, section {s}: {e}"))?;
                secs.push(d);
                pos += len;
            }
            peers.push(secs);
        }
        self.peers = peers;
        Ok(())
    }
}

//! In-process transport over channels, all parties as threads of one process. The channels are
//! unbounded, so a send never blocks.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::Duration;

use super::{Abort, Payload, Transport, wrong_tag};

/// `(round, instance, payload)`.
type Frame = (u32, u32, Payload);

pub struct MemTransport {
    id: usize,
    n: usize,
    tx: Vec<Option<Sender<Frame>>>,
    rx: Vec<Option<Receiver<Frame>>>,
    timeout: Duration,
    bytes_sent: Arc<AtomicU64>,
    rushing: bool,
}

/// One transport per party, with a channel per ordered pair.
pub fn network(n: usize, timeout: Duration) -> Vec<MemTransport> {
    let mut parties: Vec<MemTransport> = (0..n)
        .map(|id| MemTransport {
            id,
            n,
            tx: (0..n).map(|_| None).collect(),
            rx: (0..n).map(|_| None).collect(),
            timeout,
            bytes_sent: Arc::new(AtomicU64::new(0)),
            rushing: false,
        })
        .collect();
    for from in 0..n {
        for to in 0..n {
            if from != to {
                let (tx, rx) = channel();
                parties[from].tx[to] = Some(tx);
                parties[to].rx[from] = Some(rx);
            }
        }
    }
    parties
}

impl MemTransport {
    /// Counter of the payload bytes this party has sent; it stays readable after the transport moves.
    pub fn bytes_sent(&self) -> Arc<AtomicU64> {
        self.bytes_sent.clone()
    }

    /// Test-only: makes this party rushing (see `Transport::rushing`). Honest parties send
    /// without waiting, so one rushing party cannot deadlock the others.
    pub fn set_rushing(&mut self) {
        self.rushing = true;
    }
}

impl Transport for MemTransport {
    fn id(&self) -> usize {
        self.id
    }

    fn n(&self) -> usize {
        self.n
    }

    fn rushing(&self) -> bool {
        self.rushing
    }

    fn send(&mut self, round: u32, instance: u32, out: &[Payload]) -> Result<(), Abort> {
        assert_eq!(out.len(), self.n);
        for (j, frame) in out.iter().enumerate() {
            if j == self.id {
                continue;
            }
            self.bytes_sent
                .fetch_add(frame.len() as u64, Ordering::Relaxed);
            // A gone peer shows in `recv`.
            let tx = self.tx[j].as_ref().expect("channel to peer");
            let _ = tx.send((round, instance, frame.clone()));
        }
        Ok(())
    }

    fn recv(&mut self, round: u32, instance: u32) -> Result<Vec<Payload>, Abort> {
        let mut frames = Vec::with_capacity(self.n);
        for j in 0..self.n {
            if j == self.id {
                frames.push(Payload::default());
                continue;
            }
            let rx = self.rx[j].as_ref().expect("channel from peer");
            match rx.recv_timeout(self.timeout) {
                Ok((r, i, frame)) if (r, i) == (round, instance) => frames.push(frame),
                Ok((r, i, _)) => return Err(wrong_tag(j, (r, i), (round, instance))),
                Err(RecvTimeoutError::Timeout) => {
                    return Err(Abort::new(format!(
                        "timeout waiting for party {j} in round {round} instance {instance}"
                    )));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(Abort::new(format!(
                        "party {j} has gone (round {round} instance {instance})"
                    )));
                }
            }
        }
        Ok(frames)
    }
}

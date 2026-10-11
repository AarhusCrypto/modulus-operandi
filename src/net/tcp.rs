//! TCP transport: a fixed peer list, one connection per pair, and per peer a reader and a writer
//! thread that only move frames between the socket and a channel, so that `send` never blocks.
//!
//! Party `i` connects to every `j < i` and accepts every `j > i`. Each side of a new connection
//! sends a handshake `id ‖ sid ‖ params` (4 + 16 + 32 bytes), where `params` hashes the protocol
//! and its parameters. Frames are `len ‖ round ‖ instance ‖ payload`, the first three as `u32`,
//! all little-endian.

use std::io::{self, ErrorKind, IoSlice, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{Abort, Payload, Transport, wrong_tag};

/// Largest payload accepted in one frame.
pub const MAX_FRAME: usize = 1 << 30;
const HEADER: usize = 12;
const HELLO: usize = 4 + 16 + 32;

/// A frame `(round, instance, payload)`.
type Frame = (u32, u32, Payload);

/// A received frame, or why the reader or the writer of that peer stopped.
type Incoming = Result<Frame, String>;

pub struct TcpTransport {
    id: usize,
    n: usize,
    streams: Vec<Option<TcpStream>>,
    rx: Vec<Option<Receiver<Incoming>>>,
    tx: Vec<Option<Sender<Frame>>>,
    readers: Vec<JoinHandle<()>>,
    writers: Vec<JoinHandle<()>>,
    timeout: Duration,
    bytes_sent: Arc<AtomicU64>,
}

/// The handshake each side of a connection sends.
struct Hello {
    id: u32,
    sid: [u8; 16],
    params: [u8; 32],
}

impl Hello {
    fn encode(&self) -> [u8; HELLO] {
        let mut b = [0u8; HELLO];
        b[..4].copy_from_slice(&self.id.to_le_bytes());
        b[4..20].copy_from_slice(&self.sid);
        b[20..].copy_from_slice(&self.params);
        b
    }

    fn read(s: &mut TcpStream, deadline: Instant) -> Result<Hello, String> {
        s.set_read_timeout(Some(remaining(deadline)))
            .map_err(|e| e.to_string())?;
        let mut b = [0u8; HELLO];
        s.read_exact(&mut b).map_err(|e| match e.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                "no handshake before the deadline".into()
            }
            ErrorKind::UnexpectedEof => "connection closed during the handshake".into(),
            _ => e.to_string(),
        })?;
        Ok(Hello {
            id: u32::from_le_bytes(b[..4].try_into().unwrap()),
            sid: b[4..20].try_into().unwrap(),
            params: b[20..].try_into().unwrap(),
        })
    }

    /// Compares party `j`'s handshake with ours.
    fn check(&self, ours: &Hello, j: usize) -> Result<(), Abort> {
        if self.sid != ours.sid {
            return Err(Abort::new(format!(
                "handshake with party {j}: sid differs (ours {}, theirs {})",
                hex(&ours.sid),
                hex(&self.sid)
            )));
        }
        if self.params != ours.params {
            return Err(Abort::new(format!(
                "handshake with party {j}: parameter hash differs (protocol, parameters or dealer seed)"
            )));
        }
        Ok(())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Time left until `deadline`, at least 1 ms (a zero socket timeout is invalid).
fn remaining(deadline: Instant) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(1))
}

fn resolve(peer: &str) -> Result<Vec<SocketAddr>, Abort> {
    let addrs: Vec<_> = peer
        .to_socket_addrs()
        .map_err(|e| Abort::new(format!("cannot resolve {peer}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(Abort::new(format!("{peer} resolves to no address")));
    }
    Ok(addrs)
}

/// Connects to party `j` at `peer`, retrying until `deadline`.
fn connect_until(peer: &str, j: usize, deadline: Instant) -> Result<TcpStream, Abort> {
    let addrs = resolve(peer)?;
    loop {
        let mut last = None;
        for a in &addrs {
            match TcpStream::connect_timeout(a, remaining(deadline).min(Duration::from_secs(1))) {
                Ok(s) => return Ok(s),
                Err(e) => last = Some(e),
            }
        }
        if Instant::now() >= deadline {
            return Err(Abort::new(format!(
                "timeout during connection setup: cannot connect to party {j} at {peer}: {}",
                last.expect("at least one address")
            )));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Reads one frame; a clean EOF between frames is reported as the peer having closed.
fn read_frame(s: &mut TcpStream) -> Result<Frame, String> {
    let mut h = [0u8; HEADER];
    let mut got = 0;
    while got < HEADER {
        match s.read(&mut h[got..]) {
            Ok(0) if got == 0 => return Err("connection closed".into()),
            Ok(0) => return Err("connection closed mid-frame".into()),
            Ok(k) => got += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    let word = |i: usize| u32::from_le_bytes(h[4 * i..4 * i + 4].try_into().unwrap());
    let (len, round, instance) = (word(0) as usize, word(1), word(2));
    if len > MAX_FRAME {
        return Err(format!(
            "frame of round {round} instance {instance} has {len} bytes, more than {MAX_FRAME}"
        ));
    }
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).map_err(|e| match e.kind() {
        ErrorKind::UnexpectedEof => "connection closed mid-frame".into(),
        _ => e.to_string(),
    })?;
    Ok((round, instance, Payload::new(payload)))
}

/// Writes `header ‖ payload` without copying them into one buffer.
fn write_all_vectored(s: &mut TcpStream, header: &[u8], payload: &[u8]) -> io::Result<()> {
    let mut bufs = [IoSlice::new(header), IoSlice::new(payload)];
    let mut bufs = &mut bufs[..];
    while !bufs.is_empty() {
        match s.write_vectored(bufs) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(k) => IoSlice::advance_slices(&mut bufs, k),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// The reader thread: moves frames into the channel until EOF or an error, which it sends too.
fn reader(mut s: TcpStream, tx: Sender<Incoming>) {
    loop {
        let f = read_frame(&mut s);
        let stop = f.is_err();
        if tx.send(f).is_err() || stop {
            return;
        }
    }
}

/// The writer thread: writes the queued frames until the queue closes or a write fails; it
/// reports a failure on the peer's incoming channel, where `recv` finds it.
fn writer(mut s: TcpStream, queue: Receiver<Frame>, errors: Sender<Incoming>) {
    for (round, instance, payload) in queue {
        let mut header = [0u8; HEADER];
        header[..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        header[4..8].copy_from_slice(&round.to_le_bytes());
        header[8..].copy_from_slice(&instance.to_le_bytes());
        if let Err(e) = write_all_vectored(&mut s, &header, &payload) {
            let e = match e.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => "timeout".to_string(),
                _ => e.to_string(),
            };
            let _ = errors.send(Err(format!(
                "sending round {round} instance {instance}: {e}"
            )));
            return;
        }
    }
}

impl TcpTransport {
    /// Binds `peers[id]`, then as `with_listener`.
    pub fn connect(
        id: usize,
        peers: &[String],
        sid: [u8; 16],
        params: [u8; 32],
        timeout: Duration,
    ) -> Result<TcpTransport, Abort> {
        let peer = peers
            .get(id)
            .ok_or_else(|| Abort::new(format!("party {id} is not in the peer list")))?;
        let addrs = resolve(peer)?;
        let listener = TcpListener::bind(&addrs[..])
            .map_err(|e| Abort::new(format!("cannot listen on {peer}: {e}")))?;
        TcpTransport::with_listener(listener, id, peers, sid, params, timeout)
    }

    /// Connects to every `j < id` at `peers[j]` and accepts every `j > id` on `listener`, all
    /// before `timeout` has passed, and runs the handshake on each connection. Every party
    /// answers all handshakes before checking them, so each side of a mismatch names it.
    /// `timeout` is also how long `recv` waits for a frame and a write may block.
    pub fn with_listener(
        listener: TcpListener,
        id: usize,
        peers: &[String],
        sid: [u8; 16],
        params: [u8; 32],
        timeout: Duration,
    ) -> Result<TcpTransport, Abort> {
        let n = peers.len();
        if id >= n {
            return Err(Abort::new(format!("party {id} is not in the peer list")));
        }
        let deadline = Instant::now() + timeout;
        let ours = Hello {
            id: id as u32,
            sid,
            params,
        };
        let setup = |e: io::Error| Abort::new(format!("connection setup: {e}"));
        let mut streams: Vec<Option<TcpStream>> = (0..n).map(|_| None).collect();
        let mut mismatch: Option<Abort> = None;

        for j in 0..id {
            let mut s = connect_until(&peers[j], j, deadline)?;
            s.set_nodelay(true).map_err(setup)?;
            s.write_all(&ours.encode())
                .map_err(|e| Abort::new(format!("handshake with party {j}: {e}")))?;
            streams[j] = Some(s);
        }

        listener.set_nonblocking(true).map_err(setup)?;
        let mut accepted = 0;
        while accepted < n - 1 - id {
            let (mut s, addr) = match listener.accept() {
                Ok(c) => c,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        let missing: Vec<_> = (id + 1..n)
                            .filter(|&j| streams[j].is_none())
                            .map(|j| format!("party {j}"))
                            .collect();
                        return Err(Abort::new(format!(
                            "timeout during connection setup: no connection from {}",
                            missing.join(", ")
                        )));
                    }
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => return Err(setup(e)),
            };
            s.set_nonblocking(false).map_err(setup)?;
            s.set_nodelay(true).map_err(setup)?;
            let theirs = Hello::read(&mut s, deadline)
                .map_err(|e| Abort::new(format!("handshake with a connection from {addr}: {e}")))?;
            let j = theirs.id as usize;
            if j <= id || j >= n {
                return Err(Abort::new(format!(
                    "handshake from {addr}: party {j} is not one that connects to party {id}"
                )));
            }
            if streams[j].is_some() {
                return Err(Abort::new(format!(
                    "handshake from {addr}: party {j} connected twice"
                )));
            }
            s.write_all(&ours.encode())
                .map_err(|e| Abort::new(format!("handshake with party {j}: {e}")))?;
            if let Err(e) = theirs.check(&ours, j) {
                mismatch.get_or_insert(e);
            }
            streams[j] = Some(s);
            accepted += 1;
        }

        for j in 0..id {
            let s = streams[j].as_mut().expect("connected above");
            let theirs = Hello::read(s, deadline)
                .map_err(|e| Abort::new(format!("handshake with party {j}: {e}")))?;
            let res = if theirs.id as usize != j {
                Err(Abort::new(format!(
                    "handshake with party {j}: {} answered as party {}",
                    peers[j], theirs.id
                )))
            } else {
                theirs.check(&ours, j)
            };
            if let Err(e) = res {
                mismatch.get_or_insert(e);
            }
        }
        if let Some(e) = mismatch {
            return Err(e);
        }

        let mut rx: Vec<Option<Receiver<Incoming>>> = (0..n).map(|_| None).collect();
        let mut tx: Vec<Option<Sender<Frame>>> = (0..n).map(|_| None).collect();
        let mut readers = Vec::with_capacity(n - 1);
        let mut writers = Vec::with_capacity(n - 1);
        for (j, s) in streams.iter().enumerate() {
            let Some(s) = s else { continue };
            s.set_read_timeout(None).map_err(setup)?;
            s.set_write_timeout(Some(timeout)).map_err(setup)?;
            let (r, w) = (s.try_clone().map_err(setup)?, s.try_clone().map_err(setup)?);
            let (in_tx, in_rx) = channel();
            let (out_tx, out_rx) = channel();
            rx[j] = Some(in_rx);
            tx[j] = Some(out_tx);
            let errors = in_tx.clone();
            let spawn = |name: String, f: Box<dyn FnOnce() + Send>| {
                thread::Builder::new().name(name).spawn(f).map_err(setup)
            };
            readers.push(spawn(
                format!("reader-{j}"),
                Box::new(move || reader(r, in_tx)),
            )?);
            writers.push(spawn(
                format!("writer-{j}"),
                Box::new(move || writer(w, out_rx, errors)),
            )?);
        }
        Ok(TcpTransport {
            id,
            n,
            streams,
            rx,
            tx,
            readers,
            writers,
            timeout,
            bytes_sent: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Counter of the bytes this party has handed to the writers in frames, headers included
    /// (the handshake excluded); it stays readable after the transport moves.
    pub fn bytes_sent(&self) -> Arc<AtomicU64> {
        self.bytes_sent.clone()
    }
}

impl Transport for TcpTransport {
    fn id(&self) -> usize {
        self.id
    }

    fn n(&self) -> usize {
        self.n
    }

    fn send(&mut self, round: u32, instance: u32, out: &[Payload]) -> Result<(), Abort> {
        assert_eq!(out.len(), self.n);
        for (j, payload) in out.iter().enumerate() {
            if j == self.id {
                continue;
            }
            if payload.len() > MAX_FRAME {
                return Err(Abort::new(format!(
                    "frame to party {j} in round {round} instance {instance} has {} bytes, more \
                     than {MAX_FRAME}",
                    payload.len()
                )));
            }
            // A writer that has stopped has put its error where `recv` finds it.
            let tx = self.tx[j].as_ref().expect("queue to peer");
            let _ = tx.send((round, instance, payload.clone()));
            self.bytes_sent
                .fetch_add((HEADER + payload.len()) as u64, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Waits at most the timeout for the whole round, not per peer.
    fn recv(&mut self, round: u32, instance: u32) -> Result<Vec<Payload>, Abort> {
        let deadline = Instant::now() + self.timeout;
        let mut frames = Vec::with_capacity(self.n);
        let at = format!("round {round} instance {instance}");
        for j in 0..self.n {
            if j == self.id {
                frames.push(Payload::default());
                continue;
            }
            let rx = self.rx[j].as_ref().expect("channel from peer");
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(Ok((r, i, frame))) if (r, i) == (round, instance) => frames.push(frame),
                Ok(Ok((r, i, _))) => return Err(wrong_tag(j, (r, i), (round, instance))),
                Ok(Err(e)) => {
                    return Err(Abort::new(format!("party {j}: {e} (waiting for {at})")));
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(Abort::new(format!("timeout waiting for party {j} in {at}")));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(Abort::new(format!(
                        "party {j}: reader stopped (waiting for {at})"
                    )));
                }
            }
        }
        Ok(frames)
    }
}

impl Drop for TcpTransport {
    /// Lets the writers drain their queues, then shuts the sockets down, which ends the readers.
    fn drop(&mut self) {
        self.tx.clear();
        for h in self.writers.drain(..) {
            let _ = h.join();
        }
        for s in self.streams.iter().flatten() {
            let _ = s.shutdown(Shutdown::Both);
        }
        for h in self.readers.drain(..) {
            let _ = h.join();
        }
    }
}

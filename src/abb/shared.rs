//! Authenticated SPDZ2k sharings, one entry per decryption of a batch.

use crate::ring::Ring;

/// One party's shares of a vector of values in `Z_{2^k}`: value shares `⟨x̂⟩` and MAC shares `⟨Δx̂⟩`,
/// both mod `2^{k+κ}`. An extra mask is a `Shared` with `k = 0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shared {
    pub k: u32,
    pub kappa: u32,
    pub val: Vec<u128>,
    pub mac: Vec<u128>,
}

impl Shared {
    pub fn new(k: u32, kappa: u32, val: Vec<u128>, mac: Vec<u128>) -> Shared {
        assert!(k + kappa <= 128, "k + κ = {} exceeds 128", k + kappa);
        assert_eq!(val.len(), mac.len());
        Shared { k, kappa, val, mac }
    }

    pub fn len(&self) -> usize {
        self.val.len()
    }

    pub fn is_empty(&self) -> bool {
        self.val.is_empty()
    }

    /// The ring of the shares, `Z_{2^{k+κ}}`.
    pub fn ring(&self) -> Ring {
        Ring::new(self.k + self.kappa)
    }

    fn same_shape(&self, o: &Shared) {
        assert_eq!((self.k, self.kappa, self.len()), (o.k, o.kappa, o.len()));
    }

    /// `f` on every value and MAC share, into a sharing with `k2` in place of `k`.
    fn map(&self, k2: u32, f: impl Fn(u128) -> u128) -> Shared {
        let g = |v: &[u128]| v.iter().map(|&x| f(x)).collect();
        Shared::new(k2, self.kappa, g(&self.val), g(&self.mac))
    }

    /// `self[i] = f(self[i], o[i])`, value and MAC shares alike.
    fn zip_assign(&mut self, o: &Shared, f: impl Fn(u128, u128) -> u128) {
        self.same_shape(o);
        for (a, &b) in self.val.iter_mut().zip(&o.val) {
            *a = f(*a, b);
        }
        for (a, &b) in self.mac.iter_mut().zip(&o.mac) {
            *a = f(*a, b);
        }
    }

    pub fn add(&self, o: &Shared) -> Shared {
        self.same_shape(o);
        let r = self.ring();
        let g = |a: &[u128], b: &[u128]| a.iter().zip(b).map(|(&x, &y)| r.add(x, y)).collect();
        Shared::new(
            self.k,
            self.kappa,
            g(&self.val, &o.val),
            g(&self.mac, &o.mac),
        )
    }

    pub fn add_assign(&mut self, o: &Shared) {
        let r = self.ring();
        self.zip_assign(o, |a, b| r.add(a, b));
    }

    pub fn sub_assign(&mut self, o: &Shared) {
        let r = self.ring();
        self.zip_assign(o, |a, b| r.sub(a, b));
    }

    /// `self += c · o` for the public `c`.
    pub fn add_scaled(&mut self, o: &Shared, c: u128) {
        let r = self.ring();
        self.zip_assign(o, |a, b| r.add(a, r.mul(c, b)));
    }

    pub fn neg_assign(&mut self) {
        let r = self.ring();
        for x in self.val.iter_mut().chain(self.mac.iter_mut()) {
            *x = r.neg(*x);
        }
    }

    /// Adds the public `c(i)` (in `Z_{2^k}`) to entry `i`: party 0 adds it to its value share, and
    /// every party adds `key · c(i)` to its MAC share, `key` being its share of `Δ`.
    fn add_public(&mut self, c: impl Fn(usize) -> u128, party: usize, key: u128) {
        let (r, rk) = (self.ring(), Ring::new(self.k));
        for i in 0..self.len() {
            let ci = rk.mask(c(i));
            if party == 0 {
                self.val[i] = r.add(self.val[i], ci);
            }
            self.mac[i] = r.add(self.mac[i], r.mul(key, ci));
        }
    }

    /// Adds the public `c[i]` (in `Z_{2^k}`) to entry `i`, with this party's id and share `key` of
    /// `Δ`.
    pub fn add_const_assign(&mut self, c: &[u128], party: usize, key: u128) {
        assert_eq!(c.len(), self.len());
        self.add_public(|i| c[i], party, key);
    }

    /// `add_const_assign` into a new sharing.
    pub fn add_const(&self, c: &[u128], party: usize, key: u128) -> Shared {
        let mut out = self.clone();
        out.add_const_assign(c, party, key);
        out
    }

    /// Adds the same public `c` to every entry.
    pub fn add_scalar_assign(&mut self, c: u128, party: usize, key: u128) {
        self.add_public(|_| c, party, key);
    }

    /// DivModConv: a sharing of `x mod 2^k2`, for `k2 <= k`.
    pub fn reduce(&self, k2: u32) -> Shared {
        assert!(k2 <= self.k);
        let r = Ring::new(k2 + self.kappa);
        self.map(k2, |x| r.mask(x))
    }

    /// A sharing of `2^{k2-k} x` mod `2^k2`, for `k2 >= k`.
    pub fn lift(&self, k2: u32) -> Shared {
        assert!(k2 >= self.k);
        let r = Ring::new(k2 + self.kappa);
        let s = k2 - self.k;
        self.map(k2, |x| r.mask(x.checked_shl(s).unwrap_or(0)))
    }
}

/// A dealt lookup table of `width` authenticated entries per decryption, stored per decryption:
/// entry `x` of decryption `i` is entry `e = i · width + x`, its value and MAC share side by side
/// at `data[off + 2e]` and `data[off + 2e + 1]`. `off` aligns every entry to 32 bytes, so that a
/// lookup touches one cache line. A clone is aligned anew, and tables compare by their entries.
#[derive(Debug)]
pub struct Table {
    pub k: u32,
    pub kappa: u32,
    width: usize,
    off: usize,
    data: Vec<u128>,
}

impl Table {
    /// The table whose entries for decryption `i` are the `width` entries of `row(i)`, for
    /// `i < rows`.
    pub fn from_rows(
        k: u32,
        kappa: u32,
        width: usize,
        rows: usize,
        mut row: impl FnMut(usize) -> Shared,
    ) -> Table {
        assert!(width > 0);
        let (mut data, off) = Self::alloc(2 * rows * width);
        for i in 0..rows {
            let r = row(i);
            assert_eq!((r.k, r.kappa, r.len()), (k, kappa, width));
            for (&val, &mac) in r.val.iter().zip(&r.mac) {
                data.push(val);
                data.push(mac);
            }
        }
        Table {
            k,
            kappa,
            width,
            off,
            data,
        }
    }

    /// An empty vector with room for `len` more elements after `off` zeros, `off` aligning
    /// them to 32 bytes.
    fn alloc(len: usize) -> (Vec<u128>, usize) {
        let mut data = Vec::with_capacity(len + 1);
        let off = (data.as_ptr() as usize / 16) % 2;
        data.resize(off, 0);
        (data, off)
    }

    /// The entries, without the alignment.
    fn entries(&self) -> &[u128] {
        &self.data[self.off..]
    }

    /// Entries per decryption.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Entry `x` of every decryption.
    pub fn column(&self, x: usize) -> Shared {
        assert!(x < self.width);
        let entries = self.entries().as_chunks::<2>().0;
        let col = || entries.iter().skip(x).step_by(self.width);
        let val = col().map(|e| e[0]).collect();
        let mac = col().map(|e| e[1]).collect();
        Shared::new(self.k, self.kappa, val, mac)
    }

    /// Entry `idx[i]` of decryption `i`.
    pub fn select(&self, idx: &[usize]) -> Shared {
        let row = 2 * self.width;
        assert_eq!(self.off + idx.len() * row, self.data.len());
        let mut val = Vec::with_capacity(idx.len());
        let mut mac = Vec::with_capacity(idx.len());
        for (r, &x) in self.entries().chunks_exact(row).zip(idx) {
            let e = &r[2 * x..2 * x + 2];
            val.push(e[0]);
            mac.push(e[1]);
        }
        Shared::new(self.k, self.kappa, val, mac)
    }
}

impl Clone for Table {
    /// A deep copy in an allocation of its own, aligned as `from_rows` aligns.
    fn clone(&self) -> Table {
        let (mut data, off) = Self::alloc(self.entries().len());
        data.extend_from_slice(self.entries());
        Table {
            k: self.k,
            kappa: self.kappa,
            width: self.width,
            off,
            data,
        }
    }
}

impl PartialEq for Table {
    fn eq(&self, other: &Table) -> bool {
        (self.k, self.kappa, self.width) == (other.k, other.kappa, other.width)
            && self.entries() == other.entries()
    }
}

impl Eq for Table {}

//! Arithmetic in `Z_{2^bits}`, held in a machine word.

/// Machine word that holds ring elements. All operations wrap at the word width; a wider word (for a
/// second SPDZ2k instance) can implement this trait later.
pub trait Word: Copy + Eq + Ord + std::fmt::Debug + Default + Send + Sync + 'static {
    const BITS: u32;
    fn wrapping_add(self, other: Self) -> Self;
    fn wrapping_sub(self, other: Self) -> Self;
    /// Full-width product, reduced mod `2^BITS`.
    fn wrapping_mul(self, other: Self) -> Self;
    /// `2^bits - 1`, for `bits <= BITS`.
    fn low_mask(bits: u32) -> Self;
    fn and(self, other: Self) -> Self;
}

impl Word for u128 {
    const BITS: u32 = 128;
    fn wrapping_add(self, other: Self) -> Self {
        u128::wrapping_add(self, other)
    }
    fn wrapping_sub(self, other: Self) -> Self {
        u128::wrapping_sub(self, other)
    }
    fn wrapping_mul(self, other: Self) -> Self {
        u128::wrapping_mul(self, other)
    }
    fn low_mask(bits: u32) -> Self {
        assert!(bits <= 128);
        if bits == 128 {
            u128::MAX
        } else {
            (1u128 << bits) - 1
        }
    }
    fn and(self, other: Self) -> Self {
        self & other
    }
}

/// The ring `Z_{2^bits}`: operations wrap at the word width, then mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring {
    bits: u32,
}

impl Ring {
    pub fn new(bits: u32) -> Ring {
        assert!(bits <= 128, "ring width {bits} exceeds 128 bits");
        Ring { bits }
    }

    pub fn bits(self) -> u32 {
        self.bits
    }

    pub fn mask<W: Word>(self, x: W) -> W {
        x.and(W::low_mask(self.bits))
    }

    pub fn add<W: Word>(self, a: W, b: W) -> W {
        self.mask(a.wrapping_add(b))
    }

    pub fn sub<W: Word>(self, a: W, b: W) -> W {
        self.mask(a.wrapping_sub(b))
    }

    pub fn neg<W: Word>(self, a: W) -> W {
        self.mask(W::default().wrapping_sub(a))
    }

    pub fn mul<W: Word>(self, a: W, b: W) -> W {
        self.mask(a.wrapping_mul(b))
    }

    /// Bytes per encoded element: `⌈bits/8⌉`.
    pub fn bytes(self) -> usize {
        self.bits.div_ceil(8) as usize
    }

    /// Appends the low `bytes()` bytes of `x`, little-endian. Bits of an unreduced `x` within the
    /// top byte are kept, so that the decoder rejects it.
    pub fn encode(self, x: u128, out: &mut Vec<u8>) {
        out.extend_from_slice(&x.to_le_bytes()[..self.bytes()]);
    }

    /// Decodes one element from exactly `bytes()` bytes; `None` if it is not below `2^bits`.
    pub fn decode(self, b: &[u8]) -> Option<u128> {
        if b.len() != self.bytes() {
            return None;
        }
        let mut buf = [0u8; 16];
        buf[..b.len()].copy_from_slice(b);
        let x = u128::from_le_bytes(buf);
        if self.mask(x) == x { Some(x) } else { None }
    }
}

use modulus_operandi::prg::{Part, Stream};
use modulus_operandi::ring::Ring;

#[test]
fn ring_ops_wrap_and_mask() {
    for bits in 0..=128u32 {
        let r = Ring::new(bits);
        let max = r.mask(u128::MAX);
        assert_eq!(r.add(max, 1), 0);
        assert_eq!(r.sub(0, 1), max);
        assert_eq!(r.add(r.neg(5), 5), 0);
        assert_eq!(r.mul(max, max), r.mask(1));
    }
    let r = Ring::new(64);
    assert_eq!(r.mul(1u128 << 63, 2), 0);
    // Full-width product: (2^64 + 1)^2 = 2^128 + 2^65 + 1.
    assert_eq!(
        Ring::new(128).mul((1u128 << 64) + 1, (1u128 << 64) + 1),
        (1u128 << 65) + 1
    );
}

#[test]
#[should_panic]
fn ring_rejects_width_above_128() {
    let _ = Ring::new(129);
}

#[test]
fn encoding_round_trips_and_rejects_out_of_range() {
    let mut s = Stream::new(1, &[Part::S("test")]);
    for bits in 0..=128u32 {
        let r = Ring::new(bits);
        assert_eq!(r.bytes(), bits.div_ceil(8) as usize);
        for _ in 0..50 {
            let x = s.bits(bits);
            let mut buf = Vec::new();
            r.encode(x, &mut buf);
            assert_eq!(buf.len(), r.bytes());
            assert_eq!(r.decode(&buf), Some(x));
        }
        let mut buf = Vec::new();
        r.encode(r.mask(u128::MAX), &mut buf);
        assert_eq!(r.decode(&buf), Some(r.mask(u128::MAX)));
        if bits % 8 != 0 {
            // The first value above the range sets a bit of the top byte.
            let last = buf.len() - 1;
            buf[last] |= 1 << (bits % 8);
            assert_eq!(r.decode(&buf), None);
        }
        assert_eq!(r.decode(&vec![0; r.bytes() + 1]), None);
    }
}

#[test]
fn streams_are_deterministic_and_separated() {
    let label = [Part::S("share"), Part::N(2), Part::N(7)];
    let a: Vec<u128> = (0..8)
        .map({
            let mut s = Stream::new(5, &label);
            move |_| s.u128()
        })
        .collect();
    let b: Vec<u128> = (0..8)
        .map({
            let mut s = Stream::new(5, &label);
            move |_| s.u128()
        })
        .collect();
    assert_eq!(a, b);
    let others = [
        Stream::new(6, &label).u128(),
        Stream::new(5, &[Part::S("share"), Part::N(2), Part::N(8)]).u128(),
        Stream::new(5, &[Part::S("share"), Part::N(27)]).u128(),
        Stream::new(5, &[Part::S("share2"), Part::N(7)]).u128(),
        Stream::new(5, &[Part::N(2), Part::S("share"), Part::N(7)]).u128(),
    ];
    for o in others {
        assert_ne!(o, a[0]);
    }
}

#[test]
fn stream_sampling_stays_in_range() {
    let mut s = Stream::new(9, &[Part::S("range")]);
    for bits in 0..=128u32 {
        let mut or = 0u128;
        for _ in 0..200 {
            let x = s.bits(bits);
            assert_eq!(x, Ring::new(bits).mask(x));
            or |= x;
        }
        // Every bit of the width shows up.
        assert_eq!(or, Ring::new(bits).mask(u128::MAX));
    }
    for bound in [1u128, 2, 3, 5, 7, 1000, (1 << 64) + 3, u128::MAX] {
        for _ in 0..200 {
            assert!(s.below(bound) < bound);
        }
    }
    let mut seen = [false; 7];
    for _ in 0..500 {
        seen[s.below(7) as usize] = true;
    }
    assert!(seen.iter().all(|&b| b));
    let ones = (0..1000).filter(|_| s.bit()).count();
    assert!((400..600).contains(&ones));
}

//! Modulus Operandi: benchmark of threshold decryption by modulus conversion on SPDZ2k.

// Index loops over parallel share vectors read more plainly than zipped iterators.
#![allow(clippy::needless_range_loop)]

pub mod abb;
pub mod conv;
pub mod dec;
pub mod net;
pub mod prep;
pub mod prg;
pub mod ring;
pub mod run;

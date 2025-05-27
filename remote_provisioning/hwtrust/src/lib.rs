//! A library for handling data related to the hardware root-of-trust. The DICE chain is the
//! fundamental data structure that other features and services build on top of.

pub mod dice;
pub mod publickey;
pub mod rkp;
pub mod session;

mod cbor;
mod eek;

pub(crate) fn debug_option<T: std::fmt::Debug>(option: &Option<T>) -> &dyn std::fmt::Debug {
    match option {
        Some(x) => x,
        n => n,
    }
}

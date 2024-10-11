//! Traits for the curve25519-dalek crate.
use crate::traits::*;
use elliptic_curve::hash2curve::ExpandMsgXmd;
use vsss_rs::curve25519::WrappedScalar;
use vsss_rs::{
    curve25519::{WrappedEdwards, WrappedRistretto},
    curve25519_dalek::{edwards::EdwardsPoint, ristretto::RistrettoPoint},
};

impl GroupHasher for WrappedRistretto {
    fn hash_to_curve(msg: &[u8]) -> Self {
        WrappedRistretto(RistrettoPoint::hash_from_bytes::<sha2::Sha512>(msg))
    }
}

impl GroupHasher for WrappedEdwards {
    fn hash_to_curve(msg: &[u8]) -> Self {
        const DST: &[u8] = b"edwards25519_XMD:SHA-512_ELL2_RO_";
        let pt = curve25519_dalek_ml::edwards::EdwardsPoint::hash_to_curve::<
            ExpandMsgXmd<sha2::Sha512>,
        >(msg, DST);
        WrappedEdwards(unsafe {
            std::mem::transmute::<curve25519_dalek_ml::edwards::EdwardsPoint, EdwardsPoint>(pt)
        })
    }
}

impl ReduceWide<64> for WrappedScalar {
    fn reduce_wide(okm: &[u8; 64]) -> Self {
        WrappedScalar(vsss_rs::curve25519_dalek::Scalar::from_bytes_mod_order_wide(okm))
    }
}

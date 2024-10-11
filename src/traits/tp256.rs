//! Traits for the P-256 curve.
use crate::traits::*;
use elliptic_curve::{
    bigint::{NonZero, U512},
    hash2curve::{ExpandMsgXmd, GroupDigest},
    scalar::FromUintUnchecked,
};
use p256::{NistP256, ProjectivePoint, Scalar};

impl GroupHasher for ProjectivePoint {
    fn hash_to_curve(msg: &[u8]) -> Self {
        const DST: &[u8] = b"P256_XMD:SHA-256_SSWU_RO_";
        let msg = [msg];
        let dst = [DST];
        NistP256::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}

impl ReduceWide<64> for Scalar {
    fn reduce_wide(okm: &[u8; 64]) -> Self {
        const MODULUS: NonZero<U512> = NonZero::from_uint(U512::from_be_hex("0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));
        let bytes = U512::from_be_slice(okm);
        let reduced = bytes % MODULUS;
        let (_, lo) = reduced.split();
        Scalar::from_uint_unchecked(lo)
    }
}

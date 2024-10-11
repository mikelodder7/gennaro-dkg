//! Traits for the BLS12-381 curve.
use crate::traits::*;
use blsful::inner_types::*;
use elliptic_curve::hash2curve::ExpandMsgXmd;

impl GroupHasher for G1Projective {
    fn hash_to_curve(msg: &[u8]) -> Self {
        const DST: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";
        G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, DST)
    }
}

impl GroupHasher for G2Projective {
    fn hash_to_curve(msg: &[u8]) -> Self {
        const DST: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_RO_";
        G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, DST)
    }
}

impl ReduceWide<64> for Scalar {
    fn reduce_wide(wide: &[u8; 64]) -> Self {
        Scalar::from_bytes_wide(wide)
    }
}

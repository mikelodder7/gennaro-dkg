//! Extensions for jubjub
use crate::traits::*;
use elliptic_curve::hash2curve::ExpandMsgXmd;
use jubjub_plus::{ExtendedPoint, Scalar, SubgroupPoint};

impl GroupHasher for SubgroupPoint {
    fn hash_to_curve(msg: &[u8]) -> Self {
        const DST: &[u8] = b"jubjub_XMD:SHA-256_HP_RO_";
        SubgroupPoint::from(ExtendedPoint::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, DST))
    }
}

impl GroupHasher for ExtendedPoint {
    fn hash_to_curve(msg: &[u8]) -> Self {
        const DST: &[u8] = b"jubjub_XMD:SHA-256_HP_RO_";
        ExtendedPoint::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, DST)
    }
}

impl ReduceWide<64> for Scalar {
    fn reduce_wide(okm: &[u8; 64]) -> Self {
        Scalar::from_bytes_wide(okm)
    }
}

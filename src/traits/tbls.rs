//! Traits for the BLS12-381 curve.
use crate::traits::*;
use blsful::inner_types::*;
use elliptic_curve::hash2curve::ExpandMsgXmd;

impl GroupHasher for G1Projective {
    fn hash_to_curve(msg: &[u8]) -> Self {
        const DST: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";
        G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&msg, DST)
    }
}

impl GroupHasher for G2Projective {
    fn hash_to_curve(msg: &[u8]) -> Self {
        const DST: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_RO_";
        G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&msg, DST)
    }
}

impl SumOfProducts for G1Projective {
    fn sum_of_products(group: &[Self], field: &[Self::Scalar]) -> Self {
        G1Projective::sum_of_products(group, field)
    }
}

impl SumOfProducts for G2Projective {
    fn sum_of_products(group: &[Self], field: &[Self::Scalar]) -> Self {
        G2Projective::sum_of_products(group, field)
    }
}

impl ReduceWide<64> for Scalar {
    fn reduce_wide(wide: &[u8; 64]) -> Self {
        Scalar::from_bytes_wide(wide)
    }
}

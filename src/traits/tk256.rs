//! Traits for the secp256k1 curve.
use crate::traits::*;
use elliptic_curve::{
    bigint::U512,
    hash2curve::{ExpandMsgXmd, GroupDigest},
    ops::Reduce,
};
use k256::{ProjectivePoint, Scalar, Secp256k1, WideBytes};

impl GroupHasher for ProjectivePoint {
    fn hash_to_curve(msg: &[u8]) -> Self {
        const DST: &[u8] = b"secp256k1_XMD:SHA-256_SSWU_RO_";
        let msg = [msg];
        let dst = [DST];
        Secp256k1::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}

impl SumOfProducts for ProjectivePoint {
    fn sum_of_products(group: &[Self], field: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<Scalar, ProjectivePoint, 4>(group, field)
    }
}

impl AsLimbs<4> for Scalar {
    fn as_limbs(&self) -> [u64; 4] {
        scalar_primitive_to_limbs::<4, 8, Secp256k1>(*self)
    }
}

impl ReduceWide<64> for Scalar {
    fn reduce_wide(okm: &[u8; 64]) -> Self {
        let bytes = WideBytes::from_slice(okm);
        <Scalar as Reduce<U512>>::reduce_bytes(bytes)
    }
}

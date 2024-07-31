use crate::traits::*;
use elliptic_curve::{
    bigint::{NonZero, U768},
    hash2curve::{ExpandMsgXmd, GroupDigest},
    scalar::FromUintUnchecked,
};
use p384::{NistP384, ProjectivePoint, Scalar};

impl GroupHasher for ProjectivePoint {
    fn hash_to_curve(msg: &[u8]) -> Self {
        const DST: &[u8] = b"P384_XMD:SHA-384_SSWU_RO_";
        let msg = [msg];
        let dst = [DST];
        NistP384::hash_from_bytes::<ExpandMsgXmd<sha2::Sha384>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}

impl SumOfProducts for ProjectivePoint {
    fn sum_of_products(group: &[Self], field: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<Scalar, ProjectivePoint, 6>(group, field)
    }
}

impl AsLimbs<6> for Scalar {
    fn as_limbs(&self) -> [u64; 6] {
        scalar_primitive_to_limbs::<6, 12, NistP384>(*self)
    }
}

impl ReduceWide<96> for Scalar {
    fn reduce_wide(okm: &[u8; 96]) -> Self {
        const MODULUS: NonZero<U768> = NonZero::from_uint(U768::from_be_hex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"));
        let bytes = U768::from_be_slice(okm);
        let reduced = bytes % MODULUS;
        let (_, lo) = reduced.split();
        Scalar::from_uint_unchecked(lo)
    }
}

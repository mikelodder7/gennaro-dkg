//! Traits for the ed448 curve.
use crate::traits::*;
use ed448_goldilocks_plus::{EdwardsPoint, Scalar, WideScalarBytes};

impl GroupHasher for EdwardsPoint {
    fn hash_to_curve(msg: &[u8]) -> Self {
        EdwardsPoint::hash_with_defaults(msg)
    }
}

impl SumOfProducts for EdwardsPoint {
    fn sum_of_products(group: &[Self], field: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<Scalar, Self, 7>(group, field)
    }
}

impl AsLimbs<7> for Scalar {
    fn as_limbs(&self) -> [u64; 7] {
        struct InnerScalar(pub(crate) [u32; 14]);
        let inner_scalar = unsafe { std::mem::transmute::<Self, InnerScalar>(*self) };
        let mut out = [0u64; 7];
        let mut i = 0;
        let mut j = 0;
        while i < inner_scalar.0.len() && j < out.len() {
            out[j] = (inner_scalar.0[i + 1] as u64) << 32 | (inner_scalar.0[i] as u64);
            i += 2;
            j += 1;
        }
        out
    }
}

impl ReduceWide<114> for Scalar {
    fn reduce_wide(okm: &[u8; 114]) -> Self {
        Scalar::from_bytes_mod_order_wide(WideScalarBytes::from_slice(okm))
    }
}

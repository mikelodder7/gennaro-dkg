//! Traits for the ed448 curve.
use crate::traits::*;
use ed448_goldilocks_plus::{EdwardsPoint, Scalar, WideScalarBytes};

impl GroupHasher for EdwardsPoint {
    fn hash_to_curve(msg: &[u8]) -> Self {
        EdwardsPoint::hash_with_defaults(msg)
    }
}

impl ReduceWide<114> for Scalar {
    fn reduce_wide(okm: &[u8; 114]) -> Self {
        Scalar::from_bytes_mod_order_wide(WideScalarBytes::from_slice(okm))
    }
}

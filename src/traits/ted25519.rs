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

// impl SumOfProducts for vsss_rs::curve25519_dalek::ristretto::RistrettoPoint {
//     fn sum_of_products(group: &[Self], field: &[Self::Scalar]) -> Self {
//         sum_of_products_pippenger::<
//             vsss_rs::curve25519_dalek::Scalar,
//             vsss_rs::curve25519_dalek::ristretto::RistrettoPoint,
//             4,
//         >(group, field)
//     }
// }
//
// impl GroupHasher for vsss_rs::curve25519_dalek::edwards::EdwardsPoint {
//     fn hash_to_curve(msg: &[u8]) -> Self {
//         const DST: &[u8] = b"edwards25519_XMD:SHA-512_ELL2_RO_";
//         let pt = curve25519_dalek_ml::edwards::EdwardsPoint::hash_to_curve::<
//             ExpandMsgXmd<sha2::Sha512>,
//         >(msg, DST);
//         unsafe { std::mem::transmute(pt) }
//     }
// }
//
// impl SumOfProducts for vsss_rs::curve25519_dalek::edwards::EdwardsPoint {
//     fn sum_of_products(group: &[Self], field: &[Self::Scalar]) -> Self {
//         sum_of_products_pippenger::<
//             vsss_rs::curve25519_dalek::Scalar,
//             vsss_rs::curve25519_dalek::edwards::EdwardsPoint,
//             4,
//         >(group, field)
//     }
// }
//
// impl AsLimbs<4> for vsss_rs::curve25519_dalek::Scalar {
//     fn as_limbs(&self) -> [u64; 4] {
//         let mut limbs = [0u64; 4];
//         let bytes = self.to_bytes();
//         limbs[0] = u64::from_le_bytes([
//             bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
//         ]);
//         limbs[1] = u64::from_le_bytes([
//             bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
//         ]);
//         limbs[2] = u64::from_le_bytes([
//             bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
//         ]);
//         limbs[3] = u64::from_le_bytes([
//             bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
//         ]);
//         limbs
//     }
// }

impl ReduceWide<64> for WrappedScalar {
    fn reduce_wide(okm: &[u8; 64]) -> Self {
        WrappedScalar(vsss_rs::curve25519_dalek::Scalar::from_bytes_mod_order_wide(okm))
    }
}

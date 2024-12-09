#[cfg(feature = "bls")]
pub mod tbls;
#[cfg(feature = "curve25519")]
pub mod ted25519;
#[cfg(feature = "ed448")]
pub mod ted448;
#[cfg(feature = "jubjub")]
pub mod tjubjub;
#[cfg(feature = "k256")]
pub mod tk256;
#[cfg(feature = "p256")]
pub mod tp256;
#[cfg(feature = "p384")]
pub mod tp384;

use elliptic_curve::{Group, PrimeField};

/// A trait for a group that use a hash function to create a group element from
/// an arbitrary message
pub trait GroupHasher: Group {
    /// Hash a message to a group element
    fn hash_to_curve(msg: &[u8]) -> Self;
}

/// A trait for a prime field that can reduce a wide number of bytes to a prime field element.
/// The number of bytes is expected to be 2*bits where bits is the number of bits in the prime field.
pub trait ReduceWide<const N: usize>: PrimeField {
    /// Reduce a wide number of bytes to a prime field element.
    fn reduce_wide(okm: &[u8; N]) -> Self;
}

use crate::{deserialize_g_vec, deserialize_scalar, serialize_g_vec, serialize_scalar};
use serde::{Deserialize, Serialize};
use vsss_rs::{
    elliptic_curve::{group::GroupEncoding, Group},
    *,
};

/// The inner representation of the secret shares
pub type InnerShare = Vec<u8>;

/// The pedersen result used by the DKG
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GennaroDkgPedersenResult<G: Group + GroupEncoding + Default> {
    /// The blinder used to blind the secret shares
    #[serde(
        serialize_with = "serialize_scalar",
        deserialize_with = "deserialize_scalar"
    )]
    pub blinder: G::Scalar,
    /// The secret shares
    pub secret_shares: Vec<InnerShare>,
    /// The blinder shares derived from splitting `blinder`
    pub blinder_shares: Vec<InnerShare>,
    /// The feldman verifiers
    #[serde(
        serialize_with = "serialize_g_vec",
        deserialize_with = "deserialize_g_vec"
    )]
    pub feldman_verifier_set: Vec<G>,
    /// The pedersen verifiers
    #[serde(
        serialize_with = "serialize_g_vec",
        deserialize_with = "deserialize_g_vec"
    )]
    pub pedersen_verifier_set: Vec<G>,
}

impl<G: Group + GroupEncoding + Default> PedersenResult<G, [u8; 1], u8, InnerShare>
    for GennaroDkgPedersenResult<G>
{
    type ShareSet = Vec<InnerShare>;
    type FeldmanVerifierSet = Vec<G>;
    type PedersenVerifierSet = Vec<G>;

    fn new(
        blinder: G::Scalar,
        secret_shares: Self::ShareSet,
        blinder_shares: Self::ShareSet,
        feldman_verifier_set: Self::FeldmanVerifierSet,
        pedersen_verifier_set: Self::PedersenVerifierSet,
    ) -> Self {
        Self {
            blinder,
            secret_shares,
            blinder_shares,
            feldman_verifier_set,
            pedersen_verifier_set,
        }
    }

    fn blinder(&self) -> G::Scalar {
        self.blinder
    }

    fn secret_shares(&self) -> &Self::ShareSet {
        &self.secret_shares
    }

    fn blinder_shares(&self) -> &Self::ShareSet {
        &self.blinder_shares
    }

    fn feldman_verifier_set(&self) -> &Self::FeldmanVerifierSet {
        &self.feldman_verifier_set
    }

    fn pedersen_verifier_set(&self) -> &Self::PedersenVerifierSet {
        &self.pedersen_verifier_set
    }
}

impl<G: Group + GroupEncoding + Default> From<StdPedersenResult<G, [u8; 1], u8, InnerShare>>
    for GennaroDkgPedersenResult<G>
{
    fn from(value: StdPedersenResult<G, [u8; 1], u8, InnerShare>) -> Self {
        Self {
            blinder: value.blinder(),
            secret_shares: value.secret_shares().clone(),
            blinder_shares: value.blinder_shares().clone(),
            feldman_verifier_set: value.feldman_verifier_set().clone(),
            pedersen_verifier_set: value.pedersen_verifier_set().clone(),
        }
    }
}

mod round1;
mod round2;
mod round3;
mod round4;
mod round5;

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::num::NonZeroUsize;

use crate::*;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use vsss_rs::pedersen;
use vsss_rs::{
    elliptic_curve::{ff::Field, group::GroupEncoding, Group},
    FeldmanVerifierSet, PedersenVerifierSet, Share,
};

/// Secret Participant type
pub type SecretParticipant<G> = Participant<SecretParticipantImpl<G>, G>;

/// Refresh Participant type
pub type RefreshParticipant<G> = Participant<RefreshParticipantImpl<G>, G>;

/// Participant implementation
pub trait ParticipantImpl<G: Group + GroupEncoding + Default> {
    /// Get the participants secret
    fn secret(rng: impl RngCore + CryptoRng) -> G::Scalar;
    /// Check the feldman verifier at position 0.
    /// During a new or update key gen, this value is not the identity
    /// during a refresh, it must be identity
    fn check_feldman_verifier(verifier: G) -> bool;
    /// Check the public key.
    /// During a new or update key gen, this value is not the identity
    /// during a refresh, it must be identity
    fn check_public_key(key: G, computed: G) -> bool;
}

/// A DKG participant FSM
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant<I: ParticipantImpl<G>, G: Group + GroupEncoding + Default> {
    id: usize,
    #[serde(bound(serialize = "GennaroDkgPedersenResult<G>: Serialize"))]
    #[serde(bound(deserialize = "GennaroDkgPedersenResult<G>: Deserialize<'de>"))]
    components: GennaroDkgPedersenResult<G>,
    threshold: usize,
    limit: usize,
    round: Round,
    #[serde(
        serialize_with = "serialize_scalar",
        deserialize_with = "deserialize_scalar"
    )]
    secret_share: G::Scalar,
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    public_key: G,
    #[serde(bound(serialize = "Round1BroadcastData<G>: Serialize"))]
    #[serde(bound(deserialize = "Round1BroadcastData<G>: Deserialize<'de>"))]
    round1_broadcast_data: BTreeMap<usize, Round1BroadcastData<G>>,
    round1_p2p_data: BTreeMap<usize, Round1P2PData>,
    valid_participant_ids: BTreeSet<usize>,
    participant_impl: I,
}

impl<I, G> Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: Group + GroupEncoding + Default,
{
    /// Create a new participant to generate a new key share
    pub fn new(id: NonZeroUsize, parameters: Parameters<G>) -> DkgResult<Self> {
        let rng = rand_core::OsRng;
        let secret = I::secret(rng);
        let blinder = G::Scalar::random(rng);
        Self::initialize(id, parameters, secret, blinder)
    }

    /// Create a new participant with an existing secret.
    ///
    /// This allows the polynomial to be updated versus refreshing the shares.
    pub fn with_secret(
        id: NonZeroUsize,
        secret: G::Scalar,
        parameters: Parameters<G>,
    ) -> DkgResult<Self> {
        let mut rng = rand_core::OsRng;
        let blinder = G::Scalar::random(&mut rng);
        Self::initialize(id, parameters, secret, blinder)
    }

    fn initialize(
        id: NonZeroUsize,
        parameters: Parameters<G>,
        secret: G::Scalar,
        blinder: G::Scalar,
    ) -> DkgResult<Self> {
        let rng = rand_core::OsRng;
        let components = pedersen::split_secret(
            parameters.threshold,
            parameters.limit,
            secret,
            Some(blinder),
            Some(parameters.message_generator),
            Some(parameters.blinder_generator),
            rng,
        )?;
        let components = GennaroDkgPedersenResult::from(components);

        if (components
            .pedersen_verifier_set
            .secret_generator()
            .is_identity()
            | components
                .pedersen_verifier_set
                .blinder_generator()
                .is_identity())
        .into()
        {
            return Err(crate::Error::InitializationError(
                "Invalid generators".to_string(),
            ));
        }
        let pedersen_commitments = components.pedersen_verifier_set.blind_verifiers();
        let feldman_commitments = components.feldman_verifier_set.verifiers();
        if pedersen_commitments.iter().any(|c| c.is_identity().into())
            || feldman_commitments
                .iter()
                .skip(1)
                .any(|c| c.is_identity().into())
            || !I::check_feldman_verifier(feldman_commitments[0])
        {
            return Err(crate::Error::InitializationError(
                "Invalid commitments".to_string(),
            ));
        }
        if components.secret_shares.iter().any(|s| s.is_zero().into())
            || components.blinder_shares.iter().any(|s| s.is_zero().into())
        {
            return Err(crate::Error::InitializationError(
                "Invalid shares".to_string(),
            ));
        }
        Ok(Self {
            id: id.get(),
            components,
            threshold: parameters.threshold,
            limit: parameters.limit,
            round: Round::One,
            round1_broadcast_data: BTreeMap::new(),
            round1_p2p_data: BTreeMap::new(),
            secret_share: G::Scalar::ZERO,
            public_key: G::identity(),
            valid_participant_ids: BTreeSet::new(),
            participant_impl: Default::default(),
        })
    }

    /// The identifier associated with this secret_participant
    pub fn get_id(&self) -> usize {
        self.id
    }

    /// Returns true if this secret_participant is complete
    pub fn completed(&self) -> bool {
        self.round == Round::Five
    }

    /// Computed secret share.
    /// This value is useless until all rounds have been run
    /// so [`None`] is returned until completion
    pub fn get_secret_share(&self) -> Option<G::Scalar> {
        if self.round == Round::Five {
            Some(self.secret_share)
        } else {
            None
        }
    }

    /// Computed public key
    /// This value is useless until all rounds have been run
    /// so [`None`] is returned until completion
    pub fn get_public_key(&self) -> Option<G> {
        if self.round == Round::Five {
            Some(self.public_key)
        } else {
            None
        }
    }
}

/// Secret Participant Implementation
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SecretParticipantImpl<G>(PhantomData<G>);

impl<G: Group + GroupEncoding + Default> ParticipantImpl<G> for SecretParticipantImpl<G> {
    fn secret(mut rng: impl RngCore) -> <G as Group>::Scalar {
        G::Scalar::random(&mut rng)
    }

    fn check_feldman_verifier(verifier: G) -> bool {
        verifier.is_identity().unwrap_u8() == 0u8
    }

    fn check_public_key(key: G, computed: G) -> bool {
        key.is_identity().unwrap_u8() == 0u8 && key != computed
    }
}

/// Refresh Participant Implementation
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RefreshParticipantImpl<G>(PhantomData<G>);

impl<G: Group + GroupEncoding + Default> ParticipantImpl<G> for RefreshParticipantImpl<G> {
    fn secret(mut _rng: impl RngCore) -> <G as Group>::Scalar {
        G::Scalar::ZERO
    }

    fn check_feldman_verifier(verifier: G) -> bool {
        verifier.is_identity().into()
    }

    fn check_public_key(key: G, computed: G) -> bool {
        (key.is_identity() & computed.is_identity()).into()
    }
}

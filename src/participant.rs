mod round1;
mod round2;
mod round3;
mod round4;
mod round5;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use crate::*;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use soteria_rs::Protected;
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
    #[serde(with = "secret_share")]
    secret_share: Arc<Mutex<Protected>>,
    #[serde(with = "secret_share")]
    blind_share: Arc<Mutex<Protected>>,
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    public_key: G,
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    blind_key: G,
    #[serde(bound(serialize = "Round1BroadcastData<G>: Serialize"))]
    #[serde(bound(deserialize = "Round1BroadcastData<G>: Deserialize<'de>"))]
    round1_broadcast_data: BTreeMap<usize, Round1BroadcastData<G>>,
    #[serde(with = "protected")]
    round1_p2p_data: BTreeMap<usize, Arc<Mutex<Protected>>>,
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
        parameters: Parameters<G>,
        share: G::Scalar,
        shares_ids: &[G::Scalar],
        index: usize,
    ) -> DkgResult<Self> {
        let mut rng = rand_core::OsRng;
        let blinder = G::Scalar::random(&mut rng);
        let secret = Self::lagrange_interpolation(share, shares_ids, index)?;
        Self::initialize(id, parameters, secret, blinder)
    }

    fn initialize(
        id: NonZeroUsize,
        parameters: Parameters<G>,
        secret: G::Scalar,
        blinder: G::Scalar,
    ) -> DkgResult<Self> {
        let rng = rand_core::OsRng;

        let components = pedersen::split_secret::<G, u8, InnerShare>(
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
            return Err(Error::InitializationError("Invalid generators".to_string()));
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
            return Err(Error::InitializationError(
                "Invalid commitments".to_string(),
            ));
        }
        if components.secret_shares.iter().any(|s| s.is_zero().into())
            || components.blinder_shares.iter().any(|s| s.is_zero().into())
        {
            return Err(Error::InitializationError("Invalid shares".to_string()));
        }
        Ok(Self {
            id: id.get(),
            components,
            threshold: parameters.threshold,
            limit: parameters.limit,
            round: Round::One,
            round1_broadcast_data: BTreeMap::new(),
            round1_p2p_data: BTreeMap::new(),
            secret_share: Arc::new(Mutex::new(Protected::field_element(G::Scalar::ZERO))),
            blind_share: Arc::new(Mutex::new(Protected::field_element(G::Scalar::ZERO))),
            public_key: G::identity(),
            blind_key: G::identity(),
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

    /// Return the current round
    pub fn get_round(&self) -> Round {
        self.round
    }

    /// Return the set threshold
    pub fn get_threshold(&self) -> usize {
        self.threshold
    }

    /// Return the set limit
    pub fn get_limit(&self) -> usize {
        self.limit
    }

    /// Computed secret share.
    /// This value is useless until at least 2 rounds have been run
    /// so [`None`] is returned until completion
    pub fn get_secret_share(&self) -> Option<G::Scalar> {
        if self.round >= Round::Two {
            let mut protected = self.secret_share.lock().ok()?;
            let u = protected.unprotect()?;
            u.field_element::<G::Scalar>().ok()
        } else {
            None
        }
    }

    /// Computed blind share.
    /// This value is useless until at least 2 rounds have been run
    /// so [`None`] is returned until completion
    /// This is not normally used outside this protocol
    /// however, it can be used as a second secret share if needed
    /// thereby allowing to extract a 2nd share from one run of the protocol
    pub fn get_blind_share(&self) -> Option<G::Scalar> {
        if self.round >= Round::Two {
            let mut protected = self.blind_share.lock().ok()?;
            let u = protected.unprotect()?;
            u.field_element::<G::Scalar>().ok()
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

    /// Return the list of valid participant ids
    pub fn get_valid_participant_ids(&self) -> &BTreeSet<usize> {
        &self.valid_participant_ids
    }

    fn lagrange_interpolation(
        share: G::Scalar,
        shares_ids: &[G::Scalar],
        index: usize,
    ) -> DkgResult<G::Scalar> {
        let mut set = HashSet::new();
        for id in shares_ids {
            if !set.insert(id.to_repr().as_ref().to_vec()) {
                return Err(Error::InitializationError(format!(
                    "duplicate id found {:?}",
                    id
                )));
            }
        }

        let mut basis = G::Scalar::ONE;
        for (j, x_j) in shares_ids.iter().enumerate() {
            if j == index {
                continue;
            }
            let denominator = *x_j - shares_ids[index];
            basis *= *x_j * denominator.invert().unwrap();
        }

        Ok(basis * share)
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

#[cfg(test)]
mod tests {
    use super::*;
    use blsful::inner_types::*;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use vsss_rs::{Pedersen, PedersenResult, Share};

    #[test]
    fn reconstruct_blind_key() {
        let mut rng = ChaCha12Rng::from_seed([1u8; 32]);
        let secrets = [
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        ];
        let blind_secrets = [
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        ];

        let pedersen_verifier_set0 =
            vsss_rs::StdVsss::<G1Projective, u8, InnerShare>::split_secret_with_blind_verifier(
                2,
                3,
                secrets[0],
                Some(blind_secrets[0]),
                None,
                None,
                &mut rng,
            )
            .unwrap();

        let pedersen_verifier_set1 =
            vsss_rs::StdVsss::<G1Projective, u8, InnerShare>::split_secret_with_blind_verifier(
                2,
                3,
                secrets[1],
                Some(blind_secrets[1]),
                None,
                None,
                &mut rng,
            )
            .unwrap();

        let pedersen_verifier_set2 =
            vsss_rs::StdVsss::<G1Projective, u8, InnerShare>::split_secret_with_blind_verifier(
                2,
                3,
                secrets[2],
                Some(blind_secrets[2]),
                None,
                None,
                &mut rng,
            )
            .unwrap();

        let secret_shares0 = pedersen_verifier_set0.secret_shares();
        let blinder_shares0 = pedersen_verifier_set0.blinder_shares();
        let pedersen_verifiers0 = pedersen_verifier_set0.pedersen_verifier_set();
        let blind_verifiers0 = pedersen_verifiers0.blind_verifiers();
        let secret_verifiers0 = pedersen_verifier_set0.feldman_verifier_set().verifiers();

        assert_eq!(
            blind_verifiers0[0],
            pedersen_verifiers0.secret_generator() * secrets[0]
                + pedersen_verifiers0.blinder_generator() * blind_secrets[0]
        );
        assert_eq!(
            secret_verifiers0[0],
            pedersen_verifiers0.secret_generator() * secrets[0]
        );

        let blind_key0 = blind_verifiers0[0] - secret_verifiers0[0];
        assert_eq!(
            blind_key0,
            pedersen_verifiers0.blinder_generator() * blind_secrets[0]
        );

        let secret_shares1 = pedersen_verifier_set1.secret_shares();
        let blinder_shares1 = pedersen_verifier_set1.blinder_shares();
        let pedersen_verifiers1 = pedersen_verifier_set1.pedersen_verifier_set();
        let blind_verifiers1 = pedersen_verifiers1.blind_verifiers();
        let secret_verifiers1 = pedersen_verifier_set1.feldman_verifier_set().verifiers();

        assert_eq!(
            blind_verifiers1[0],
            pedersen_verifiers1.secret_generator() * secrets[1]
                + pedersen_verifiers1.blinder_generator() * blind_secrets[1]
        );
        assert_eq!(
            secret_verifiers1[0],
            pedersen_verifiers1.secret_generator() * secrets[1]
        );

        let blind_key1 = blind_verifiers1[0] - secret_verifiers1[0];
        assert_eq!(
            blind_key1,
            pedersen_verifiers1.blinder_generator() * blind_secrets[1]
        );

        let secret_shares2 = pedersen_verifier_set2.secret_shares();
        let blinder_shares2 = pedersen_verifier_set2.blinder_shares();
        let pedersen_verifiers2 = pedersen_verifier_set2.pedersen_verifier_set();
        let blind_verifiers2 = pedersen_verifiers2.blind_verifiers();
        let secret_verifiers2 = pedersen_verifier_set2.feldman_verifier_set().verifiers();

        assert_eq!(
            blind_verifiers2[0],
            pedersen_verifiers2.secret_generator() * secrets[2]
                + pedersen_verifiers2.blinder_generator() * blind_secrets[2]
        );
        assert_eq!(
            secret_verifiers2[0],
            pedersen_verifiers2.secret_generator() * secrets[2]
        );

        let blind_key2 = blind_verifiers2[0] - secret_verifiers2[0];
        assert_eq!(
            blind_key2,
            pedersen_verifiers2.blinder_generator() * blind_secrets[2]
        );

        let secret_share0 = [
            <InnerShare as Share>::as_field_element::<Scalar>(&secret_shares0[0]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&secret_shares1[0]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&secret_shares2[0]).unwrap(),
        ]
        .iter()
        .sum::<Scalar>();
        let secret_share1 = [
            <InnerShare as Share>::as_field_element::<Scalar>(&secret_shares0[1]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&secret_shares1[1]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&secret_shares2[1]).unwrap(),
        ]
        .iter()
        .sum::<Scalar>();

        let secret_share2 = [
            <InnerShare as Share>::as_field_element::<Scalar>(&secret_shares0[2]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&secret_shares1[2]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&secret_shares2[2]).unwrap(),
        ]
        .iter()
        .sum::<Scalar>();

        let blind_share0 = [
            <InnerShare as Share>::as_field_element::<Scalar>(&blinder_shares0[0]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&blinder_shares1[0]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&blinder_shares2[0]).unwrap(),
        ]
        .iter()
        .sum::<Scalar>();
        let blind_share1 = [
            <InnerShare as Share>::as_field_element::<Scalar>(&blinder_shares0[1]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&blinder_shares1[1]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&blinder_shares2[1]).unwrap(),
        ]
        .iter()
        .sum::<Scalar>();
        let blind_share2 = [
            <InnerShare as Share>::as_field_element::<Scalar>(&blinder_shares0[2]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&blinder_shares1[2]).unwrap(),
            <InnerShare as Share>::as_field_element::<Scalar>(&blinder_shares2[2]).unwrap(),
        ]
        .iter()
        .sum::<Scalar>();

        let public_key = [
            pedersen_verifier_set0.feldman_verifier_set().verifiers()[0],
            pedersen_verifier_set1.feldman_verifier_set().verifiers()[0],
            pedersen_verifier_set2.feldman_verifier_set().verifiers()[0],
        ]
        .iter()
        .sum::<G1Projective>();

        let original_secret: Scalar = vsss_rs::combine_shares(&[
            <InnerShare as Share>::from_field_element(1u8, secret_share0).unwrap(),
            <InnerShare as Share>::from_field_element(2u8, secret_share1).unwrap(),
            <InnerShare as Share>::from_field_element(3u8, secret_share2).unwrap(),
        ])
        .unwrap();
        assert_eq!(original_secret, secrets.iter().sum());
        assert_eq!(public_key, G1Projective::GENERATOR * original_secret);

        let blind_key = [
            pedersen_verifier_set0
                .pedersen_verifier_set()
                .blind_verifiers()[0],
            pedersen_verifier_set1
                .pedersen_verifier_set()
                .blind_verifiers()[0],
            pedersen_verifier_set2
                .pedersen_verifier_set()
                .blind_verifiers()[0],
        ]
        .iter()
        .sum::<G1Projective>()
            - public_key;

        let original_blinder: Scalar = vsss_rs::combine_shares(&[
            <InnerShare as Share>::from_field_element(1u8, blind_share0).unwrap(),
            <InnerShare as Share>::from_field_element(2u8, blind_share1).unwrap(),
            <InnerShare as Share>::from_field_element(3u8, blind_share2).unwrap(),
        ])
        .unwrap();
        assert_eq!(original_blinder, blind_secrets.iter().sum());
        assert_eq!(blind_key0 + blind_key1 + blind_key2, blind_key);
    }
}

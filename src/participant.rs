mod round0;
mod round1;
mod round2;
mod round3;
mod round4;

use std::collections::{BTreeMap, HashSet};
use std::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use crate::*;
use elliptic_curve::subtle::ConstantTimeEq;
use elliptic_curve::{group::GroupEncoding, Field, Group};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use vsss_rs::subtle::Choice;
use vsss_rs::{ParticipantNumberGenerator, Polynomial};

/// Secret Participant type
pub type SecretParticipant<G> = Participant<SecretParticipantImpl<G>, G>;

/// Refresh Participant type
pub type RefreshParticipant<G> = Participant<RefreshParticipantImpl<G>, G>;

/// Participant implementation
pub trait ParticipantImpl<G>
where
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    /// Get the participant type
    fn get_type(&self) -> ParticipantType;
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
#[derive(Clone)]
pub struct Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    ordinal: usize,
    id: G::Scalar,
    threshold: usize,
    limit: usize,
    round: Round,
    message_generator: G,
    blinder_generator: G,
    secret_share: G::Scalar,
    secret_shares: Vec<(G::Scalar, G::Scalar)>,
    blind_share: G::Scalar,
    blinder_shares: Vec<(G::Scalar, G::Scalar)>,
    feldman_verifier_set: Vec<G>,
    pedersen_verifier_set: Vec<G>,
    public_key: G,
    blind_key: G,
    powers_of_i: Vec<G::Scalar>,
    received_round0_data: BTreeMap<usize, Round0Data<G>>,
    received_round1_data: BTreeMap<usize, Round1Data<G>>,
    received_round2_data: BTreeMap<usize, Round2Data<G>>,
    received_round3_data: BTreeMap<usize, Round3Data<G>>,
    received_round4_data: BTreeMap<usize, Round4Data<G>>,
    valid_participant_ids: BTreeMap<usize, G::Scalar>,
    all_participant_ids: BTreeMap<usize, G::Scalar>,
    participant_impl: I,
    transcript: Transcript,
}

impl<I, G> Debug for Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Participant")
            .field("id", &self.id)
            .field("threshold", &self.threshold)
            .field("limit", &self.limit)
            .field("round", &self.round)
            .field("message_generator", &self.message_generator)
            .field("blinder_generator", &self.blinder_generator)
            .field("secret_share", &self.secret_share)
            .field("secret_shares", &self.secret_shares)
            .field("blind_share", &self.blind_share)
            .field("blinder_shares", &self.blinder_shares)
            .field("feldman_verifier_set", &self.feldman_verifier_set)
            .field("pedersen_verifier_set", &self.pedersen_verifier_set)
            .field("public_key", &self.public_key)
            .field("blind_key", &self.blind_key)
            .field("received_round0_data", &self.received_round0_data)
            .field("received_round1_data", &self.received_round1_data)
            .field("received_round2_data", &self.received_round2_data)
            .field("received_round3_data", &self.received_round3_data)
            .field("received_round4_data", &self.received_round4_data)
            .field("valid_participant_ids", &self.valid_participant_ids)
            .field("all_participant_ids", &self.all_participant_ids)
            .finish()
    }
}

impl<I, G> Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    /// Create a new participant to generate a new key share
    pub fn new<P: ParticipantNumberGenerator<G::Scalar> + Default>(
        id: G::Scalar,
        parameters: &Parameters<G, P>,
    ) -> DkgResult<Self> {
        let rng = rand_core::OsRng;
        let secret = I::secret(rng);
        let blinder = G::Scalar::random(rng);
        Self::initialize(id, parameters, secret, blinder)
    }

    /// Create a new participant with an existing secret.
    ///
    /// This allows the polynomial to be updated versus refreshing the shares.
    pub fn with_secret<P: ParticipantNumberGenerator<G::Scalar> + Default>(
        id: G::Scalar,
        parameters: &Parameters<G, P>,
        share: G::Scalar,
        shares_ids: &[G::Scalar],
    ) -> DkgResult<Self> {
        let mut rng = rand_core::OsRng;
        let blinder = G::Scalar::random(&mut rng);
        let secret = share * Self::lagrange(share, shares_ids);
        Self::initialize(id, parameters, secret, blinder)
    }

    fn initialize<P: ParticipantNumberGenerator<G::Scalar> + Default>(
        id: G::Scalar,
        parameters: &Parameters<G, P>,
        secret: G::Scalar,
        blinder: G::Scalar,
    ) -> DkgResult<Self> {
        let rng = rand_core::OsRng;

        if parameters.threshold > parameters.limit {
            return Err(Error::InitializationError(
                "Threshold greater than limit".to_string(),
            ));
        }
        if parameters.threshold < 1 {
            return Err(Error::InitializationError(
                "Threshold less than 1".to_string(),
            ));
        }
        if parameters.message_generator.is_identity().into() {
            return Err(Error::InitializationError(
                "Invalid message generator".to_string(),
            ));
        }
        if parameters.blinder_generator.is_identity().into() {
            return Err(Error::InitializationError(
                "Invalid blinder generator".to_string(),
            ));
        }

        let mut secret_polynomial =
            <Vec<G::Scalar> as Polynomial<G::Scalar>>::create(parameters.threshold);
        secret_polynomial.fill(secret, rng, parameters.limit)?;
        let mut blinder_polynomial =
            <Vec<G::Scalar> as Polynomial<G::Scalar>>::create(parameters.threshold);
        blinder_polynomial.fill(blinder, rng, parameters.limit)?;

        let mut pedersen_verifier_set = vec![G::identity(); parameters.threshold];
        let mut feldman_verifier_set = vec![G::identity(); parameters.threshold];

        for ((pedersen, feldman), (secret_coefficient, blinder_coefficient)) in
            pedersen_verifier_set
                .iter_mut()
                .zip(feldman_verifier_set.iter_mut())
                .zip(secret_polynomial.iter().zip(blinder_polynomial.iter()))
        {
            *feldman = parameters.message_generator * secret_coefficient;
            *pedersen = *feldman + parameters.blinder_generator * blinder_coefficient;
        }

        let mut secret_shares = vec![(G::Scalar::ZERO, G::Scalar::ZERO); parameters.limit];
        let mut blinder_shares = vec![(G::Scalar::ZERO, G::Scalar::ZERO); parameters.limit];

        let mut all_participant_ids = BTreeMap::new();
        let mut dup_check = HashSet::new();
        let mut ordinal = 0;
        for (i, (secret_share, blinder_share)) in secret_shares
            .iter_mut()
            .zip(blinder_shares.iter_mut())
            .enumerate()
        {
            let share_id = parameters
                .participant_number_generator
                .get_participant_id(i);
            if !dup_check.insert(share_id.to_repr().as_ref().to_vec()) {
                return Err(Error::InitializationError(format!(
                    "Duplicate id found {:?}",
                    share_id
                )));
            }
            if share_id == id {
                ordinal = i;
            }
            all_participant_ids.insert(i, share_id);
            *secret_share = (
                share_id,
                secret_polynomial
                    .iter()
                    .rfold(G::Scalar::ZERO, |acc, c| acc * share_id + c),
            );
            *blinder_share = (
                share_id,
                blinder_polynomial
                    .iter()
                    .rfold(G::Scalar::ZERO, |acc, c| acc * share_id + c),
            );
        }
        if !all_participant_ids.contains_key(&ordinal) {
            return Err(Error::InitializationError(
                "Id not found in participant ids".to_string(),
            ));
        }

        let mut powers_of_i = vec![G::Scalar::ONE; parameters.threshold];
        powers_of_i[1] = id;
        for i in 2..parameters.threshold {
            powers_of_i[i] = powers_of_i[i - 1] * id;
        }

        if pedersen_verifier_set.iter().any(|c| c.is_identity().into())
            || feldman_verifier_set
                .iter()
                .skip(1)
                .any(|c| c.is_identity().into())
            || !I::check_feldman_verifier(feldman_verifier_set[0])
        {
            return Err(Error::InitializationError(
                "Invalid commitments".to_string(),
            ));
        }
        Ok(Self {
            ordinal,
            id,
            threshold: parameters.threshold,
            limit: parameters.limit,
            round: Round::One,
            message_generator: parameters.message_generator,
            blinder_generator: parameters.blinder_generator,
            secret_share: G::Scalar::ZERO,
            secret_shares,
            blind_share: G::Scalar::ZERO,
            blinder_shares,
            feldman_verifier_set,
            pedersen_verifier_set,
            public_key: G::identity(),
            blind_key: G::identity(),
            powers_of_i,
            received_round0_data: BTreeMap::new(),
            received_round1_data: BTreeMap::new(),
            received_round2_data: BTreeMap::new(),
            received_round3_data: BTreeMap::new(),
            received_round4_data: BTreeMap::new(),
            valid_participant_ids: BTreeMap::new(),
            all_participant_ids,
            participant_impl: Default::default(),
            transcript: Transcript::new(b"gennaro-dkg v1.0.0"),
        })
    }

    /// The ordinal index of this participant
    pub fn get_ordinal(&self) -> usize {
        self.ordinal
    }

    /// The identifier associated with this secret_participant
    pub fn get_id(&self) -> G::Scalar {
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
            Some(self.secret_share)
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
            Some(self.blind_share)
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
    pub fn get_valid_participant_ids(&self) -> &BTreeMap<usize, G::Scalar> {
        &self.valid_participant_ids
    }

    /// Return the list of all participants that started the protocol
    pub fn get_all_participant_ids(&self) -> &BTreeMap<usize, G::Scalar> {
        &self.all_participant_ids
    }

    /// Receive data from another participant
    pub fn receive(&mut self, data: &[u8]) -> DkgResult<()> {
        let round = Round::try_from(data[0]).map_err(|e| Error::InitializationError(e))?;
        match round {
            Round::Zero => {
                let round0_payload = postcard::from_bytes::<Round0Data<G>>(&data[1..])?;
                self.receive_round0data(round0_payload)
            }
            Round::One => {
                let round1_payload = postcard::from_bytes::<Round1Data<G>>(&data[1..])?;
                self.receive_round1data(round1_payload)
            }
            Round::Two => {
                let round2_payload = postcard::from_bytes::<Round2Data<G>>(&data[1..])?;
                self.receive_round2data(round2_payload)
            }
            Round::Three => {
                let round3_payload = postcard::from_bytes::<Round3Data<G>>(&data[1..])?;
                self.receive_round3data(round3_payload)
            }
            Round::Four => {
                let round4_payload = postcard::from_bytes::<Round4Data<G>>(&data[1..])?;
                self.receive_round4data(round4_payload)
            }
            _ => Err(Error::RoundError(5, "Protocol is complete".to_string())),
        }
    }

    /// Run the next step in the protocol
    pub fn run(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        match self.round {
            Round::Zero => self.round0(),
            Round::One => self.round1(),
            Round::Two => self.round2(),
            Round::Three => self.round3(),
            Round::Four => self.round4(),
            Round::Five => Err(Error::RoundError(5, "nothing more to run".to_string())),
        }
    }

    pub(crate) fn check_sending_participant_id(
        &self,
        round: usize,
        sender_index: usize,
        sender_id: G::Scalar,
    ) -> DkgResult<()> {
        if !self.all_participant_ids.contains_key(&sender_index) {
            return Err(Error::RoundError(
                round,
                format!("Unknown sender index, {}", sender_index),
            ));
        }
        if sender_id.is_zero().into() {
            return Err(Error::RoundError(round, "Sender id is zero".to_string()));
        }
        if self.id.ct_eq(&sender_id).into() {
            return Err(Error::RoundError(
                round,
                "Sender id is equal to our id".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn compute_pedersen_commitments_hash(
        participant_type: ParticipantType,
        ordinal_index: usize,
        id: G::Scalar,
        threshold: usize,
        pedersen_commitments: &[G],
    ) -> [u8; 32] {
        let mut transcript = Transcript::new(b"pedersen commitments");
        transcript.append_u64(b"participant type", participant_type as u64);
        transcript.append_u64(b"sender index", ordinal_index as u64);
        transcript.append_message(b"sender id", id.to_repr().as_ref());
        transcript.append_u64(b"threshold", threshold as u64);
        for (i, commitment) in pedersen_commitments.iter().enumerate() {
            transcript.append_u64(b"commitment index", i as u64);
            transcript.append_message(b"commitment", commitment.to_bytes().as_ref());
        }
        let mut commitment_hash = [0u8; 32];
        transcript.challenge_bytes(b"pedersen commitment hash", &mut commitment_hash);
        commitment_hash
    }

    pub(crate) fn compute_feldman_commitments_hash(
        participant_type: ParticipantType,
        ordinal_index: usize,
        id: G::Scalar,
        threshold: usize,
        feldman_commitments: &[G],
    ) -> [u8; 32] {
        let mut transcript = Transcript::new(b"feldman commitments");
        transcript.append_u64(b"participant type", participant_type as u64);
        transcript.append_u64(b"sender index", ordinal_index as u64);
        transcript.append_message(b"sender id", id.to_repr().as_ref());
        transcript.append_u64(b"threshold", threshold as u64);
        for (i, commitment) in feldman_commitments.iter().enumerate() {
            transcript.append_u64(b"commitment index", i as u64);
            transcript.append_message(b"commitment", commitment.to_bytes().as_ref());
        }
        let mut commitment_hash = [0u8; 32];
        transcript.challenge_bytes(b"feldman commitment hash", &mut commitment_hash);
        commitment_hash
    }

    pub(crate) fn lagrange(share: G::Scalar, shares_ids: &[G::Scalar]) -> G::Scalar {
        let mut num = G::Scalar::ONE;
        let mut den = G::Scalar::ONE;
        for &x_j in shares_ids.iter() {
            if x_j == share {
                continue;
            }
            num *= x_j;
            den *= x_j - share;
        }

        num * den.invert().expect("Denominator should not be zero")
    }
}

/// Secret Participant Implementation
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SecretParticipantImpl<G>(PhantomData<G>);

impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default> ParticipantImpl<G>
    for SecretParticipantImpl<G>
{
    fn get_type(&self) -> ParticipantType {
        ParticipantType::Secret
    }

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

impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default> ParticipantImpl<G>
    for RefreshParticipantImpl<G>
{
    fn get_type(&self) -> ParticipantType {
        ParticipantType::Refresh
    }

    fn secret(_rng: impl RngCore) -> <G as Group>::Scalar {
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

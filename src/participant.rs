mod round1;
mod round2;
mod round3;
mod round4;
mod round5;

use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use crate::{
    DkgResult, Error, GroupHasher, Parameters, ParticipantType, Round, Round1Data, Round2Data,
    Round3Data, Round4Data, RoundOutputGenerator,
};
use elliptic_curve::{group::GroupEncoding, Field, Group, PrimeField};
use elliptic_curve_tools::*;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use vsss_rs::{
    pedersen::PedersenOptions,
    subtle::{Choice, ConstantTimeEq},
    DefaultShare, FeldmanVerifierSet, IdentifierPrimeField, Pedersen, PedersenResult,
    PedersenVerifierSet, Share, ShareElement, ShareVerifierGroup, StdPedersenResult, StdVsss,
    ValueGroup, ValuePrimeField, VecFeldmanVerifierSet, VecPedersenVerifierSet,
};

/// Secret Participant type
pub type SecretParticipant<G> = Participant<SecretParticipantImpl<G>, G>;

/// Refresh Participant type
pub type RefreshParticipant<G> = Participant<RefreshParticipantImpl<G>, G>;

/// The inner share representation
pub type SecretShare<F> = DefaultShare<IdentifierPrimeField<F>, IdentifierPrimeField<F>>;

/// The inner feldman share verifiers
pub type FeldmanShareVerifier<G> = ShareVerifierGroup<G>;

/// The inner pedersen share result
pub type InnerPedersenResult<F, G> = StdPedersenResult<SecretShare<F>, ShareVerifierGroup<G>>;

/// Participant implementation
pub trait ParticipantImpl<G>
where
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    /// Get the participant type
    fn get_type(&self) -> ParticipantType;
    /// Get the participants secret
    fn random_value(rng: impl RngCore + CryptoRng) -> G::Scalar;
    /// Check the feldman verifier at position 0.
    /// During a new or update key gen, this value is not the identity
    /// during a refresh, it must be identity
    fn check_feldman_verifier(verifier: G) -> bool;
}

/// A DKG participant FSM
#[derive(Clone)]
pub struct Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    pub(crate) ordinal: usize,
    pub(crate) id: IdentifierPrimeField<G::Scalar>,
    pub(crate) threshold: usize,
    pub(crate) limit: usize,
    pub(crate) round: Round,
    pub(crate) completed: bool,
    pub(crate) components: InnerPedersenResult<G::Scalar, G>,
    pub(crate) secret_share: SecretShare<G::Scalar>,
    pub(crate) blind_share: SecretShare<G::Scalar>,
    pub(crate) message_generator: G,
    pub(crate) blinder_generator: G,
    pub(crate) public_key: ValueGroup<G>,
    pub(crate) powers_of_i: Vec<G::Scalar>,
    pub(crate) received_round1_data: BTreeMap<usize, Round1Data<G>>,
    pub(crate) received_round2_data: BTreeMap<usize, Round2Data<G>>,
    pub(crate) received_round3_data: BTreeMap<usize, Round3Data<G>>,
    pub(crate) received_round4_data: BTreeMap<usize, Round4Data<G>>,
    pub(crate) valid_participant_ids: BTreeMap<usize, IdentifierPrimeField<G::Scalar>>,
    pub(crate) all_participant_ids: BTreeMap<usize, IdentifierPrimeField<G::Scalar>>,
    pub(crate) participant_impl: I,
    pub(crate) transcript: Transcript,
}

unsafe impl<I, G> Send for Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
}

unsafe impl<I, G> Sync for Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
}

impl<I, G> Debug for Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Participant")
            .field("ordinal", &self.ordinal)
            .field("id", &self.id)
            .field("threshold", &self.threshold)
            .field("limit", &self.limit)
            .field("round", &self.round)
            .field("components", &self.components)
            .field("secret_share", &self.secret_share)
            .field("blind_share", &self.blind_share)
            .field("public_key", &self.public_key)
            .field("powers_of_i", &self.powers_of_i)
            .field("received_round1_data", &self.received_round1_data)
            .field("received_round2_data", &self.received_round2_data)
            .field("received_round3_data", &self.received_round3_data)
            .field("received_round4_data", &self.received_round4_data)
            .field("valid_participant_ids", &self.valid_participant_ids)
            .field("all_participant_ids", &self.all_participant_ids)
            .finish()
    }
}

impl<G> Participant<SecretParticipantImpl<G>, G>
where
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    /// Create a new participant with an existing secret.
    ///
    /// This allows the polynomial to be updated versus refreshing the shares.
    pub fn with_secret(
        new_identifier: IdentifierPrimeField<G::Scalar>,
        old_share: &SecretShare<G::Scalar>,
        parameters: &Parameters<G>,
        shares_ids: &[IdentifierPrimeField<G::Scalar>],
    ) -> DkgResult<Self> {
        let mut rng = rand_core::OsRng;
        let blinder = G::Scalar::random(&mut rng);
        let secret = *old_share.value * *Self::lagrange(old_share, shares_ids);
        Self::initialize(
            new_identifier,
            parameters,
            IdentifierPrimeField(secret),
            IdentifierPrimeField(blinder),
        )
    }
}

impl<I, G> Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    /// Create a new participant to generate a new key share
    pub fn new(id: IdentifierPrimeField<G::Scalar>, parameters: &Parameters<G>) -> DkgResult<Self> {
        let rng = rand_core::OsRng;
        let secret = I::random_value(rng);
        let blinder = G::Scalar::random(rng);
        Self::initialize(
            id,
            parameters,
            IdentifierPrimeField(secret),
            IdentifierPrimeField(blinder),
        )
    }

    fn initialize(
        id: IdentifierPrimeField<G::Scalar>,
        parameters: &Parameters<G>,
        secret: ValuePrimeField<G::Scalar>,
        blinder: ValuePrimeField<G::Scalar>,
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
        if parameters.message_generator == parameters.blinder_generator {
            return Err(Error::InitializationError(
                "Message and blinder generators cannot be equal".to_string(),
            ));
        }

        let pedersen_params = PedersenOptions {
            secret,
            blinder: Some(blinder),
            secret_generator: Some(ValueGroup(parameters.message_generator)),
            blinder_generator: Some(ValueGroup(parameters.blinder_generator)),
            participant_generators: parameters.participant_number_generators.as_slice(),
        };

        let components: InnerPedersenResult<G::Scalar, G> =
            StdVsss::split_secret_with_blind_verifiers(
                parameters.threshold,
                parameters.limit,
                &pedersen_params,
                rng,
            )?;

        let mut powers_of_i = vec![G::Scalar::ONE; parameters.threshold];
        powers_of_i[1] = *id;
        for i in 2..parameters.threshold {
            powers_of_i[i] = powers_of_i[i - 1] * *id;
        }

        let pedersen_verifier_set: VecPedersenVerifierSet<
            SecretShare<G::Scalar>,
            ShareVerifierGroup<G>,
        > = components.pedersen_verifier_set().into();
        if pedersen_verifier_set
            .blind_verifiers()
            .iter()
            .any(|c| c.is_identity().into())
        {
            return Err(Error::InitializationError(
                "Invalid pedersen verifier".to_string(),
            ));
        }

        let feldman_verifier_set: VecFeldmanVerifierSet<
            SecretShare<G::Scalar>,
            ShareVerifierGroup<G>,
        > = components.feldman_verifier_set().into();
        let feldman_verifiers = feldman_verifier_set.verifiers();
        if feldman_verifiers
            .iter()
            .skip(1)
            .any(|c| c.is_identity().into())
            || !I::check_feldman_verifier(*feldman_verifiers[0])
        {
            return Err(Error::InitializationError(
                "Invalid feldman verifier".to_string(),
            ));
        }

        let ordinal = components
            .secret_shares()
            .iter()
            .position(|s| s.identifier == id)
            .ok_or_else(|| {
                Error::InitializationError(format!(
                    "Invalid participant id '{}'. Not in generated set of shares",
                    id
                ))
            })?;
        let all_participant_ids = components
            .secret_shares()
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.identifier))
            .collect();

        Ok(Self {
            ordinal,
            id,
            threshold: parameters.threshold,
            limit: parameters.limit,
            completed: false,
            round: Round::One,
            components,
            secret_share: SecretShare::<G::Scalar>::default(),
            blind_share: SecretShare::<G::Scalar>::default(),
            message_generator: parameters.message_generator,
            blinder_generator: parameters.blinder_generator,
            public_key: ValueGroup::<G>::identity(),
            powers_of_i,
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
    pub fn get_id(&self) -> IdentifierPrimeField<G::Scalar> {
        self.id
    }

    /// Returns true if this secret_participant is complete
    pub fn completed(&self) -> bool {
        self.completed
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
    pub fn get_secret_share(&self) -> Option<SecretShare<G::Scalar>> {
        if self.completed {
            Some(self.secret_share)
        } else {
            None
        }
    }

    /// Computed public key
    /// This value is useless until all rounds have been run
    /// so [`None`] is returned until completion
    pub fn get_public_key(&self) -> Option<G> {
        if self.completed {
            Some(*self.public_key)
        } else {
            None
        }
    }

    /// Return the list of valid participant ids
    pub fn get_valid_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.valid_participant_ids
    }

    /// Return the list of all participants that started the protocol
    pub fn get_all_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.all_participant_ids
    }

    /// Return the pedersen blinded verifiers
    pub fn get_pedersen_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        let pedersen_verifier_set: VecPedersenVerifierSet<
            SecretShare<G::Scalar>,
            ShareVerifierGroup<G>,
        > = self.components.pedersen_verifier_set().into();
        pedersen_verifier_set.blind_verifiers().to_vec()
    }

    /// Return the feldman verifiers
    pub fn get_feldman_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        let feldman_verifier_set: VecFeldmanVerifierSet<
            SecretShare<G::Scalar>,
            ShareVerifierGroup<G>,
        > = self.components.feldman_verifier_set().into();
        feldman_verifier_set.verifiers().to_vec()
    }

    /// Receive data from another participant
    pub fn receive(&mut self, data: &[u8]) -> DkgResult<()> {
        let round = Round::try_from(data[0]).map_err(Error::InitializationError)?;
        match round {
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
            _ => Err(Error::RoundError(
                Round::Five,
                "Protocol is complete".to_string(),
            )),
        }
    }

    /// Run the next step in the protocol
    pub fn run(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        match self.round {
            Round::One => self.round1(),
            Round::Two => self.round2(),
            Round::Three => self.round3(),
            Round::Four => self.round4(),
            Round::Five => self.round5(),
        }
    }

    pub(crate) fn check_sending_participant_id(
        &self,
        round: Round,
        sender_ordinal: usize,
        sender_id: IdentifierPrimeField<G::Scalar>,
    ) -> DkgResult<()> {
        let id = self
            .all_participant_ids
            .get(&sender_ordinal)
            .ok_or_else(|| {
                Error::RoundError(round, format!("Unknown sender ordinal, {}", sender_ordinal))
            })?;
        if *id != sender_id {
            return Err(Error::RoundError(
                round,
                format!("Sender id mismatch, expected '{}', got '{}'", id, sender_id),
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
        id: IdentifierPrimeField<G::Scalar>,
        threshold: usize,
        pedersen_commitments: &[ShareVerifierGroup<G>],
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
        id: IdentifierPrimeField<G::Scalar>,
        threshold: usize,
        feldman_commitments: &[ShareVerifierGroup<G>],
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

    pub(crate) fn lagrange(
        share: &SecretShare<G::Scalar>,
        shares_ids: &[IdentifierPrimeField<G::Scalar>],
    ) -> ValuePrimeField<G::Scalar> {
        let mut num = G::Scalar::ONE;
        let mut den = G::Scalar::ONE;
        for &x_j in shares_ids.iter() {
            if x_j == share.identifier {
                continue;
            }
            num *= *x_j;
            den *= *x_j - *share.identifier;
        }

        IdentifierPrimeField(num * den.invert().expect("Denominator should not be zero"))
    }
}

/// Secret Participant Implementation
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SecretParticipantImpl<G>(PhantomData<G>);

unsafe impl<G> Send for SecretParticipantImpl<G> {}
unsafe impl<G> Sync for SecretParticipantImpl<G> {}

impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default> ParticipantImpl<G>
    for SecretParticipantImpl<G>
{
    fn get_type(&self) -> ParticipantType {
        ParticipantType::Secret
    }

    fn random_value(mut rng: impl RngCore) -> <G as Group>::Scalar {
        G::Scalar::random(&mut rng)
    }

    fn check_feldman_verifier(verifier: G) -> bool {
        verifier.is_identity().unwrap_u8() == 0u8
    }
}

/// Refresh Participant Implementation
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RefreshParticipantImpl<G>(PhantomData<G>);

unsafe impl<G> Send for RefreshParticipantImpl<G> {}
unsafe impl<G> Sync for RefreshParticipantImpl<G> {}

impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default> ParticipantImpl<G>
    for RefreshParticipantImpl<G>
{
    fn get_type(&self) -> ParticipantType {
        ParticipantType::Refresh
    }

    fn random_value(_rng: impl RngCore) -> <G as Group>::Scalar {
        G::Scalar::ZERO
    }

    fn check_feldman_verifier(verifier: G) -> bool {
        verifier.is_identity().into()
    }
}

/// A trait to allow for dynamic dispatch of the participant
pub trait AnyParticipant<G>: Send + Sync
where
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    /// Get the ordinal index of this participant
    fn get_ordinal(&self) -> usize;
    /// Get the identifier associated with this participant
    fn get_id(&self) -> IdentifierPrimeField<G::Scalar>;
    /// Get the threshold
    fn get_threshold(&self) -> usize;
    /// Get the limit
    fn get_limit(&self) -> usize;
    /// Get the current round
    fn get_round(&self) -> Round;
    /// Get the secret share if completed
    fn get_secret_share(&self) -> Option<SecretShare<G::Scalar>>;
    /// Get the public key if completed
    fn get_public_key(&self) -> Option<G>;
    /// Get the valid participant ids from the last round
    fn get_valid_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>>;
    /// Get all participant ids that started the protocol
    fn get_all_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>>;
    /// Return the pedersen blinded verifiers
    fn get_pedersen_verifiers(&self) -> Vec<ShareVerifierGroup<G>>;
    /// Return the feldman verifiers
    fn get_feldman_verifiers(&self) -> Vec<ShareVerifierGroup<G>>;
    /// Check if the participant is completed
    fn completed(&self) -> bool;
    /// Receive data from another participant
    fn receive(&mut self, data: &[u8]) -> DkgResult<()>;
    /// Run the next round in the protocol after receiving data from other participants
    fn run(&mut self) -> DkgResult<RoundOutputGenerator<G>>;
}

impl<G> AnyParticipant<G> for Participant<SecretParticipantImpl<G>, G>
where
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    fn get_ordinal(&self) -> usize {
        self.ordinal
    }

    fn get_id(&self) -> IdentifierPrimeField<G::Scalar> {
        self.id
    }

    fn get_threshold(&self) -> usize {
        self.threshold
    }

    fn get_limit(&self) -> usize {
        self.limit
    }

    fn get_round(&self) -> Round {
        self.round
    }

    fn get_secret_share(&self) -> Option<SecretShare<G::Scalar>> {
        self.get_secret_share()
    }

    fn get_public_key(&self) -> Option<G> {
        self.get_public_key()
    }

    fn get_valid_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.valid_participant_ids
    }

    fn get_all_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.all_participant_ids
    }

    fn get_pedersen_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        self.get_pedersen_verifiers()
    }

    fn get_feldman_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        self.get_feldman_verifiers()
    }

    fn completed(&self) -> bool {
        self.completed()
    }

    fn receive(&mut self, data: &[u8]) -> DkgResult<()> {
        self.receive(data)
    }

    fn run(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        self.run()
    }
}

impl<G> AnyParticipant<G> for Participant<RefreshParticipantImpl<G>, G>
where
    G: GroupHasher + SumOfProducts + GroupEncoding + Default,
{
    fn get_ordinal(&self) -> usize {
        self.ordinal
    }

    fn get_id(&self) -> IdentifierPrimeField<G::Scalar> {
        self.id
    }

    fn get_threshold(&self) -> usize {
        self.threshold
    }

    fn get_limit(&self) -> usize {
        self.limit
    }

    fn get_round(&self) -> Round {
        self.round
    }

    fn get_secret_share(&self) -> Option<SecretShare<G::Scalar>> {
        self.get_secret_share()
    }

    fn get_public_key(&self) -> Option<G> {
        self.get_public_key()
    }

    fn get_valid_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.valid_participant_ids
    }

    fn get_all_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.all_participant_ids
    }

    fn get_pedersen_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        self.get_pedersen_verifiers()
    }

    fn get_feldman_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        self.get_feldman_verifiers()
    }

    fn completed(&self) -> bool {
        self.completed()
    }

    fn receive(&mut self, data: &[u8]) -> DkgResult<()> {
        self.receive(data)
    }

    fn run(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        self.run()
    }
}

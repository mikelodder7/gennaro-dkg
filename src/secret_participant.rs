mod round1;
mod round2;
mod round3;
mod round4;
mod round5;

use super::*;

/// Secret Participant with the Default Logger
pub type DefaultSecretParticipant<G> = SecretParticipant<G, DefaultLogger>;

/// A DKG secret participant. Maintains state information for each round
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretParticipant<G: Group + GroupEncoding + Default, L: Log> {
    id: usize,
    #[serde(bound(serialize = "PedersenResult<G::Scalar, G>: Serialize"))]
    #[serde(bound(deserialize = "PedersenResult<G::Scalar, G>: Deserialize<'de>"))]
    components: PedersenResult<G::Scalar, G>,
    threshold: usize,
    #[serde(skip)]
    logger: Option<L>,
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
}

impl<G: Group + GroupEncoding + Default, L: Log> SecretParticipant<G, L> {
    /// Create a new participant to generate a new key share
    pub fn new(id: NonZeroUsize, parameters: Parameters<G>) -> DkgResult<Self> {
        let mut rng = rand_core::OsRng;
        let secret = G::Scalar::random(&mut rng);
        let blinder = G::Scalar::random(&mut rng);
        Self::initialize(id, parameters, secret, blinder)
    }

    /// Create a new participant to run the DKG with an existing secret.
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
        let pedersen = Pedersen {
            t: parameters.threshold,
            n: parameters.limit,
        };
        let mut rng = rand_core::OsRng;
        let components = pedersen.split_secret(
            secret,
            Some(blinder),
            Some(parameters.message_generator),
            Some(parameters.blinder_generator),
            &mut rng,
        )?;

        if (components.verifier.generator.is_identity()
            | components.verifier.feldman_verifier.generator.is_identity())
        .unwrap_u8()
            == 1u8
        {
            return Err(Error::InitializationError("Invalid generators".to_string()));
        }
        if components
            .verifier
            .commitments
            .iter()
            .any(|c| c.is_identity().unwrap_u8() == 1u8)
            || components
                .verifier
                .feldman_verifier
                .commitments
                .iter()
                .any(|c| c.is_identity().unwrap_u8() == 1u8)
        {
            return Err(Error::InitializationError(
                "Invalid commitments".to_string(),
            ));
        }
        if components.secret_shares.iter().any(|s| s.is_zero())
            || components.blind_shares.iter().any(|s| s.is_zero())
        {
            return Err(Error::InitializationError("Invalid shares".to_string()));
        }
        Ok(Self {
            id: id.get(),
            components,
            threshold: parameters.threshold,
            limit: parameters.limit,
            logger: None,
            round: Round::One,
            round1_broadcast_data: BTreeMap::new(),
            round1_p2p_data: BTreeMap::new(),
            secret_share: G::Scalar::zero(),
            public_key: G::identity(),
            valid_participant_ids: BTreeSet::new(),
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

    /// Set a logger to receive internal errors
    pub fn set_logger(&mut self, logger: L) {
        self.logger = Some(logger);
    }

    pub(crate) fn log(&self, error: ParticipantError) {
        let e = error.to_string();
        if let Some(l) = self.logger.as_ref() {
            let record = Record::builder().level(Level::Warn).target(&e).build();
            l.log(&record)
        }
    }
}

#[test]
fn test_serialization() {
    serialization::<k256::ProjectivePoint>();
    serialization::<p256::ProjectivePoint>();
    serialization::<vsss_rs::curve25519::WrappedEdwards>();
    serialization::<vsss_rs::curve25519::WrappedRistretto>();
    serialization::<bls12_381_plus::G1Projective>();
    serialization::<bls12_381_plus::G2Projective>();
}

#[cfg(test)]
fn serialization<G: Group + GroupEncoding + Default>() {
    let participant = unsafe {
        DefaultSecretParticipant::new(
            NonZeroUsize::new_unchecked(1),
            Parameters::<G>::new(
                NonZeroUsize::new_unchecked(2),
                NonZeroUsize::new_unchecked(3),
            ),
        )
        .unwrap()
    };
    let st = serde_json::to_string(&participant).unwrap();
    let res = serde_json::from_str::<DefaultSecretParticipant<G>>(&st);
    assert!(res.is_ok());
    let participant2 = res.unwrap();
    compare_participants(&participant, &participant2);
    let bin = serde_bare::to_vec(&participant).unwrap();
    let res = serde_bare::from_slice::<DefaultSecretParticipant<G>>(&bin);
    assert!(res.is_ok());
    let participant2 = res.unwrap();
    compare_participants(&participant, &participant2);
}

#[cfg(test)]
fn compare_participants<G: Group + GroupEncoding + Default>(
    participant: &DefaultSecretParticipant<G>,
    participant2: &DefaultSecretParticipant<G>,
) {
    assert_eq!(participant2.id, participant.id);
    assert_eq!(participant2.limit, participant.limit);
    assert_eq!(participant2.threshold, participant.threshold);
    assert_eq!(participant2.public_key, participant.public_key);
    assert_eq!(participant2.round, participant.round);
    assert_eq!(participant2.secret_share, participant.secret_share);
    assert_eq!(
        participant2.components.blinding,
        participant.components.blinding
    );
    assert_eq!(
        participant2.components.blind_shares.len(),
        participant.components.blind_shares.len()
    );
    assert_eq!(
        participant2.components.blind_shares[0],
        participant.components.blind_shares[0]
    );
    assert_eq!(
        participant2.components.blind_shares[1],
        participant.components.blind_shares[1]
    );
    assert_eq!(
        participant2.components.blind_shares[2],
        participant.components.blind_shares[2]
    );
    assert_eq!(
        participant2.components.secret_shares.len(),
        participant.components.secret_shares.len()
    );
    assert_eq!(
        participant2.components.secret_shares[0],
        participant.components.secret_shares[0]
    );
    assert_eq!(
        participant2.components.secret_shares[1],
        participant.components.secret_shares[1]
    );
    assert_eq!(
        participant2.components.secret_shares[2],
        participant.components.secret_shares[2]
    );
    assert_eq!(
        participant2.components.verifier.generator,
        participant.components.verifier.generator
    );
    assert_eq!(
        participant2.components.verifier.commitments.len(),
        participant.components.verifier.commitments.len()
    );
    assert_eq!(
        participant2.components.verifier.commitments[0],
        participant.components.verifier.commitments[0]
    );
    assert_eq!(
        participant2.components.verifier.commitments[1],
        participant.components.verifier.commitments[1]
    );
    assert_eq!(
        participant2.components.verifier.feldman_verifier.generator,
        participant.components.verifier.feldman_verifier.generator
    );
    assert_eq!(
        participant2
            .components
            .verifier
            .feldman_verifier
            .commitments
            .len(),
        participant
            .components
            .verifier
            .feldman_verifier
            .commitments
            .len()
    );
    assert_eq!(
        participant2
            .components
            .verifier
            .feldman_verifier
            .commitments[0],
        participant.components.verifier.feldman_verifier.commitments[0]
    );
    assert_eq!(
        participant2
            .components
            .verifier
            .feldman_verifier
            .commitments[1],
        participant.components.verifier.feldman_verifier.commitments[1]
    );
}

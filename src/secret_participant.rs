mod round1;
mod round2;
mod round3;
mod round4;
mod round5;

use super::*;

/// A DKG secret participant. Maintains state information for each round
#[derive(Serialize, Deserialize)]
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
        self.logger.as_ref().map(|l| {
            let record = Record::builder().level(Level::Warn).target(&e).build();
            l.log(&record)
        });
    }
}

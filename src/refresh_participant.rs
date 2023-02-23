mod round1;
mod round2;
mod round3;
mod round4;
mod round5;

use super::*;

/// Secret Participant with the Default Logger
pub type DefaultRefreshParticipant<G> = RefreshParticipant<G, DefaultLogger>;

/// A DKG refresh participant. Maintains state information for each round
/// Follows principles from <https://eprint.iacr.org/2020/1052>
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshParticipant<G: Group + GroupEncoding + Default, L: Log> {
    id: usize,
    #[serde(bound(serialize = "PedersenResult<G::Scalar, G>: Serialize"))]
    #[serde(bound(deserialize = "PedersenResult<G::Scalar, G>: Deserialize<'de>"))]
    components: PedersenResult<G::Scalar, G>,
    threshold: usize,
    limit: usize,
    logger: Option<L>,
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

impl<G: Group + GroupEncoding + Default, L: Log> RefreshParticipant<G, L> {
    /// Create a new refresh participant to generate a refresh share.
    /// This method enables proactive secret sharing.
    /// The difference between new and refresh is new generates a random secret
    /// where refresh uses zero as the secret which just alters the polynomial
    /// when added to the share generated from new but doesn't change the secret itself.
    ///
    /// The algorithm runs the same regardless of the value used for secret.
    ///
    /// Another approach is to just run the DKG with the same secret since a different
    /// polynomial will be generated from the share, however, this approach exposes the shares
    /// if an attacker obtains any traffic. Using zero is safer in this regard and only requires
    /// an addition to the share upon completion.
    ///
    /// If the idea is to change the polynomial then
    /// [`SecretParticipant`]::with_secret should be used
    pub fn new(id: NonZeroUsize, parameters: Parameters<G>) -> DkgResult<Self> {
        let blinder = G::Scalar::random(rand_core::OsRng);
        Self::initialize(id, parameters, G::Scalar::zero(), blinder)
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
            .skip(1)
            .any(|c| c.is_identity().unwrap_u8() == 1u8)
            || components
                .verifier
                .feldman_verifier
                .commitments
                .iter()
                .skip(1)
                .any(|c| c.is_identity().unwrap_u8() == 1u8)
            || components.verifier.commitments[0].is_identity().unwrap_u8() == 0u8
            || components.verifier.feldman_verifier.commitments[0]
                .is_identity()
                .unwrap_u8()
                == 0u8
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
    /// so [`None`] is returned until completion.
    ///
    /// Add this value to an existing share to execute proactive secret sharing
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

    pub(crate) fn log(&self, error: ParticipantError) {
        let e = error.to_string();
        if let Some(l) = self.logger.as_ref() {
            let record = Record::builder().level(Level::Warn).target(&e).build();
            l.log(&record)
        }
    }
}

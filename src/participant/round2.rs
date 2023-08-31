use super::*;

impl<I: ParticipantImpl<G> + Default, G: Group + GroupEncoding + Default> Participant<I, G> {
    /// Computes round2 for this participant.
    ///
    /// Inputs correspond to messages received from other participants
    ///
    /// The protocol will continue if some parties are malicious as
    /// long as `threshold` or more participants are honest.
    ///
    /// Example: this participant is id = 1, others include 2, 3, 4
    /// broadcast_data = {
    ///     2: Round1BroadcastData, // from participant 2
    ///     3: Round1BroadcastData, // from participant 3
    ///     4: Round1BroadcastData, // from participant 4
    /// }
    ///
    /// p2p_data = {
    ///     2: Round1P2PData, // from participant 2
    ///     3: Round1P2PData, // from participant 3
    ///     4: Round1P2PData, // from participant 4
    /// }
    ///
    /// Throws an error if this participant is not in round 2.
    ///
    /// Returns the data needed for round 2
    pub fn round2(
        &mut self,
        broadcast_data: BTreeMap<usize, Round1BroadcastData<G>>,
        p2p_data: BTreeMap<usize, Round1P2PData>,
    ) -> DkgResult<Round2EchoBroadcastData> {
        if !matches!(self.round, Round::Two) {
            return Err(Error::RoundError(
                Round::Two.into(),
                format!("Invalid Round, use round{}", self.round),
            ));
        }

        if broadcast_data.is_empty() {
            return Err(Error::RoundError(
                Round::Two.into(),
                "Missing broadcast data from other participants".to_string(),
            ));
        }
        if p2p_data.is_empty() {
            return Err(Error::RoundError(
                Round::Two.into(),
                "Missing peer-to-peer data from other participants".to_string(),
            ));
        }
        // Allow -1 since including this participant
        // This round doesn't expect this participant data included in the broadcast_data map
        if broadcast_data.len() < self.threshold - 1 {
            return Err(Error::RoundError(
                Round::Two.into(),
                format!(
                    "Not enough secret_participant data. Expected {}, received {}",
                    self.threshold,
                    broadcast_data.len()
                ),
            ));
        }
        if p2p_data.len() < self.threshold - 1 {
            return Err(Error::RoundError(
                Round::Two.into(),
                format!(
                    "Not enough secret_participant data. Expected {}, received {}",
                    self.threshold,
                    broadcast_data.len()
                ),
            ));
        }

        self.valid_participant_ids.clear();
        let mut secret_share =
            self.components.secret_shares[self.id - 1].as_field_element::<G::Scalar>()?;
        let og = secret_share;

        // Create a unique list of secret_participant ids
        let pids = broadcast_data
            .keys()
            .copied()
            .chain(p2p_data.keys().copied())
            .collect::<BTreeSet<usize>>();
        for pid in &pids {
            // resolve bid != pid where bid might exist or pid might exist in the other
            // probably didn't receive the data, not necessarily malicious
            let opt_bdata = broadcast_data.get(pid);
            if opt_bdata.is_none() {
                continue;
            }
            let opt_p2p_data = p2p_data.get(pid);
            if opt_p2p_data.is_none() {
                continue;
            }

            let bdata = opt_bdata.unwrap();

            // If not using the same generator then its a problem
            if bdata.blinder_generator != self.components.pedersen_verifier_set.blinder_generator()
                || bdata.message_generator
                    != self.components.pedersen_verifier_set.secret_generator()
                || bdata.pedersen_commitments.len() != self.threshold
            {
                continue;
            }

            if bdata
                .pedersen_commitments
                .iter()
                .any(|c| c.is_identity().into())
            {
                continue;
            }
            let p2p = opt_p2p_data.unwrap();
            if (p2p.secret_share.is_zero() | p2p.blind_share.is_zero()).into() {
                continue;
            }

            let verifier = Vec::<G>::pedersen_set_with_generators_and_verifiers(
                bdata.message_generator,
                bdata.blinder_generator,
                &bdata.pedersen_commitments,
            );

            if verifier
                .verify_share_and_blinder(&p2p.secret_share, &p2p.blind_share)
                .is_err()
            {
                continue;
            }
            if let Ok(s) = p2p.secret_share.as_field_element::<G::Scalar>() {
                secret_share += s;
                self.valid_participant_ids.insert(*pid);
            }
        }

        if secret_share.is_zero().into() || secret_share == og {
            return Err(Error::RoundError(
                Round::Two.into(),
                "The resulting secret key share is invalid".to_string(),
            ));
        }
        self.valid_participant_ids.insert(self.id);
        if self.valid_participant_ids.len() < self.threshold {
            return Err(Error::RoundError(
                Round::Two.into(),
                "Not enough valid participants, below the threshold".to_string(),
            ));
        }

        self.round = Round::Three;
        // Include own id in valid set
        self.round1_p2p_data = p2p_data
            .iter()
            .map(|(key, value)| {
                let val = Arc::new(RefCell::new(Protected::serde(value).unwrap()));
                (*key, val)
            })
            .collect();
        self.round1_broadcast_data = broadcast_data;

        let echo_data = Round2EchoBroadcastData {
            valid_participant_ids: self.valid_participant_ids.clone(),
        };
        self.secret_share = Arc::new(RefCell::new(Protected::field_element(secret_share)));

        Ok(echo_data)
    }
}

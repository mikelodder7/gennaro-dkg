use super::*;
use std::marker::PhantomData;

impl<G: Group + GroupEncoding + Default, L: Log> RefreshParticipant<G, L> {
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
        if broadcast_data.len() < self.threshold {
            return Err(Error::RoundError(
                Round::Two.into(),
                "Not enough secret_participant data".to_string(),
            ));
        }

        self.valid_participant_ids.clear();
        self.secret_share =
            self.components.secret_shares[self.id - 1].as_field_element::<G::Scalar>()?;
        let og = self.secret_share;

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
                self.log(ParticipantError::MissingBroadcastData(*pid));
                continue;
            }
            let opt_p2p_data = p2p_data.get(pid);
            if opt_p2p_data.is_none() {
                self.log(ParticipantError::MissingBroadcastData(*pid));
                continue;
            }

            let bdata = opt_bdata.unwrap();

            // If not using the same generator then its a problem
            if bdata.blinder_generator != self.components.verifier.generator
                || bdata.message_generator != self.components.verifier.feldman_verifier.generator
                || bdata.pedersen_commitments.len() != self.threshold
            {
                self.log(ParticipantError::MismatchedParameters(*pid));
                continue;
            }

            if bdata
                .pedersen_commitments
                .iter()
                .skip(1)
                .any(|c| c.is_identity().unwrap_u8() == 1u8)
                || bdata.pedersen_commitments[0].is_identity().unwrap_u8() == 0u8
            {
                self.log(ParticipantError::IdentityElementPedersenCommitments(*pid));
                continue;
            }
            let p2p = opt_p2p_data.unwrap();
            if (p2p.secret_share.is_zero() | p2p.blind_share.is_zero()).into() {
                self.log(ParticipantError::ZeroValueShares(*pid));
                continue;
            }

            let verifier = PedersenVerifier {
                generator: bdata.blinder_generator,
                commitments: bdata.pedersen_commitments.clone(),
                feldman_verifier: FeldmanVerifier {
                    generator: bdata.message_generator,
                    commitments: vec![],
                    marker: PhantomData::<G::Scalar>,
                },
            };

            if verifier
                .verify(&p2p.secret_share, &p2p.blind_share)
                .is_err()
            {
                self.log(ParticipantError::NoVerifyShares(*pid));
                continue;
            }
            if let Ok(s) = p2p.secret_share.as_field_element::<G::Scalar>() {
                self.secret_share += s;
                self.valid_participant_ids.insert(*pid);
            } else {
                self.log(ParticipantError::BadFormatShare(*pid));
            }
        }

        if self.secret_share.is_zero().unwrap_u8() == 1u8 || self.secret_share == og {
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
        self.round1_p2p_data = p2p_data;
        self.round1_broadcast_data = broadcast_data;

        let echo_data = Round2EchoBroadcastData {
            valid_participant_ids: self.valid_participant_ids.clone(),
        };

        Ok(echo_data)
    }
}

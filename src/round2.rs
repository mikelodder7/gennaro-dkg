use super::*;
use std::marker::PhantomData;

impl<G: Group + GroupEncoding + Default> Participant<G> {
    /// Computes round2 for this participant.
    ///
    /// Inputs correspond to messages received from other participants
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
            return Err(Error::RoundError(2, "Invalid Round".to_string()));
        }

        if broadcast_data.is_empty() {
            return Err(Error::RoundError(
                2,
                "Missing broadcast data from other participants".to_string(),
            ));
        }
        if p2p_data.is_empty() {
            return Err(Error::RoundError(
                2,
                "Missing peer-to-peer data from other participants".to_string(),
            ));
        }
        if broadcast_data.len() != p2p_data.len() {
            return Err(Error::RoundError(
                2,
                "Mismatching broadcast data and peer-to-peer data".to_string(),
            ));
        }
        if broadcast_data.len() > self.limit {
            return Err(Error::RoundError(
                2,
                "Too much participant data".to_string(),
            ));
        }
        if broadcast_data.len() < self.threshold {
            return Err(Error::RoundError(
                2,
                "Not enough participant data".to_string(),
            ));
        }

        self.valid_participant_ids.clear();
        self.secret_share = self.components.secret_shares[self.id - 1].as_field_element::<G::Scalar>()?;
        let og = self.secret_share;

        for ((bid, bdata), (pid, p2p)) in broadcast_data.iter().zip(p2p_data.iter()) {
            if bid != pid {
                return Err(Error::RoundError(
                    2,
                    format!("Missing data from participant {}", *bid),
                ));
            }

            // If not using the same generator then its a problem
            if bdata.blinder_generator != self.components.verifier.generator
                || bdata.message_generator != self.components.verifier.feldman_verifier.generator
                || bdata.pedersen_commitments.len() != self.threshold
            {
                continue;
            }
            if bdata
                .pedersen_commitments
                .iter()
                .any(|c| c.is_identity().unwrap_u8() == 1u8)
                || p2p.secret_share.is_zero()
                || p2p.blind_share.is_zero()
            {
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

            if !verifier.verify(&p2p.secret_share, &p2p.blind_share) {
                continue;
            }

            if let Ok(s) = p2p.secret_share.as_field_element::<G::Scalar>() {
                self.secret_share += s;
                self.valid_participant_ids.insert(*bid);
            }
        }

        if self.secret_share.is_zero().unwrap_u8() == 1u8 || self.secret_share == og {
            return Err(Error::RoundError(
                2,
                "The resulting secret key share is invalid".to_string(),
            ));
        }
        self.valid_participant_ids.insert(self.id);
        if self.valid_participant_ids.len() < self.threshold {
            return Err(Error::RoundError(
                2,
                "Not enough valid participants, below the threshold".to_string(),
            ))
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

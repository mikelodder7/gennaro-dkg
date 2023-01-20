use super::*;
use std::marker::PhantomData;

impl<G: Group + GroupEncoding + Default, L: Log> RefreshParticipant<G, L> {
    /// Computes round 4 for this participant.
    ///
    /// Receives the associated feldman verifiers and checks the secret
    /// shares sent from round 1.
    ///
    /// If they all pass then, the public key and secret key share are returned
    ///
    /// The public key should be echo broadcast to all valid participants to be checked.
    ///
    /// Throws an error if this participant is not in round 4.
    pub fn round4(
        &mut self,
        broadcast_data: &BTreeMap<usize, Round3BroadcastData<G>>,
    ) -> DkgResult<Round4EchoBroadcastData<G>> {
        if !matches!(self.round, Round::Four) {
            return Err(Error::RoundError(
                Round::Four.into(),
                format!("Invalid Round, use round{}", self.round),
            ));
        }

        if broadcast_data.is_empty() {
            return Err(Error::RoundError(
                Round::Four.into(),
                "Missing broadcast data from other participants. Broadcast data is empty"
                    .to_string(),
            ));
        }
        if broadcast_data.len() < self.threshold {
            return Err(Error::RoundError(
                Round::Four.into(),
                "Missing broadcast data from other participants. Non-sufficient data provided."
                    .to_string(),
            ));
        }

        self.public_key = self.components.verifier.feldman_verifier.commitments[0];
        let og = self.public_key;

        for (id, bdata) in broadcast_data {
            if self.id == *id {
                continue;
            }
            if !self.valid_participant_ids.contains(id) {
                self.log(ParticipantError::UnexpectedBroadcast(*id));
                continue;
            }
            if !self.round1_p2p_data.contains_key(id) {
                // How would this happen?
                // Round 2 removed all invalid participants
                // Round 3 sent echo broadcast to double check valid participants
                self.log(ParticipantError::MissingP2PDataRound1(*id));
                self.valid_participant_ids.remove(id);
                continue;
            }
            if !self.round1_broadcast_data.contains_key(id) {
                // How would this happen?
                // Round 2 removed all invalid participants
                // Round 3 sent echo broadcast to double check valid participants
                self.log(ParticipantError::MissingBroadcastDataRound1(*id));
                self.valid_participant_ids.remove(id);
                continue;
            }
            if self.components.verifier.feldman_verifier.generator != bdata.message_generator
                || self.round1_broadcast_data[id].message_generator != bdata.message_generator
            {
                self.log(ParticipantError::MismatchedParameters(*id));
                self.valid_participant_ids.remove(id);
                continue;
            }
            let verifier = FeldmanVerifier {
                commitments: bdata.commitments.clone(),
                generator: bdata.message_generator,
                marker: PhantomData::<G::Scalar>,
            };
            if verifier
                .commitments
                .iter()
                .skip(1)
                .any(|c| c.is_identity().unwrap_u8() == 1u8)
                || verifier.commitments[0].is_identity().unwrap_u8() == 0u8
            {
                self.log(ParticipantError::IdentityElementFeldmanCommitments(*id));
                self.valid_participant_ids.remove(id);
                continue;
            }
            if !verifier.verify(&self.round1_p2p_data[id].secret_share) {
                self.log(ParticipantError::NoVerifyShares(*id));
                self.valid_participant_ids.remove(id);
                continue;
            }

            if self.valid_participant_ids.len() < self.threshold {
                return Err(Error::RoundError(
                    Round::Four.into(),
                    "Not enough valid participants to continue".to_string(),
                ));
            }

            self.public_key += bdata.commitments[0];
        }

        if self.public_key.is_identity().unwrap_u8() == 0u8 || self.public_key == og {
            return Err(Error::RoundError(
                Round::Four.into(),
                "Invalid public key".to_string(),
            ));
        }
        self.round = Round::Five;

        Ok(Round4EchoBroadcastData {
            public_key: self.public_key,
        })
    }
}

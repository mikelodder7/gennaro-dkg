use super::*;
use std::marker::PhantomData;

impl<G: Group + GroupEncoding + Default> Participant<G> {
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
    ) -> DkgResult<(Round4EchoBroadcastData<G>, G::Scalar)> {
        if !matches!(self.round, Round::Four) {
            return Err(Error::RoundError(4, "Invalid Round.".to_string()));
        }

        if broadcast_data.is_empty() {
            return Err(Error::RoundError(
                4,
                "Missing broadcast data from other participants. Broadcast data is empty"
                    .to_string(),
            ));
        }
        if broadcast_data.len() != self.valid_participant_ids.len() {
            return Err(Error::RoundError(
                4,
                "Missing broadcast data from other participants. Non-sufficient data provided."
                    .to_string(),
            ));
        }

        self.public_key = self.components.verifier.feldman_verifier.commitments[0];

        for (id, bdata) in broadcast_data {
            if self.id == *id {
                continue;
            }
            if !self.valid_participant_ids.contains(id)
                || !self.round1_p2p_data.contains_key(id)
                || !self.round1_broadcast_data.contains_key(id)
            {
                return Err(Error::RoundError(
                    4,
                    format!("Received data from malicious participant {}.", *id),
                ));
            }
            if self.components.verifier.feldman_verifier.generator != bdata.message_generator
                || self.round1_broadcast_data[id].message_generator != bdata.message_generator
            {
                return Err(Error::RoundError(
                    4,
                    format!(
                        "Received incorrect data from participant {}. Wrong generator",
                        *id
                    ),
                ));
            }
            let verifier = FeldmanVerifier {
                commitments: bdata.commitments.clone(),
                generator: bdata.message_generator,
                marker: PhantomData::<G::Scalar>,
            };
            if verifier
                .commitments
                .iter()
                .any(|c| c.is_identity().unwrap_u8() == 1u8)
            {
                return Err(Error::RoundError(
                    4,
                    format!(
                        "Received incorrect data from participant {}. Invalid share",
                        *id
                    ),
                ));
            }
            if !verifier.verify(&self.round1_p2p_data[id].secret_share) {
                return Err(Error::RoundError(
                    4,
                    format!(
                        "Received incorrect data from participant {}. Invalid share",
                        *id
                    ),
                ));
            }

            self.public_key += bdata.commitments[0];
        }

        if self.public_key.is_identity().unwrap_u8() == 1u8 {
            return Err(Error::RoundError(4, "Invalid public key".to_string()));
        }
        self.round = Round::Five;

        Ok((
            Round4EchoBroadcastData {
                public_key: self.public_key,
            },
            self.secret_share,
        ))
    }
}

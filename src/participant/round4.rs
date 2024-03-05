use super::*;
use std::ops::Deref;

impl<I: ParticipantImpl<G> + Default, G: Group + GroupEncoding + Default> Participant<I, G> {
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

        self.public_key = self.components.feldman_verifier_set.verifiers()[0];

        for (id, bdata) in broadcast_data {
            if self.id == *id {
                continue;
            }
            if !self.valid_participant_ids.contains(id) {
                continue;
            }
            if !self.round1_p2p_data.contains_key(id) {
                // How would this happen?
                // Round 2 removed all invalid participants
                // Round 3 sent echo broadcast to double-check valid participants
                self.valid_participant_ids.remove(id);
                continue;
            }
            if !self.round1_broadcast_data.contains_key(id) {
                // How would this happen?
                // Round 2 removed all invalid participants
                // Round 3 sent echo broadcast to double-check valid participants
                self.valid_participant_ids.remove(id);
                continue;
            }
            if bdata
                .commitments
                .iter()
                .skip(1)
                .any(|c| c.is_identity().into())
            // || !I::check_feldman_verifier(bdata.commitments[0])
            {
                self.valid_participant_ids.remove(id);
                continue;
            }
            let verifier = Vec::<G>::feldman_set_with_generator_and_verifiers(
                self.components.feldman_verifier_set.generator(),
                &bdata.commitments,
            );
            let value = &self.round1_p2p_data[id];
            let mut protected_share = value.deref().lock().map_err(|_e| {
                Error::RoundError(Round::Four.into(), "unable to lock".to_string())
            })?;
            let unprotected = protected_share.unprotect().ok_or_else(|| {
                Error::RoundError(Round::Four.into(), "invalid secret unprotected".to_string())
            })?;
            let round1_p2p_data = unprotected
                .serde::<Round1P2PData>()
                .expect("to unwrap protected");
            let p2p_secret_share =
                serde_bare::from_slice::<InnerShare>(&round1_p2p_data.secret_share)
                    .map_err(|e| Error::RoundError(Round::Four.into(), e.to_string()))?;
            if verifier.verify_share(&p2p_secret_share).is_err() {
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

            // Double-check the blinder shares in case the user wants to use them
            let blinder_verifiers = self.round1_broadcast_data[id]
                .pedersen_commitments
                .iter()
                .zip(bdata.commitments.iter())
                .map(|(b, c)| *b - *c)
                .collect::<Vec<G>>();
            let verifier = Vec::<G>::feldman_set_with_generator_and_verifiers(
                self.components.pedersen_verifier_set.blinder_generator(),
                &blinder_verifiers,
            );
            let p2p_blind_share =
                serde_bare::from_slice::<InnerShare>(&round1_p2p_data.blind_share)
                    .map_err(|e| Error::RoundError(Round::Four.into(), e.to_string()))?;

            if verifier.verify_share(&p2p_blind_share).is_err() {
                self.valid_participant_ids.remove(id);
                continue;
            }
        }

        self.round = Round::Five;

        Ok(Round4EchoBroadcastData {
            public_key: self.public_key,
        })
    }
}

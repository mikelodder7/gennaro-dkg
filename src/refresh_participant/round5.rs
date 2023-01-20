use super::*;

impl<G: Group + GroupEncoding + Default, L: Log> RefreshParticipant<G, L> {
    /// Computes round 5 for this participant.
    ///
    /// Checks if all participants computed the same public key.
    ///
    /// Throws an error if this participant is not in round 5.
    pub fn round5(
        &self,
        broadcast_data: &BTreeMap<usize, Round4EchoBroadcastData<G>>,
    ) -> DkgResult<()> {
        if !matches!(self.round, Round::Five) {
            return Err(Error::RoundError(
                Round::Five.into(),
                format!("Invalid Round, use round{}", self.round),
            ));
        }
        if broadcast_data.is_empty() {
            return Err(Error::RoundError(
                Round::Five.into(),
                "Missing broadcast data from other participants. Broadcast data is empty"
                    .to_string(),
            ));
        }
        if broadcast_data.len() < self.threshold {
            return Err(Error::RoundError(
                Round::Five.into(),
                "Missing broadcast data from other participants. Non-sufficient data provided."
                    .to_string(),
            ));
        }

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
                // Round 4 also removed all invalid participants
                self.log(ParticipantError::MissingP2PDataRound1(*id));
                continue;
            }
            if !self.round1_broadcast_data.contains_key(id) {
                // How would this happen?
                // Round 2 removed all invalid participants
                // Round 3 sent echo broadcast to double check valid participants
                // Round 4 also removed all invalid participants
                self.log(ParticipantError::MissingBroadcastDataRound1(*id));
                continue;
            }
            if bdata.public_key != self.public_key {
                return Err(Error::RoundError(
                    Round::Five.into(),
                    format!(
                        "Public key from secret_participant {} does not match.  Expected {:?}, found {:?}",
                        id, self.public_key, bdata.public_key
                    ),
                ));
            }
        }

        Ok(())
    }
}

use super::*;

impl<G: Group + GroupEncoding + Default> Participant<G> {
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
            return Err(Error::RoundError(5, "Invalid Round.".to_string()));
        }
        if broadcast_data.is_empty() {
            return Err(Error::RoundError(
                5,
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
            if bdata.public_key != self.public_key {
                return Err(Error::RoundError(
                    5,
                    format!(
                        "Public key from participant {} does not match.  Expected {:?}, found {:?}",
                        id, self.public_key, bdata.public_key
                    ),
                ));
            }
        }

        Ok(())
    }
}

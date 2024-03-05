use super::*;

impl<I: ParticipantImpl<G> + Default, G: Group + GroupEncoding + Default> Participant<I, G> {
    /// Computes round 3 for this participant.
    ///
    /// This round checks for valid participant ids to make
    /// sure this participant reached the same decision
    /// as all honest participants.
    ///
    /// If all reported ids match this participant's expectations
    /// the round will succeed and continue to the next round.
    ///
    /// Throws an error if this participant is not in round 3.
    pub fn round3(
        &mut self,
        echo_data: &BTreeMap<usize, Round2EchoBroadcastData>,
    ) -> DkgResult<Round3BroadcastData<G>> {
        if !matches!(self.round, Round::Three) {
            return Err(Error::RoundError(
                Round::Three.into(),
                format!("Invalid Round, use round{}", self.round),
            ));
        }

        if echo_data.is_empty() {
            return Err(Error::RoundError(
                Round::Three.into(),
                "Missing broadcast data from other participants. Echo data is empty".to_string(),
            ));
        }
        if echo_data.len() < self.threshold {
            return Err(Error::RoundError(
                Round::Three.into(),
                "Missing broadcast data from other participants. Non-sufficient echo data provided.".to_string(),
            ));
        }

        for (id, echo) in echo_data {
            if self.id == *id {
                continue;
            }
            if !self.valid_participant_ids.contains(id) {
                continue;
            }
            if self
                .valid_participant_ids
                .difference(&echo.valid_participant_ids)
                .count()
                != 0
            {
                return Err(Error::RoundError(
                    Round::Three.into(),
                    format!(
                        "Received data from malicious secret_participant {}. Valid sets don't match.",
                        *id
                    ),
                ));
            }
        }

        let round3_bdata = Round3BroadcastData {
            commitments: self.components.feldman_verifier_set.verifiers().to_vec(),
        };
        self.round = Round::Four;

        Ok(round3_bdata)
    }
}

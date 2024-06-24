use super::*;

impl<I: ParticipantImpl<G> + Default, G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    Participant<I, G>
{
    pub(crate) fn round3_ready(&self) -> bool {
        self.round == Round::Three && self.received_round2_data.len() >= self.threshold
    }

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
    pub(crate) fn round3(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        if !self.round3_ready() {
            return Err(Error::RoundError(
                Round::Three.into(),
                format!("round not ready, haven't received enough data from other participants. Need {} more", self.threshold - self.received_round2_data.len()),
            ));
        }

        for round3 in self.received_round2_data.values() {
            round3.add_to_transcript(&mut self.transcript);
        }

        self.received_round3_data.insert(
            self.ordinal,
            Round3Data {
                sender_ordinal: self.ordinal,
                sender_id: self.id,
                feldman_commitments: self.feldman_verifier_set.clone(),
            },
        );
        self.round = Round::Four;
        Ok(RoundOutputGenerator::Round3(Round3OutputGenerator {
            participant_ids: self.valid_participant_ids.clone(),
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            feldman_commitments: self.feldman_verifier_set.clone(),
        }))
    }

    pub(crate) fn receive_round3data(&mut self, data: Round3Data<G>) -> DkgResult<()> {
        if self.round != Round::Four {
            return Err(Error::RoundError(
                3,
                "Invalid round payload received".to_string(),
            ));
        }
        if self.received_round3_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                3,
                "Sender has already sent data".to_string(),
            ));
        }
        self.check_sending_participant_id(3, data.sender_ordinal, data.sender_id)?;
        if !self
            .valid_participant_ids
            .contains_key(&data.sender_ordinal)
        {
            return Err(Error::RoundError(3, "Not a valid participant".to_string()));
        }
        if data.feldman_commitments.is_empty() {
            return Err(Error::RoundError(
                3,
                "Feldman commitments are empty".to_string(),
            ));
        }
        if data.feldman_commitments.len() != self.threshold {
            return Err(Error::RoundError(
                3,
                "Feldman commitments length is not equal to threshold".to_string(),
            ));
        }
        if data.feldman_commitments[1..]
            .iter()
            .fold(Choice::from(0u8), |acc, c| acc | c.is_identity())
            .into()
        {
            return Err(Error::RoundError(
                3,
                "Feldman commitments contain the identity point".to_string(),
            ));
        }

        let participant_type = self.received_round0_data[&data.sender_ordinal].sender_type;
        let feldman_valid = match participant_type {
            ParticipantType::Secret => {
                SecretParticipantImpl::check_feldman_verifier(data.feldman_commitments[0])
            }
            ParticipantType::Refresh => {
                RefreshParticipantImpl::check_feldman_verifier(data.feldman_commitments[0])
            }
        };
        if !feldman_valid {
            return Err(Error::RoundError(
                3,
                "Feldman commitment is not a valid verifier".to_string(),
            ));
        }

        let commitment_hash = Self::compute_feldman_commitments_hash(
            participant_type,
            data.sender_ordinal,
            data.sender_id,
            self.threshold,
            &data.feldman_commitments,
        );

        if commitment_hash
            == self.received_round0_data[&data.sender_ordinal].pedersen_commitment_hash
        {
            return Err(Error::RoundError(
                1,
                "Feldman commitment hash does not match".to_string(),
            ));
        }

        // verify the share
        let rhs =
            <G as SumOfProducts>::sum_of_products(&data.feldman_commitments, &self.powers_of_i);
        let lhs =
            self.message_generator * self.received_round1_data[&data.sender_ordinal].secret_share;
        if !bool::from((lhs - rhs).is_identity()) {
            return Err(Error::RoundError(
                3,
                "The share does not verify with the given commitments".to_string(),
            ));
        }

        self.received_round3_data
            .insert(data.sender_ordinal, data.clone());
        Ok(())
    }
}

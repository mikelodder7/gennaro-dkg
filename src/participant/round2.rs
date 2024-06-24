use super::*;

impl<I: ParticipantImpl<G> + Default, G: Group + GroupEncoding + Default> Participant<I, G> {
    pub(crate) fn round2_ready(&self) -> bool {
        self.round == Round::Two && self.received_round1_data.len() >= self.threshold
    }

    /// Computes round2 for this participant.
    ///
    /// Throws an error if this participant is not in round 2.
    ///
    /// Returns the data needed for round 2
    pub(crate) fn round2(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        if !self.round2_ready() {
            return Err(Error::RoundError(
                Round::Two.into(),
                format!("round not ready, haven't received enough data from other participants. Need {} more", self.threshold - self.received_round1_data.len()),
            ));
        }

        let mut blind_key = G::identity();
        let mut secret_share = G::Scalar::ZERO;
        let mut blind_share = G::Scalar::ZERO;
        let og_secret = self.secret_shares[self.ordinal].1;
        let og_blind = self.blinder_shares[self.ordinal].1;

        for data in self.received_round1_data.values() {
            blind_key += data.pedersen_commitments[0];
            secret_share += data.secret_share;
            blind_share += data.blind_share;
        }

        if secret_share.is_zero().into() || secret_share == og_secret {
            return Err(Error::RoundError(
                Round::Two.into(),
                "The resulting secret key share is invalid".to_string(),
            ));
        }
        if blind_share.is_zero().into() || blind_share == og_blind {
            return Err(Error::RoundError(
                Round::Two.into(),
                "The resulting blind key share is invalid".to_string(),
            ));
        }
        if self.valid_participant_ids.len() < self.threshold {
            return Err(Error::RoundError(
                Round::Two.into(),
                "Not enough valid participants, below the threshold".to_string(),
            ));
        }
        for data in self.received_round1_data.values() {
            data.add_to_transcript(&mut self.transcript);
        }

        self.round = Round::Three;
        self.secret_share = secret_share;
        self.blind_share = blind_share;
        self.blind_key = blind_key;
        self.received_round2_data.insert(
            self.ordinal,
            Round2Data {
                sender_ordinal: self.ordinal,
                sender_id: self.id,
                valid_participant_ids: self.valid_participant_ids.clone(),
            },
        );

        Ok(RoundOutputGenerator::Round2(Round2OutputGenerator {
            participant_ids: self.all_participant_ids.clone(),
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            valid_participant_ids: self.valid_participant_ids.clone(),
        }))
    }

    pub(crate) fn receive_round2data(&mut self, data: Round2Data<G>) -> DkgResult<()> {
        if self.round != Round::Three {
            return Err(Error::RoundError(
                3,
                "Invalid round payload received".to_string(),
            ));
        }
        if self.received_round2_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                2,
                "Sender has already sent data".to_string(),
            ));
        }
        self.check_sending_participant_id(2, data.sender_ordinal, data.sender_id)?;
        if data.valid_participant_ids.len() < self.threshold {
            return Err(Error::RoundError(
                2,
                "Valid participant ids length is less than threshold".to_string(),
            ));
        }
        if !data
            .valid_participant_ids
            .iter()
            .all(|(k, v)| self.all_participant_ids.contains_key(k) && bool::from(!v.is_zero()))
        {
            return Err(Error::RoundError(
                2,
                "Invalid valid participant ids".to_string(),
            ));
        }
        if self.valid_participant_ids != data.valid_participant_ids {
            return Err(Error::RoundError(
                2,
                "Valid participant ids do not match".to_string(),
            ));
        }
        self.received_round2_data
            .insert(data.sender_ordinal, data.clone());
        Ok(())
    }
}

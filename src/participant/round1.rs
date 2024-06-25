use super::*;

impl<I: ParticipantImpl<G> + Default, G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    Participant<I, G>
{
    pub(crate) fn round1_ready(&self) -> bool {
        self.round == Round::One && self.received_round0_data.len() >= self.threshold
    }

    /// Compute round1 for this participant.
    ///
    /// Throws an error if this participant is not in round 1.
    pub(crate) fn round1(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        if !self.round1_ready() {
            return Err(Error::RoundError(
                Round::One.into(),
                format!("round not ready, haven't received enough data from other participants. Need {} more", self.threshold - self.received_round0_data.len()),
            ));
        }
        let mut secret_share = BTreeMap::new();
        let mut blind_share = BTreeMap::new();
        for (i, (s, b)) in self
            .secret_shares
            .iter()
            .zip(self.blinder_shares.iter())
            .enumerate()
        {
            debug_assert_eq!(s.0, b.0, "Mismatched shares");
            if s.0 == self.id {
                continue;
            }

            secret_share.insert(i, s.1);
            blind_share.insert(i, b.1);
        }

        // Add received commitments to transcript
        for round0 in self.received_round0_data.values() {
            round0.add_to_transcript(&mut self.transcript);
        }

        self.valid_participant_ids.insert(self.ordinal, self.id);
        self.round = Round::Two;
        self.received_round1_data.insert(
            self.ordinal,
            Round1Data {
                sender_ordinal: self.ordinal,
                sender_id: self.id,
                message_generator: self.message_generator,
                blinder_generator: self.blinder_generator,
                pedersen_commitments: self.pedersen_verifier_set.clone(),
                secret_share: self.secret_share,
                blind_share: self.blind_share,
            },
        );
        Ok(RoundOutputGenerator::Round1(Round1OutputGenerator {
            participant_ids: self.all_participant_ids.clone(),
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            message_generator: self.message_generator,
            blinder_generator: self.blinder_generator,
            pedersen_commitments: self.pedersen_verifier_set.clone(),
            secret_share,
            blind_share,
        }))
    }

    pub(crate) fn receive_round1data(&mut self, data: Round1Data<G>) -> DkgResult<()> {
        if self.round != Round::Two {
            return Err(Error::RoundError(
                2,
                "Invalid round payload received".to_string(),
            ));
        }
        if self.received_round1_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                1,
                "Sender has already sent data".to_string(),
            ));
        }
        self.check_sending_participant_id(1, data.sender_ordinal, data.sender_id)?;
        if !self.received_round0_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                1,
                "Sender has not sent round 0 data".to_string(),
            ));
        }
        if data.pedersen_commitments.is_empty() {
            return Err(Error::RoundError(
                1,
                "Pedersen commitments are empty".to_string(),
            ));
        }
        if data.pedersen_commitments.len() != self.threshold {
            return Err(Error::RoundError(
                1,
                "Pedersen commitments length is not equal to threshold".to_string(),
            ));
        }
        if data.message_generator.is_identity().into() {
            return Err(Error::RoundError(
                1,
                "Message generator is the identity point".to_string(),
            ));
        }
        if data.blinder_generator.is_identity().into() {
            return Err(Error::RoundError(
                1,
                "Blinder generator is the identity point".to_string(),
            ));
        }
        if data
            .pedersen_commitments
            .iter()
            .fold(Choice::from(0u8), |acc, c| acc | c.is_identity())
            .into()
        {
            return Err(Error::RoundError(
                1,
                "Pedersen commitments contain the identity point".to_string(),
            ));
        }

        let participant_type = self.received_round0_data[&data.sender_ordinal].sender_type;
        let commitment_hash = Self::compute_pedersen_commitments_hash(
            participant_type,
            data.sender_ordinal,
            data.sender_id,
            self.threshold,
            &data.pedersen_commitments,
        );
        if commitment_hash
            == self.received_round0_data[&data.sender_ordinal].pedersen_commitment_hash
        {
            return Err(Error::RoundError(
                1,
                "Pedersen commitment hash does not match".to_string(),
            ));
        }
        // verify the share
        let rhs =
            <G as SumOfProducts>::sum_of_products(&data.pedersen_commitments, &self.powers_of_i);
        let lhs =
            self.message_generator * data.secret_share + self.blinder_generator * data.blind_share;
        if !bool::from((lhs - rhs).is_identity()) {
            return Err(Error::RoundError(
                1,
                "The share does not verify with the given commitments".to_string(),
            ));
        }
        self.valid_participant_ids
            .insert(data.sender_ordinal, data.sender_id);
        self.received_round1_data
            .insert(data.sender_ordinal, data.clone());
        Ok(())
    }
}

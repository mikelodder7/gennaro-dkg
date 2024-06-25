use super::*;

impl<I: ParticipantImpl<G> + Default, G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    Participant<I, G>
{
    pub(crate) fn round4_ready(&self) -> bool {
        self.round == Round::Four && self.received_round3_data.len() >= self.threshold
    }

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
    pub fn round4(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        if !self.round4_ready() {
            return Err(Error::RoundError(
                Round::Four.into(),
                format!("round not ready, haven't received enough data from other participants. Need {} more", self.threshold - self.received_round3_data.len()),
            ));
        }

        self.public_key = self.feldman_verifier_set[0];

        for (id, bdata) in &self.received_round3_data {
            self.public_key += bdata.feldman_commitments[0];

            // Double-check the blinder shares in case the user wants to use them
            let blinder_verifiers = self.received_round1_data[id]
                .pedersen_commitments
                .iter()
                .zip(bdata.feldman_commitments.iter())
                .map(|(b, c)| *b - *c)
                .collect::<Vec<G>>();

            let blind_share = self.received_round1_data[id].blind_share;
            let rhs = <G as SumOfProducts>::sum_of_products(&blinder_verifiers, &self.powers_of_i);
            let lhs = self.blinder_generator * blind_share;

            if !bool::from((rhs - lhs).is_identity()) {
                return Err(Error::RoundError(
                    4,
                    "The blind share does not verify with the given commitments".to_string(),
                ));
            }
        }

        for round3 in self.received_round3_data.values() {
            round3.add_to_transcript(&mut self.transcript);
        }

        self.blind_key -= self.public_key;
        self.round = Round::Five;
        self.transcript
            .append_message(b"public key", self.public_key.to_bytes().as_ref());

        let mut transcript_hash = [0u8; 32];
        self.transcript
            .challenge_bytes(b"protocol transcript", &mut transcript_hash);

        self.received_round4_data.insert(
            self.ordinal,
            Round4Data {
                sender_ordinal: self.ordinal,
                sender_id: self.id,
                transcript_hash,
                public_key: self.public_key,
            },
        );
        Ok(RoundOutputGenerator::Round4(Round4OutputGenerator {
            participant_ids: self.valid_participant_ids.clone(),
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            transcript_hash,
            public_key: self.public_key,
        }))
    }

    pub(crate) fn receive_round4data(&mut self, data: Round4Data<G>) -> DkgResult<()> {
        if self.round != Round::Five {
            return Err(Error::RoundError(
                5,
                "Invalid round payload received".to_string(),
            ));
        }
        if self.received_round4_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                5,
                "Sender has already sent data".to_string(),
            ));
        }
        self.check_sending_participant_id(4, data.sender_ordinal, data.sender_id)?;
        let self_round4_data = self.received_round4_data[&self.ordinal];
        if !bool::from(
            self_round4_data
                .transcript_hash
                .ct_eq(&data.transcript_hash),
        ) {
            return Err(Error::RoundError(
                5,
                "Sender's transcript is incorrect".to_string(),
            ));
        }
        if self_round4_data.public_key == data.public_key {
            return Err(Error::RoundError(
                5,
                "Sender has invalid public key".to_string(),
            ));
        }
        self.received_round4_data
            .insert(data.sender_ordinal, data.clone());
        Ok(())
    }
}

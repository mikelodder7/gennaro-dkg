use super::*;
use crate::Round1OutputGenerator;

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
                Round::One,
                format!("round not ready, haven't received enough data from other participants. Need {} more", self.threshold - self.received_round0_data.len()),
            ));
        }
        let mut secret_share = BTreeMap::new();
        let mut blind_share = BTreeMap::new();
        for (i, (s, b)) in self
            .components
            .secret_shares()
            .iter()
            .zip(self.components.blinder_shares().iter())
            .enumerate()
        {
            debug_assert_eq!(s.identifier, b.identifier, "Mismatched shares");
            if s.identifier == self.id {
                continue;
            }

            secret_share.insert(i, *s);
            blind_share.insert(i, *b);
        }

        // Add received commitments to transcript
        for round0 in self.received_round0_data.values() {
            round0.add_to_transcript(&mut self.transcript);
        }

        self.valid_participant_ids.insert(self.ordinal, self.id);
        self.round = Round::Two;

        let pedersen_verifier_set: VecPedersenVerifierSet<
            SecretShare<G::Scalar>,
            ShareVerifierGroup<G>,
        > = self.components.pedersen_verifier_set().into();
        self.received_round1_data.insert(
            self.ordinal,
            Round1Data {
                sender_ordinal: self.ordinal,
                sender_id: self.id,
                message_generator: self.message_generator,
                blinder_generator: self.blinder_generator,
                pedersen_commitments: pedersen_verifier_set.blind_verifiers().to_vec(),
                secret_share: self.components.secret_shares()[self.ordinal],
                blind_share: self.components.blinder_shares()[self.ordinal],
            },
        );
        Ok(RoundOutputGenerator::Round1(Round1OutputGenerator {
            participant_ids: self.all_participant_ids.clone(),
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            message_generator: self.message_generator,
            blinder_generator: self.blinder_generator,
            pedersen_commitments: pedersen_verifier_set.blind_verifiers().to_vec(),
            secret_share,
            blind_share,
        }))
    }

    pub(crate) fn receive_round1data(&mut self, data: Round1Data<G>) -> DkgResult<()> {
        if self.round > Round::Two {
            return Err(Error::RoundError(
                Round::One,
                "Invalid round payload received".to_string(),
            ));
        }
        if self.received_round1_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                Round::One,
                "Sender has already sent data".to_string(),
            ));
        }
        self.check_sending_participant_id(Round::One, data.sender_ordinal, data.sender_id)?;
        if !self.received_round0_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                Round::One,
                "Sender has not sent round 0 data".to_string(),
            ));
        }
        if data.pedersen_commitments.is_empty() {
            return Err(Error::RoundError(
                Round::One,
                "Pedersen commitments are empty".to_string(),
            ));
        }
        if data.pedersen_commitments.len() != self.threshold {
            return Err(Error::RoundError(
                Round::One,
                "Pedersen commitments length is not equal to threshold".to_string(),
            ));
        }
        if data.message_generator.is_identity().into() {
            return Err(Error::RoundError(
                Round::One,
                "Message generator is the identity point".to_string(),
            ));
        }
        if data.blinder_generator.is_identity().into() {
            return Err(Error::RoundError(
                Round::One,
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
                Round::One,
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
            != self.received_round0_data[&data.sender_ordinal].pedersen_commitment_hash
        {
            return Err(Error::RoundError(
                Round::One,
                "Pedersen commitment hash does not match".to_string(),
            ));
        }
        debug_assert_eq!(data.secret_share.identifier, self.id);
        debug_assert_eq!(data.blind_share.identifier, self.id);
        // verify the share
        let sum_inputs = self
            .powers_of_i
            .iter()
            .copied()
            .zip(data.pedersen_commitments.iter().map(|g| **g))
            .collect::<Vec<(G::Scalar, G)>>();
        let rhs = <G as SumOfProducts>::sum_of_products(&sum_inputs);
        let lhs = self.message_generator * *data.secret_share.value
            + self.blinder_generator * *data.blind_share.value;
        if !bool::from((lhs - rhs).is_identity()) {
            return Err(Error::RoundError(
                Round::One,
                "The share does not verify with the given commitments".to_string(),
            ));
        }
        self.valid_participant_ids
            .insert(data.sender_ordinal, data.sender_id);
        self.received_round1_data.insert(data.sender_ordinal, data);
        Ok(())
    }
}

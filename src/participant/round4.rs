use super::*;
use crate::Round4OutputGenerator;
use vsss_rs::IdentifierPrimeField;

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
                Round::Four,
                format!("round not ready, haven't received enough data from other participants. Need {} more", self.threshold - self.received_round3_data.len()),
            ));
        }
        let mut secret_share = G::Scalar::ZERO;
        let mut public_key = G::identity();
        let secret_shares = self.components.secret_shares();
        let og_secret = *secret_shares[self.ordinal].value;
        self.valid_participant_ids.clear();

        let mut all_refresh = true;

        for (ordinal, round3) in &self.received_round3_data {
            let participant_type = self.received_round1_data[ordinal].sender_type;
            all_refresh &= matches!(participant_type, ParticipantType::Refresh);
            public_key += *round3.feldman_commitments[0];
            let r1data = &self.received_round2_data[ordinal];
            debug_assert_eq!(r1data.secret_share.identifier, self.id);
            secret_share += *r1data.secret_share.value;
        }

        let public_key_identity = bool::from(public_key.is_identity());
        if all_refresh && !public_key_identity || !all_refresh && public_key_identity {
            return Err(Error::RoundError(
                Round::Four,
                "The resulting public key is invalid".to_string(),
            ));
        }

        if secret_share == og_secret {
            return Err(Error::RoundError(
                Round::Four,
                "The resulting secret key share is invalid".to_string(),
            ));
        }

        for round3 in self.received_round3_data.values() {
            round3.add_to_transcript(&mut self.transcript);
            self.valid_participant_ids
                .insert(round3.sender_ordinal, round3.sender_id);
        }

        let mut transcript_hash = [0u8; 32];
        self.transcript
            .challenge_bytes(b"protocol transcript", &mut transcript_hash);

        self.public_key = ValueGroup(public_key);
        self.secret_share =
            SecretShare::with_identifier_and_value(self.id, IdentifierPrimeField(secret_share));
        self.round = Round::Five;
        self.transcript
            .append_message(b"public key", self.public_key.to_bytes().as_ref());

        self.received_round4_data.insert(
            self.ordinal,
            Round4Data {
                sender_ordinal: self.ordinal,
                sender_id: self.id,
                transcript_hash,
                public_key: self.public_key,
                computed_secret_commitment: ValueGroup(
                    self.message_generator * self.secret_share.value.0,
                ),
            },
        );
        Ok(RoundOutputGenerator::Round4(Round4OutputGenerator {
            participant_ids: self.valid_participant_ids.clone(),
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            transcript_hash,
            public_key: self.public_key,
            computed_secret_commitment: ValueGroup(
                self.message_generator * self.secret_share.value.0,
            ),
        }))
    }

    pub(crate) fn receive_round4data(&mut self, data: Round4Data<G>) -> DkgResult<()> {
        if self.round != Round::Five {
            return Err(Error::RoundError(
                Round::Four,
                "Invalid round payload received".to_string(),
            ));
        }
        if self.received_round4_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                Round::Four,
                "Sender has already sent data".to_string(),
            ));
        }
        self.check_sending_participant_id(Round::Four, data.sender_ordinal, data.sender_id)?;
        let self_round4_data = self.received_round4_data[&self.ordinal];
        if !bool::from(
            self_round4_data
                .transcript_hash
                .ct_eq(&data.transcript_hash),
        ) {
            return Err(Error::RoundError(
                Round::Four,
                "Sender's transcript is incorrect".to_string(),
            ));
        }
        if self_round4_data.public_key != data.public_key {
            return Err(Error::RoundError(
                Round::Four,
                "Sender has invalid public key".to_string(),
            ));
        }

        self.received_round4_data.insert(data.sender_ordinal, data);
        Ok(())
    }
}

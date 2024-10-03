use super::*;
use crate::Round2OutputGenerator;

impl<I: ParticipantImpl<G> + Default, G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    Participant<I, G>
{
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
                Round::Two,
                format!("round not ready, haven't received enough data from other participants. Need {} more", self.threshold - self.received_round1_data.len()),
            ));
        }

        for round1 in self.received_round1_data.values() {
            round1.add_to_transcript(&mut self.transcript);
        }

        self.round = Round::Three;
        self.received_round2_data.insert(
            self.ordinal,
            Round2Data {
                sender_ordinal: self.ordinal,
                sender_id: self.id,
                valid_participant_ids: self.valid_participant_ids.clone(),
            },
        );

        Ok(RoundOutputGenerator::Round2(Round2OutputGenerator {
            participant_ids: self.valid_participant_ids.clone(),
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            valid_participant_ids: self.valid_participant_ids.clone(),
        }))
    }

    pub(crate) fn receive_round2data(&mut self, data: Round2Data<G>) -> DkgResult<()> {
        if self.round > Round::Three {
            return Err(Error::RoundError(
                Round::Two,
                "Invalid round payload received".to_string(),
            ));
        }
        if self.received_round2_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                Round::Two,
                "Sender has already sent data".to_string(),
            ));
        }
        self.check_sending_participant_id(Round::Two, data.sender_ordinal, data.sender_id)?;
        if self.valid_participant_ids != data.valid_participant_ids {
            return Err(Error::RoundError(
                Round::Two,
                "Valid participant ids do not match".to_string(),
            ));
        }
        if !self
            .valid_participant_ids
            .contains_key(&data.sender_ordinal)
        {
            return Err(Error::RoundError(
                Round::Two,
                "Sender has already sent data".to_string(),
            ));
        }
        if !self.received_round0_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                Round::Two,
                "Sender didn't send any previous round 0 data".to_string(),
            ));
        }
        if !self.received_round1_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                Round::Two,
                "Sender didn't send any previous round 1 data".to_string(),
            ));
        }
        self.received_round2_data
            .insert(data.sender_ordinal, data.clone());
        Ok(())
    }
}

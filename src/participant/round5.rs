use super::*;

impl<I: ParticipantImpl<G> + Default, G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    Participant<I, G>
{
    pub(crate) fn round5_ready(&self) -> bool {
        self.round == Round::Five && self.received_round4_data.len() >= self.threshold
    }

    /// Computes round 5 for this participant.
    ///
    /// Checks if all participants computed the same public key.
    ///
    /// Throws an error if this participant is not in round 5.
    pub fn round5(&self) -> DkgResult<RoundOutputGenerator<G>> {
        if !self.round5_ready() {
            return Err(Error::RoundError(
                Round::Five.into(),
                format!("round not ready, haven't received enough data from other participants. Need {} more", self.threshold - self.received_round4_data.len()),
            ));
        }

        Ok(RoundOu)
    }
}

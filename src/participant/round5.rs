use crate::{
    DkgResult, Error, GroupHasher, Participant, ParticipantImpl, Round, RoundOutputGenerator,
};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve_tools::SumOfProducts;
use vsss_rs::{DefaultShare, ReadableShareSet};

impl<I: ParticipantImpl<G> + Default, G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    Participant<I, G>
{
    pub(crate) fn round5_ready(&self) -> bool {
        self.round == Round::Five && self.received_round4_data.len() >= self.threshold
    }

    /// Computes round 5 for this participant.
    ///
    /// Checks that the combined commitment shares match the public key.
    ///
    /// Throws an error if this participant is not in round 5 or the check fails.
    pub fn round5(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        if !self.round5_ready() {
            return Err(Error::RoundError(
                Round::Five,
                format!("round not ready, haven't received enough data from other participants. Need {} more", self.threshold - self.received_round4_data.len()),
            ));
        }
        let mut commitment_shares = Vec::with_capacity(self.received_round4_data.len());
        for round4 in self.received_round4_data.values() {
            let share = DefaultShare {
                identifier: round4.sender_id,
                value: round4.computed_secret_commitment,
            };
            commitment_shares.push(share);
        }
        let res = commitment_shares.combine();
        if res.is_err() {
            return Err(Error::RoundError(
                Round::Five,
                "Failed to combine commitment shares".to_string(),
            ));
        }
        let combined_commitment = res.expect("to succeed because err was already checked");

        if combined_commitment != self.public_key {
            return Err(Error::RoundError(
                Round::Five,
                "The combined commitment does not match the public key".to_string(),
            ));
        }
        self.completed = true;
        Ok(RoundOutputGenerator::Round5)
    }
}

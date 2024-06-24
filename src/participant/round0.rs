use crate::{
    DkgResult, Error, GroupHasher, Participant, ParticipantImpl, Round, Round0Data,
    Round0OutputGenerator, RoundOutputGenerator, SumOfProducts,
};
use elliptic_curve::group::GroupEncoding;
use vsss_rs::CtIsZero;

impl<I: ParticipantImpl<G> + Default, G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    Participant<I, G>
{
    pub(crate) fn round0(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        let pedersen_commitment_hash = Self::compute_pedersen_commitments_hash(
            self.participant_impl.get_type(),
            self.ordinal,
            self.id,
            self.threshold,
            &self.pedersen_verifier_set,
        );
        let feldman_commitment_hash = Self::compute_feldman_commitments_hash(
            self.participant_impl.get_type(),
            self.ordinal,
            self.id,
            self.threshold,
            &self.feldman_verifier_set,
        );
        self.round = Round::One;
        self.received_round0_data.insert(
            self.ordinal,
            Round0Data {
                sender_ordinal: self.ordinal,
                sender_id: self.id,
                sender_type: self.participant_impl.get_type(),
                pedersen_commitment_hash,
                feldman_commitment_hash,
            },
        );
        Ok(RoundOutputGenerator::Round0(Round0OutputGenerator {
            participant_ids: self.all_participant_ids.clone(),
            sender_type: self.participant_impl.get_type(),
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            pedersen_commitment_hash,
            feldman_commitment_hash,
        }))
    }

    pub(crate) fn receive_round0data(&mut self, data: Round0Data<G>) -> DkgResult<()> {
        if self.round != Round::One {
            return Err(Error::RoundError(
                0,
                "Invalid round payload received".to_string(),
            ));
        }
        if self.received_round0_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(
                0,
                "Sender has already sent data".to_string(),
            ));
        }
        self.check_sending_participant_id(0, data.sender_ordinal, data.sender_id)?;
        if data.pedersen_commitment_hash.ct_is_zero().into() {
            return Err(Error::RoundError(
                0,
                "Pedersen commitment hash is zero".to_string(),
            ));
        }
        if data.feldman_commitment_hash.ct_is_zero().into() {
            return Err(Error::RoundError(
                0,
                "Feldman commitment hash is zero".to_string(),
            ));
        }
        self.received_round0_data.insert(data.sender_ordinal, data);
        Ok(())
    }
}

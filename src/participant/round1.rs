use crate::{
    DkgResult, Error, GroupHasher, Participant, ParticipantImpl, Round, Round1Data,
    Round1OutputGenerator, RoundOutputGenerator, SecretShare,
};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve_tools::*;
use vsss_rs::{
    CtIsZero, FeldmanVerifierSet, PedersenResult, PedersenVerifierSet, ShareVerifierGroup,
    VecFeldmanVerifierSet, VecPedersenVerifierSet,
};

impl<I: ParticipantImpl<G> + Default, G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    Participant<I, G>
{
    pub(crate) fn round1(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        let pedersen_verifier_set: VecPedersenVerifierSet<
            SecretShare<G::Scalar>,
            ShareVerifierGroup<G>,
        > = self.components.pedersen_verifier_set().into();
        let pedersen_commitment_hash = Self::compute_pedersen_commitments_hash(
            self.participant_impl.get_type(),
            self.ordinal,
            self.id,
            self.threshold,
            pedersen_verifier_set.blind_verifiers(),
        );
        let feldman_verifier_set: VecFeldmanVerifierSet<
            SecretShare<G::Scalar>,
            ShareVerifierGroup<G>,
        > = self.components.feldman_verifier_set().into();
        let feldman_commitment_hash = Self::compute_feldman_commitments_hash(
            self.participant_impl.get_type(),
            self.ordinal,
            self.id,
            self.threshold,
            feldman_verifier_set.verifiers(),
        );
        self.round = Round::Two;
        self.received_round1_data.insert(
            self.ordinal,
            Round1Data {
                sender_ordinal: self.ordinal,
                sender_id: self.id,
                sender_type: self.participant_impl.get_type(),
                pedersen_commitment_hash,
                feldman_commitment_hash,
            },
        );
        Ok(RoundOutputGenerator::Round1(Round1OutputGenerator {
            participant_ids: self.all_participant_ids.clone(),
            sender_type: self.participant_impl.get_type(),
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            pedersen_commitment_hash,
            feldman_commitment_hash,
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
        if data.pedersen_commitment_hash.ct_is_zero().into() {
            return Err(Error::RoundError(
                Round::One,
                "Pedersen commitment hash is zero".to_string(),
            ));
        }
        if data.feldman_commitment_hash.ct_is_zero().into() {
            return Err(Error::RoundError(
                Round::One,
                "Feldman commitment hash is zero".to_string(),
            ));
        }
        self.received_round1_data.insert(data.sender_ordinal, data);
        Ok(())
    }
}

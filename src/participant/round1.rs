use super::*;

impl<I: ParticipantImpl<G> + Default, G: Group + GroupEncoding + Default> Participant<I, G> {
    /// Compute round1 for this participant.
    ///
    /// Throws an error if this participant is not in round 1.
    pub fn round1(
        &mut self,
    ) -> DkgResult<(Round1BroadcastData<G>, BTreeMap<usize, Round1P2PData>)> {
        if !matches!(self.round, Round::One) {
            return Err(Error::RoundError(
                Round::One.into(),
                format!("Invalid Round, use round{}", self.round),
            ));
        }
        let mut map = BTreeMap::new();
        for (s, b) in self
            .components
            .secret_shares
            .iter()
            .zip(self.components.blinder_shares.iter())
        {
            let id = s.identifier() as usize;
            if id == self.id {
                continue;
            }

            map.insert(
                id,
                Round1P2PData {
                    secret_share: s.clone(), // serde_bare::to_vec(&s).expect("to serialize into a tuple"),
                    blind_share: b.clone(), // serde_bare::to_vec(&b).expect("to serialize into a tuple"),
                },
            );
        }

        self.round = Round::Two;
        let bdata = Round1BroadcastData {
            blinder_generator: self.components.pedersen_verifier_set.blinder_generator(),
            message_generator: self.components.pedersen_verifier_set.secret_generator(),
            pedersen_commitments: self
                .components
                .pedersen_verifier_set
                .blind_verifiers()
                .to_vec(),
        };

        Ok((bdata, map))
    }
}

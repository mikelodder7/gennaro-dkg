use super::*;

impl<G: Group + GroupEncoding + Default> Participant<G> {
    /// Compute round1 for this participant.
    ///
    /// Throws an error if this participant is not in round 1.
    pub fn round1(
        &mut self,
    ) -> DkgResult<(Round1BroadcastData<G>, BTreeMap<usize, Round1P2PData>)> {
        if !matches!(self.round, Round::One) {
            return Err(Error::RoundError(1, "Invalid Round".to_string()));
        }
        let mut map = BTreeMap::new();
        for (s, b) in self
            .components
            .secret_shares
            .iter()
            .zip(self.components.blind_shares.iter())
        {
            let id = s.identifier() as usize;
            if id == self.id {
                continue;
            }

            map.insert(
                id,
                Round1P2PData {
                    secret_share: s.clone(),
                    blind_share: b.clone(),
                },
            );
        }

        self.round = Round::Two;
        let bdata = Round1BroadcastData {
            blinder_generator: self.components.verifier.generator,
            message_generator: self.components.verifier.feldman_verifier.generator,
            pedersen_commitments: self.components.verifier.commitments.clone(),
        };

        Ok((bdata, map))
    }
}

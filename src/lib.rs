//! Gennaro's Distributed Key Generation Algorithm.
//!
//! The algorithm uses participants with unique identifiers
//! and each party communicates broadcast data and peer-to-peer
//! data depending on the round.
//!
//! The full paper can be found is
//! [GennaroDKG](https://link.springer.com/article/10.1007/s00145-006-0347-3).
//!
//! The interface has been written to work with anything that implements the elliptic-curve::Group
//! trait.
//!
//! An example for generating a secret key on the Secp256k1 curve with 2 out of 3 participants.
//!
//! ```
//! use gennaro_dkg::{
//!     elliptic_curve_tools::SumOfProducts,
//!     vsss_rs::{
//!         elliptic_curve::{group::GroupEncoding, Group, PrimeField},
//!         Share, ShareElement, IdentifierPrimeField, ReadableShareSet
//!     },
//!     *,
//! };
//! use std::num::NonZeroUsize;
//! use k256::{ProjectivePoint, Scalar};
//!
//! fn next_round<G: GroupHasher + GroupEncoding + SumOfProducts + Default>(
//!     participants: &mut [SecretParticipant<G>],
//! ) -> Vec<RoundOutputGenerator<G>> {
//!     let mut round_generators = Vec::with_capacity(participants.len());
//!     for participant in participants {
//!         let generator = participant.run().unwrap();
//!         round_generators.push(generator);
//!     }
//!     round_generators
//! }
//!
//! fn receive<G: GroupHasher + GroupEncoding + SumOfProducts + Default>(
//!     participants: &mut [SecretParticipant<G>],
//!     round_generators: Vec<RoundOutputGenerator<G>>,
//! ) {
//!     for round_generator in &round_generators {
//!         for ParticipantRoundOutput {
//!             dst_ordinal: ordinal,
//!             dst_id: id,
//!             data,
//!             ..
//!         } in round_generator.iter()
//!         {
//!             if let Some(participant) = participants.get_mut(ordinal) {
//!                 assert_eq!(participant.get_ordinal(), ordinal);
//!                 assert_eq!(participant.get_id(), id);
//!                 let res = participant.receive(data.as_slice());
//!                 assert!(res.is_ok());
//!             }
//!         }
//!     }
//! }
//!
//! let parameters = Parameters::new(NonZeroUsize::new(2).unwrap(), NonZeroUsize::new(3).unwrap(), None, None, None);
//!
//! let mut participants = vec![
//!     SecretParticipant::<ProjectivePoint>::new(IdentifierPrimeField(Scalar::from(1u64)), &parameters).unwrap(),
//!     SecretParticipant::<ProjectivePoint>::new(IdentifierPrimeField(Scalar::from(2u64)), &parameters).unwrap(),
//!     SecretParticipant::<ProjectivePoint>::new(IdentifierPrimeField(Scalar::from(3u64)), &parameters).unwrap(),
//! ];
//!
//! // Run all rounds
//! for _ in [Round::One, Round::Two, Round::Three, Round::Four, Round::Five] {
//!    let generators = next_round(&mut participants);
//!    receive(&mut participants, generators);
//! }
//! // Get the verification key
//! let pk1 = participants[0].get_public_key().unwrap();
//! // Get the secret share
//! let share1 = participants[0].get_secret_share().unwrap();
//!
//! assert_eq!(pk1.is_identity().unwrap_u8(), 0u8);
//!
//! let pk2 = participants[1].get_public_key().unwrap();
//! let share2 = participants[1].get_secret_share().unwrap();
//!
//! assert_eq!(pk2.is_identity().unwrap_u8(), 0u8);
//!
//! let pk3 = participants[2].get_public_key().unwrap();
//! let share3 = participants[2].get_secret_share().unwrap();
//!
//! assert_eq!(pk3.is_identity().unwrap_u8(), 0u8);
//!
//! // Public keys will be equal
//! assert_eq!(pk1, pk2);
//! assert_eq!(pk2, pk3);
//! // Shares should not be
//! assert_ne!(share1, share2);
//! assert_ne!(share1, share3);
//! assert_ne!(share2, share3);
//!
//! // For demonstration purposes, the shares if collected can be combined to recreate
//! // the computed secret
//!
//! let sk = &[share1, share2, share3].combine().unwrap();
//! let computed_pk = ProjectivePoint::GENERATOR * sk.0;
//! assert_eq!(computed_pk, pk1);
//! ```
//!
//! The output of the DKG is the same as if shamir secret sharing
//! had been run on the secret and sent to separate parties.
#![deny(
    missing_docs,
    unused_import_braces,
    unused_qualifications,
    unused_parens,
    unused_lifetimes,
    unconditional_recursion,
    unused_extern_crates,
    trivial_casts,
    trivial_numeric_casts,
    clippy::unwrap_used
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use elliptic_curve;
pub use elliptic_curve_tools;
pub use rand_core;
pub use vsss_rs;

mod data;
mod error;
mod parameters;
mod participant;
mod traits;
mod utils;

use elliptic_curve::group::GroupEncoding;
use std::num::NonZeroUsize;

pub use data::*;
pub use error::*;
pub use parameters::*;
pub use participant::*;
pub use traits::*;

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::group::GroupEncoding;
    use elliptic_curve_tools::SumOfProducts;
    use rstest::*;
    use vsss_rs::{
        IdentifierPrimeField, ParticipantIdGeneratorCollection, ParticipantIdGeneratorType,
        ReadableShareSet,
    };

    #[test]
    fn one_corrupted_party_k256() {
        one_corrupted_party::<k256::ProjectivePoint>(k256::ProjectivePoint::default());
    }

    #[rstest]
    #[case::k256(k256::ProjectivePoint::default())]
    #[case::p256(p256::ProjectivePoint::default())]
    #[case::blsg1(blsful::inner_types::G1Projective::default())]
    #[case::blsg2(blsful::inner_types::G2Projective::default())]
    #[case::ed25519(vsss_rs::curve25519::WrappedEdwards::default())]
    #[case::ristretto(vsss_rs::curve25519::WrappedRistretto::default())]
    #[case::ed448(ed448_goldilocks_plus::EdwardsPoint::default())]
    fn one_corrupted_party<G: GroupHasher + GroupEncoding + SumOfProducts + Default>(
        #[case] _g: G,
    ) {
        const THRESHOLD: usize = 2;
        const LIMIT: usize = 4;
        const BAD_ID: usize = 4;

        let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
        let limit = NonZeroUsize::new(LIMIT).unwrap();
        let numbering = vec![ParticipantIdGeneratorType::sequential(
            None,
            None,
            NonZeroUsize::new(4).unwrap(),
        )];
        let parameters = Parameters::<G>::new(threshold, limit, None, None, Some(numbering));
        let numbering = vec![
            ParticipantIdGeneratorType::<IdentifierPrimeField<G::Scalar>>::sequential(
                None,
                None,
                NonZeroUsize::new(4).unwrap(),
            ),
        ];
        let mut participants = ParticipantIdGeneratorCollection::from(&numbering)
            .iter()
            .map(|id| SecretParticipant::<G>::new(id, &parameters).unwrap())
            .collect::<Vec<_>>();

        for _ in [Round::One, Round::Two] {
            let generators = next_round(&mut participants);
            receive(&mut participants, generators);
        }

        // Corrupt bad actor
        participants.remove(BAD_ID - 1);
        for _ in [Round::Three, Round::Four, Round::Five] {
            let generators = next_round(&mut participants);
            receive(&mut participants, generators);
        }

        let shares = participants
            .iter()
            .map(|p| p.get_secret_share().unwrap())
            .collect::<Vec<_>>();

        let res = shares.combine();
        assert!(res.is_ok());
        let secret = res.unwrap();

        let expected_pk = G::generator() * *secret;

        assert_eq!(participants[1].get_public_key().unwrap(), expected_pk);
    }

    fn next_round<G: GroupHasher + GroupEncoding + SumOfProducts + Default>(
        participants: &mut [SecretParticipant<G>],
    ) -> Vec<RoundOutputGenerator<G>> {
        let mut round_generators = Vec::with_capacity(participants.len());
        for participant in participants {
            let generator = participant.run().unwrap();
            round_generators.push(generator);
        }
        round_generators
    }

    fn receive<G: GroupHasher + GroupEncoding + SumOfProducts + Default>(
        participants: &mut [SecretParticipant<G>],
        round_generators: Vec<RoundOutputGenerator<G>>,
    ) {
        for round_generator in &round_generators {
            for ParticipantRoundOutput {
                dst_ordinal: ordinal,
                dst_id: id,
                data,
                ..
            } in round_generator.iter()
            {
                if let Some(participant) = participants.get_mut(ordinal) {
                    assert_eq!(participant.ordinal, ordinal);
                    assert_eq!(participant.id, id);
                    let res = participant.receive(data.as_slice());
                    assert!(res.is_ok());
                }
            }
        }
    }
}

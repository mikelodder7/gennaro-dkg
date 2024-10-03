//! Gennaro's Distributed Key Generation Algorithm.
//!
//! The algorithm uses participants with unique identifiers
//! and each party communicates broadcast data and peer-to-peer
//! data depending on the round. Round 1 generates secret_participant key shares
//! which are checked for correctness in round 2. Any secret_participant that fails
//! in round 2 is dropped from the valid set which is communicated in round 3.
//! Round 4 communicates only with the remaining valid participants
//! and computes the secret share and verification key. Round 5 checks that
//! all participants computed the same verification key.
//!
//! The idea is that Rounds 3 and 5 serve as echo broadcasts to check the
//! state of all valid participants. If an error occurs in any round, then
//! participants either drop invalid participants or abort.
//!
//! The full paper can be found
//! <https://link.springer.com/content/pdf/10.1007/s00145-006-0347-3.pdf>.
//!
//! The interface has been written to work with anything that implements the elliptic-curve::Group
//! trait.
//!
//! An example for generating a secret key on the Secp256k1 curve with 2 out of 3 participants.
//!
//! ```
//! use gennaro_dkg::*;
//! use tk256::{ProjectivePoint, Scalar};
//! use maplit::btreemap;
//! use std::{
//!     collections::BTreeMap,
//!     num::NonZeroUsize,
//! };
//! use vsss_rs::{Share, ShareElement, elliptic_curve::{Group, PrimeField}};
//!
//! let parameters = Parameters::new(NonZeroUsize::new(2).unwrap(), NonZeroUsize::new(3).unwrap());
//!
//! let mut participant1 = SecretParticipant::<ProjectivePoint>::new(NonZeroUsize::new(1).unwrap(), parameters).unwrap();
//! let mut participant2 = SecretParticipant::<ProjectivePoint>::new(NonZeroUsize::new(2).unwrap(), parameters).unwrap();
//! let mut participant3 = SecretParticipant::<ProjectivePoint>::new(NonZeroUsize::new(3).unwrap(), parameters).unwrap();
//!
//! // Round 1
//! let (b1data1, p2p1data) = participant1.round1().unwrap();
//! let (b2data1, p2p2data) = participant2.round1().unwrap();
//! let (b3data1, p2p3data) = participant3.round1().unwrap();
//!
//! // Can't call the same round twice
//! assert!(participant1.round1().is_err());
//! assert!(participant2.round1().is_err());
//! assert!(participant3.round1().is_err());
//!
//! // Send b1data1 to secret_participant 2 and 3
//! // Send b2data1 to secret_participant 1 and 3
//! // Send b3data1 to secret_participant 1 and 2
//!
//! // Send p2p1data[&2] to secret_participant 2
//! // Send p2p1data[&3] to secret_participant 3
//!
//! // Send p2p2data[&1] to secret_participant 1
//! // Send p2p2data[&3] to secret_participant 3
//!
//! // Send p2p3data[&1] to secret_participant 1
//! // Send p2p3data[&2] to secret_participant 2
//!
//! let p1bdata1 = btreemap! {
//!     2 => b2data1.clone(),
//!     3 => b3data1.clone(),
//! };
//! let p1pdata = btreemap! {
//!     2 => p2p2data[&1].clone(),
//!     3 => p2p3data[&1].clone(),
//! };
//! let b1data2 = participant1.round2(p1bdata1, p1pdata).unwrap();
//!
//! let p2bdata1 = btreemap! {
//!     1 => b1data1.clone(),
//!     3 => b3data1.clone(),
//! };
//! let p2pdata = btreemap! {
//!     1 => p2p1data[&2].clone(),
//!     3 => p2p3data[&2].clone(),
//! };
//! let b2data2 = participant2.round2(p2bdata1, p2pdata).unwrap();
//!
//! let p3bdata1 = btreemap! {
//!     1 => b1data1.clone(),
//!     2 => b2data1.clone(),
//! };
//! let p3pdata = btreemap! {
//!     1 => p2p1data[&3].clone(),
//!     2 => p2p2data[&3].clone(),
//! };
//! let b3data2 = participant3.round2(p3bdata1, p3pdata).unwrap();
//!
//! // Send b1data2 to participants 2 and 3
//! // Send b2data2 to participants 1 and 3
//! // Send b3data2 to participants 1 and 2
//!
//! // This is an optimization for the example in reality each secret_participant computes this
//! let bdata2 = btreemap! {
//!     1 => b1data2,
//!     2 => b2data2,
//!     3 => b3data2,
//! };
//!
//! let b1data3 = participant1.round3(&bdata2).unwrap();
//! let b2data3 = participant2.round3(&bdata2).unwrap();
//! let b3data3 = participant3.round3(&bdata2).unwrap();
//!
//! // Send b1data3 to participants 2 and 3
//! // Send b2data3 to participants 1 and 3
//! // Send b3data3 to participants 1 and 2
//!
//! // This is an optimization for the example in reality each secret_participant computes this
//! let bdata3 = btreemap! {
//!     1 => b1data3,
//!     2 => b2data3,
//!     3 => b3data3,
//! };
//!
//! let b1data4 = participant1.round4(&bdata3).unwrap();
//! let b2data4 = participant2.round4(&bdata3).unwrap();
//! let b3data4 = participant3.round4(&bdata3).unwrap();
//!
//! // Send b1data4 to participants 2 and 3
//! // Send b2data4 to participants 1 and 3
//! // Send b3data4 to participants 1 and 2
//!
//! // Verify that the same key is computed then done
//!
//! // This is an optimization for the example in reality each secret_participant computes this
//! let bdata4 = btreemap! {
//!     1 => b1data4,
//!     2 => b2data4,
//!     3 => b3data4,
//! };
//!
//! assert!(participant1.round5(&bdata4).is_ok());
//! assert!(participant2.round5(&bdata4).is_ok());
//! assert!(participant3.round5(&bdata4).is_ok());
//!
//! // Get the verification key
//! let pk1 = participant1.get_public_key().unwrap();
//! // Get the secret share
//! let share1 = participant1.get_secret_share().unwrap();
//!
//! assert_eq!(pk1.is_identity().unwrap_u8(), 0u8);
//! assert_eq!(share1.is_zero().unwrap_u8(), 0u8);
//!
//! let pk2 = participant2.get_public_key().unwrap();
//! let share2 = participant2.get_secret_share().unwrap();
//!
//! assert_eq!(pk2.is_identity().unwrap_u8(), 0u8);
//! assert_eq!(share2.is_zero().unwrap_u8(), 0u8);
//!
//! let pk3 = participant3.get_public_key().unwrap();
//! let share3 = participant3.get_secret_share().unwrap();
//!
//! assert_eq!(pk3.is_identity().unwrap_u8(), 0u8);
//! assert_eq!(share3.is_zero().unwrap_u8(), 0u8);
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
//! let s1 = <Vec<u8> as Share>::from_field_element(1u8, share1).unwrap();
//! let s2 = <Vec<u8> as Share>::from_field_element(2u8, share2).unwrap();
//! let s3 = <Vec<u8> as Share>::from_field_element(3u8, share3).unwrap();
//!
//! let sk: Scalar = combine_shares(&[s1, s2, s3]).unwrap();
//! let computed_pk = ProjectivePoint::GENERATOR * sk;
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

        for _ in Round::range(Round::Zero, Round::One) {
            let generators = next_round(&mut participants);
            receive(&mut participants, generators);
        }

        // Corrupt bad actor
        participants.remove(BAD_ID - 1);
        for _ in Round::range(Round::Two, Round::Four) {
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

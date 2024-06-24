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
//! use k256::{ProjectivePoint, Scalar};
//! use maplit::btreemap;
//! use std::{
//!     collections::BTreeMap,
//!     num::NonZeroUsize,
//! };
//! use vsss_rs::{Share, combine_shares, elliptic_curve::{Group, PrimeField}};
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

mod consts;
mod data;
mod error;
mod parameters;
mod participant;
mod serdes;
mod traits;
mod utils;

use elliptic_curve::{group::GroupEncoding, Group, PrimeField};
use rand_core::SeedableRng;
use serde::{
    de::{Error as DError, SeqAccess, Visitor},
    ser::{SerializeSeq, SerializeTuple},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
    marker::PhantomData,
    num::NonZeroUsize,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use data::*;
pub use error::*;
pub use parameters::*;
pub use participant::*;
pub use traits::*;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_encrypt::traits::SerdeEncryptSharedKey;
    use std::collections::BTreeMap;
    use vsss_rs::{combine_shares, SequentialParticipantNumberGenerator, Share};

    #[test]
    fn one_corrupted_party_k256() {
        one_corrupted_party::<k256::ProjectivePoint>()
    }

    #[test]
    fn one_corrupted_party_p256() {
        one_corrupted_party::<p256::ProjectivePoint>()
    }

    #[test]
    fn one_corrupted_party_curve25519() {
        one_corrupted_party::<vsss_rs::curve25519::WrappedRistretto>();
        one_corrupted_party::<vsss_rs::curve25519::WrappedEdwards>();
    }

    #[test]
    fn one_corrupted_party_bls12_381() {
        one_corrupted_party::<blsful::inner_types::G1Projective>();
        one_corrupted_party::<blsful::inner_types::G2Projective>();
    }

    fn one_corrupted_party<G: GroupHasher + GroupEncoding + Default>() {
        const THRESHOLD: usize = 2;
        const LIMIT: usize = 4;
        const BAD_ID: usize = 4;

        let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
        let limit = NonZeroUsize::new(LIMIT).unwrap();
        let parameters = Parameters::<G, SequentialParticipantNumberGenerator<G::Scalar>>::new(
            threshold, limit, None, None, None,
        );
        let mut participants = [
            SecretParticipant::<G>::new(NonZeroUsize::new(1).unwrap(), parameters).unwrap(),
            SecretParticipant::<G>::new(NonZeroUsize::new(2).unwrap(), parameters).unwrap(),
            SecretParticipant::<G>::new(NonZeroUsize::new(3).unwrap(), parameters).unwrap(),
            SecretParticipant::<G>::new(NonZeroUsize::new(4).unwrap(), parameters).unwrap(),
        ];

        let mut r1bdata = Vec::with_capacity(LIMIT);
        let mut r1p2pdata = Vec::with_capacity(LIMIT);
        for p in participants.iter_mut() {
            let (broadcast, p2p) = p.round1().expect("Round 1 should work");
            r1bdata.push(broadcast);
            r1p2pdata.push(p2p);
        }
        for p in participants.iter_mut() {
            assert!(p.round1().is_err());
        }

        // Corrupt bad actor
        for i in 0..THRESHOLD {
            r1bdata[BAD_ID - 1].pedersen_commitments[i] = G::identity();
        }

        let mut r2bdata = BTreeMap::new();

        for i in 0..LIMIT {
            let mut bdata = BTreeMap::new();
            let mut p2pdata = BTreeMap::new();

            let my_id = participants[i].get_id();
            for j in 0..LIMIT {
                let pp = &participants[j];
                let id = pp.get_id();
                if my_id == id {
                    continue;
                }
                bdata.insert(id, r1bdata[id - 1].clone());
                p2pdata.insert(id, r1p2pdata[id - 1][&my_id].clone());
            }
            let p = &mut participants[i];
            let res = p.round2(bdata, p2pdata);
            assert!(res.is_ok());
            if my_id == BAD_ID {
                continue;
            }
            r2bdata.insert(my_id, res.unwrap());
        }

        let mut r3bdata = BTreeMap::new();
        for p in participants.iter_mut() {
            if BAD_ID == p.get_id() {
                continue;
            }
            let res = p.round3(&r2bdata);
            assert!(res.is_ok());
            r3bdata.insert(p.get_id(), res.unwrap());
            assert!(p.round3(&r2bdata).is_err());
        }

        let mut r4bdata = BTreeMap::new();
        let mut r4shares = Vec::with_capacity(LIMIT);
        for p in participants.iter_mut() {
            if BAD_ID == p.get_id() {
                continue;
            }
            let res = p.round4(&r3bdata);
            assert!(res.is_ok());
            let bdata = res.unwrap();
            let share = p.get_secret_share().unwrap();
            r4bdata.insert(p.get_id(), bdata);
            r4shares
                .push(<InnerShare as Share>::from_field_element(p.get_id() as u8, share).unwrap());
            assert!(p.round4(&r3bdata).is_err());
        }

        for p in &participants {
            if BAD_ID == p.get_id() {
                continue;
            }
            assert!(p.round5(&r4bdata).is_ok());
        }

        let res = combine_shares::<G::Scalar, u8, InnerShare>(&r4shares);
        assert!(res.is_ok());
        let secret = res.unwrap();

        assert_eq!(r4bdata[&1].public_key, G::generator() * secret);
    }

    #[test]
    fn serialization_k256() {
        serialization_curve::<k256::ProjectivePoint>();
    }

    #[test]
    fn serialization_p256() {
        serialization_curve::<p256::ProjectivePoint>();
    }

    #[test]
    fn serialization_bls12_381_g1() {
        serialization_curve::<blsful::inner_types::G1Projective>();
    }

    #[test]
    fn serialization_bls12_381_g2() {
        serialization_curve::<blsful::inner_types::G2Projective>();
    }

    #[cfg(feature = "curve25519")]
    #[test]
    fn serialization_curve25519() {
        serialization_curve::<vsss_rs::curve25519::WrappedRistretto>();
        serialization_curve::<vsss_rs::curve25519::WrappedEdwards>();
    }

    fn serialization_curve<G: Group + GroupEncoding + Default>() {
        const THRESHOLD: usize = 2;
        const LIMIT: usize = 3;

        let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
        let limit = NonZeroUsize::new(LIMIT).unwrap();
        let parameters = Parameters::<G>::new(threshold, limit);
        let mut participants = [
            SecretParticipant::<G>::new(NonZeroUsize::new(1).unwrap(), parameters).unwrap(),
            SecretParticipant::<G>::new(NonZeroUsize::new(2).unwrap(), parameters).unwrap(),
            SecretParticipant::<G>::new(NonZeroUsize::new(3).unwrap(), parameters).unwrap(),
        ];

        let mut r1bdata = Vec::<Round1BroadcastData<G>>::with_capacity(LIMIT);
        let mut r1pdata = Vec::<BTreeMap<usize, Round1P2PData>>::with_capacity(LIMIT);

        for participant in participants.iter_mut() {
            let (bdata, pdata) = participant.round1().unwrap();

            // text serialize test
            let json = serde_json::to_string(&bdata).unwrap();
            let res = serde_json::from_str::<Round1BroadcastData<G>>(&json);
            assert!(res.is_ok());
            let bdata2 = res.unwrap();
            assert_eq!(bdata.message_generator, bdata.message_generator);
            assert_eq!(bdata.blinder_generator, bdata2.blinder_generator);
            assert_eq!(
                bdata.pedersen_commitments[0],
                bdata2.pedersen_commitments[0]
            );
            assert_eq!(
                bdata.pedersen_commitments[1],
                bdata2.pedersen_commitments[1]
            );

            let json = serde_json::to_string(&pdata).unwrap();
            let res = serde_json::from_str::<BTreeMap<usize, Round1P2PData>>(&json);
            assert!(res.is_ok());
            let pdata2 = res.unwrap();
            assert_eq!(pdata.len(), pdata2.len());
            for (id, val) in &pdata {
                assert!(pdata2.contains_key(id));
                assert_eq!(val.secret_share, pdata2[id].secret_share);
                assert_eq!(val.blind_share, pdata2[id].blind_share);
            }

            // binary serialize test
            let bin = serde_bare::to_vec(&bdata).unwrap();
            let res = serde_bare::from_slice::<Round1BroadcastData<G>>(&bin);
            assert!(res.is_ok());
            let bdata2 = res.unwrap();
            assert_eq!(bdata.message_generator, bdata.message_generator);
            assert_eq!(bdata.blinder_generator, bdata2.blinder_generator);
            assert_eq!(
                bdata.pedersen_commitments[0],
                bdata2.pedersen_commitments[0]
            );
            assert_eq!(
                bdata.pedersen_commitments[1],
                bdata2.pedersen_commitments[1]
            );

            let bin = serde_bare::to_vec(&pdata).unwrap();
            let res = serde_bare::from_slice::<BTreeMap<usize, Round1P2PData>>(&bin);
            assert!(res.is_ok());
            let pdata2 = res.unwrap();
            assert_eq!(pdata.len(), pdata2.len());
            for (id, val) in &pdata {
                assert!(pdata2.contains_key(id));
                assert_eq!(val.secret_share, pdata2[id].secret_share);
                assert_eq!(val.blind_share, pdata2[id].blind_share);
            }

            let shared_key = serde_encrypt::shared_key::SharedKey::new([1u8; 32]);
            let bin = bdata.encrypt(&shared_key).unwrap();
            let res = Round1BroadcastData::<G>::decrypt_owned(&bin, &shared_key);
            assert!(res.is_ok());
            let bdata2 = res.unwrap();
            assert_eq!(bdata.message_generator, bdata.message_generator);
            assert_eq!(bdata.blinder_generator, bdata2.blinder_generator);
            assert_eq!(
                bdata.pedersen_commitments[0],
                bdata2.pedersen_commitments[0]
            );
            assert_eq!(
                bdata.pedersen_commitments[1],
                bdata2.pedersen_commitments[1]
            );

            r1bdata.push(bdata);
            r1pdata.push(pdata);
        }

        let mut r2bdata = BTreeMap::<usize, Round2EchoBroadcastData>::new();
        r2bdata.insert(
            1,
            participants[0]
                .round2(
                    maplit::btreemap! {
                        2 => r1bdata[1].clone(),
                        3 => r1bdata[2].clone(),
                    },
                    maplit::btreemap! {
                        2 => r1pdata[1][&1].clone(),
                        3 => r1pdata[2][&1].clone()
                    },
                )
                .unwrap(),
        );
        r2bdata.insert(
            2,
            participants[1]
                .round2(
                    maplit::btreemap! {
                        1 => r1bdata[0].clone(),
                        3 => r1bdata[2].clone(),
                    },
                    maplit::btreemap! {
                        1 => r1pdata[0][&2].clone(),
                        3 => r1pdata[2][&2].clone(),
                    },
                )
                .unwrap(),
        );
        r2bdata.insert(
            3,
            participants[2]
                .round2(
                    maplit::btreemap! {
                        1 => r1bdata[0].clone(),
                        2 => r1bdata[1].clone(),
                    },
                    maplit::btreemap! {
                        1 => r1pdata[0][&3].clone(),
                        2 => r1pdata[1][&3].clone(),
                    },
                )
                .unwrap(),
        );

        let json = serde_json::to_string(&r2bdata).unwrap();
        let res = serde_json::from_str::<BTreeMap<usize, Round2EchoBroadcastData>>(&json);
        assert!(res.is_ok());
        let r2bdata2 = res.unwrap();
        assert_eq!(
            r2bdata[&1].valid_participant_ids,
            r2bdata2[&1].valid_participant_ids
        );

        let bin = serde_bare::to_vec(&r2bdata).unwrap();
        let res = serde_bare::from_slice::<BTreeMap<usize, Round2EchoBroadcastData>>(&bin);
        assert!(res.is_ok());
        let r2bdata2 = res.unwrap();
        assert_eq!(
            r2bdata[&1].valid_participant_ids,
            r2bdata2[&1].valid_participant_ids
        );

        // We explicitly zeroize the P2P secrets here as we have to assert that it's zeroized.
        // IRL we don't have to manually zeroize it as it will be automatically dropped as we've implemented the ZeroizeOnDrop trait
        for i in 0..3 {
            for j in 1..4 {
                r1pdata[i].get_mut(&j).map(|val| val.zeroize());
                if j != i + 1 {
                    assert!(r1pdata[i].get(&j).unwrap().secret_share.is_empty());
                    assert!(r1pdata[i].get(&j).unwrap().blind_share.is_empty());
                }
            }
        }

        let mut r3bdata = BTreeMap::<usize, Round3BroadcastData<G>>::new();
        r3bdata.insert(1, participants[0].round3(&r2bdata).unwrap());
        r3bdata.insert(2, participants[1].round3(&r2bdata).unwrap());
        r3bdata.insert(3, participants[2].round3(&r2bdata).unwrap());

        let json = serde_json::to_string(&r3bdata).unwrap();
        let res = serde_json::from_str::<BTreeMap<usize, Round3BroadcastData<G>>>(&json);
        assert!(res.is_ok());
        let r3bdata2 = res.unwrap();
        assert_eq!(
            r3bdata.get(&1).unwrap().commitments,
            r3bdata2.get(&1).unwrap().commitments
        );
        assert_eq!(
            r3bdata.get(&2).unwrap().commitments,
            r3bdata2.get(&2).unwrap().commitments
        );
        assert_eq!(
            r3bdata.get(&3).unwrap().commitments,
            r3bdata2.get(&3).unwrap().commitments
        );

        let bin = serde_bare::to_vec(&r3bdata).unwrap();
        let res = serde_bare::from_slice::<BTreeMap<usize, Round3BroadcastData<G>>>(&bin);
        assert!(res.is_ok());
        let r3bdata2 = res.unwrap();
        assert_eq!(
            r3bdata.get(&1).unwrap().commitments,
            r3bdata2.get(&1).unwrap().commitments
        );
        assert_eq!(
            r3bdata.get(&2).unwrap().commitments,
            r3bdata2.get(&2).unwrap().commitments
        );
        assert_eq!(
            r3bdata.get(&3).unwrap().commitments,
            r3bdata2.get(&3).unwrap().commitments
        );

        let mut r4bdata = BTreeMap::<usize, Round4EchoBroadcastData<G>>::new();
        r4bdata.insert(1, participants[0].round4(&r3bdata).unwrap());
        r4bdata.insert(2, participants[1].round4(&r3bdata).unwrap());
        r4bdata.insert(3, participants[2].round4(&r3bdata).unwrap());

        let json = serde_json::to_string(&r4bdata).unwrap();
        let res = serde_json::from_str::<BTreeMap<usize, Round4EchoBroadcastData<G>>>(&json);
        assert!(res.is_ok());
        let r4bdata2 = res.unwrap();
        assert_eq!(
            r4bdata.get(&1).unwrap().public_key,
            r4bdata2.get(&1).unwrap().public_key
        );
        assert_eq!(
            r4bdata.get(&2).unwrap().public_key,
            r4bdata2.get(&2).unwrap().public_key
        );
        assert_eq!(
            r4bdata.get(&3).unwrap().public_key,
            r4bdata2.get(&3).unwrap().public_key
        );

        let bin = serde_bare::to_vec(&r4bdata).unwrap();
        let res = serde_bare::from_slice::<BTreeMap<usize, Round4EchoBroadcastData<G>>>(&bin);
        assert!(res.is_ok());
        let r4bdata2 = res.unwrap();
        assert_eq!(
            r4bdata.get(&1).unwrap().public_key,
            r4bdata2.get(&1).unwrap().public_key
        );
        assert_eq!(
            r4bdata.get(&2).unwrap().public_key,
            r4bdata2.get(&2).unwrap().public_key
        );
        assert_eq!(
            r4bdata.get(&3).unwrap().public_key,
            r4bdata2.get(&3).unwrap().public_key
        );
    }
}

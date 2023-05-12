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
    trivial_numeric_casts
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use rand_core;
pub use vsss_rs;

mod error;
mod parameters;
mod participant;
mod pedersen_result;

use rand_core::SeedableRng;
use serde::{
    de::{Error as DError, SeqAccess, Unexpected, Visitor},
    ser::{SerializeSeq, SerializeTuple},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
    marker::PhantomData,
    num::NonZeroUsize,
};
use uint_zigzag::Uint;
use vsss_rs::elliptic_curve::{group::GroupEncoding, Group, PrimeField};

pub use error::*;
pub use parameters::*;
pub use participant::*;
pub use pedersen_result::*;

/// Valid rounds
#[derive(Copy, Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Round {
    /// First round
    One,
    /// Second round
    Two,
    /// Third round
    Three,
    /// Four round
    Four,
    /// Five round
    Five,
}

impl Display for Round {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::One => write!(f, "1"),
            Self::Two => write!(f, "2"),
            Self::Three => write!(f, "3"),
            Self::Four => write!(f, "4"),
            Self::Five => write!(f, "5"),
        }
    }
}

macro_rules! impl_round_to_int {
    ($ident:ident) => {
        impl From<Round> for $ident {
            fn from(value: Round) -> Self {
                match value {
                    Round::One => 1,
                    Round::Two => 2,
                    Round::Three => 3,
                    Round::Four => 4,
                    Round::Five => 5,
                }
            }
        }
    };
}

impl_round_to_int!(u8);
impl_round_to_int!(u16);
impl_round_to_int!(u32);
impl_round_to_int!(u64);
impl_round_to_int!(usize);

/// Broadcast data from round 1 that should be sent to all other participants
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1BroadcastData<G: Group + GroupEncoding + Default> {
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    message_generator: G,
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    blinder_generator: G,
    #[serde(
        serialize_with = "serialize_g_vec",
        deserialize_with = "deserialize_g_vec"
    )]
    pedersen_commitments: Vec<G>,
}

/// Echo broadcast data from round 2 that should be sent to all valid participants
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2EchoBroadcastData {
    valid_participant_ids: BTreeSet<usize>,
}

/// Broadcast data from round 3 that should be sent to all valid participants
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round3BroadcastData<G: Group + GroupEncoding + Default> {
    #[serde(
        serialize_with = "serialize_g_vec",
        deserialize_with = "deserialize_g_vec"
    )]
    commitments: Vec<G>,
}

/// Echo broadcast data from round 4 that should be sent to all valid participants
#[derive(Copy, Debug, Clone, Serialize, Deserialize)]
pub struct Round4EchoBroadcastData<G: Group + GroupEncoding + Default> {
    /// The computed public key
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    pub public_key: G,
}

/// Peer data from round 1 that should only be sent to a specific secret_participant
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1P2PData {
    secret_share: Vec<u8>,
    blind_share: Vec<u8>,
}

pub(crate) fn serialize_scalar<F: PrimeField, S: Serializer>(
    scalar: &F,
    s: S,
) -> Result<S::Ok, S::Error> {
    let v = scalar.to_repr();
    let vv = v.as_ref();
    if s.is_human_readable() {
        s.serialize_str(&data_encoding::BASE64URL_NOPAD.encode(vv))
    } else {
        let len = vv.len();
        let mut t = s.serialize_tuple(len)?;
        for vi in vv {
            t.serialize_element(vi)?;
        }
        t.end()
    }
}

pub(crate) fn deserialize_scalar<'de, F: PrimeField, D: Deserializer<'de>>(
    d: D,
) -> Result<F, D::Error> {
    struct ScalarVisitor<F: PrimeField> {
        marker: PhantomData<F>,
    }

    impl<'de, F: PrimeField> Visitor<'de> for ScalarVisitor<F> {
        type Value = F;

        fn expecting(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "a byte sequence")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: DError,
        {
            let bytes = data_encoding::BASE64URL_NOPAD
                .decode(v.as_bytes())
                .map_err(|_| DError::invalid_value(Unexpected::Str(v), &self))?;
            let mut repr = F::default().to_repr();
            repr.as_mut().copy_from_slice(bytes.as_slice());
            let sc = F::from_repr(repr);
            if sc.is_some().into() {
                Ok(sc.unwrap())
            } else {
                Err(DError::custom("unable to convert to scalar".to_string()))
            }
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut repr = F::default().to_repr();
            let mut i = 0;
            let len = repr.as_ref().len();
            while let Some(b) = seq.next_element()? {
                repr.as_mut()[i] = b;
                i += 1;
                if i == len {
                    let sc = F::from_repr(repr);
                    if sc.is_some().into() {
                        return Ok(sc.unwrap());
                    }
                }
            }
            Err(DError::custom("unable to convert to scalar".to_string()))
        }
    }

    let vis = ScalarVisitor {
        marker: PhantomData::<F>,
    };
    if d.is_human_readable() {
        d.deserialize_str(vis)
    } else {
        let repr = F::default().to_repr();
        let len = repr.as_ref().len();
        d.deserialize_tuple(len, vis)
    }
}

pub(crate) fn serialize_g<G: Group + GroupEncoding + Default, S: Serializer>(
    g: &G,
    s: S,
) -> Result<S::Ok, S::Error> {
    let v = g.to_bytes();
    let vv = v.as_ref();
    if s.is_human_readable() {
        s.serialize_str(&data_encoding::BASE64URL_NOPAD.encode(vv))
    } else {
        let mut t = s.serialize_tuple(vv.len())?;
        for b in vv {
            t.serialize_element(b)?;
        }
        t.end()
    }
}

pub(crate) fn deserialize_g<'de, G: Group + GroupEncoding + Default, D: Deserializer<'de>>(
    d: D,
) -> Result<G, D::Error> {
    struct GVisitor<G: Group + GroupEncoding + Default> {
        marker: PhantomData<G>,
    }

    impl<'de, G: Group + GroupEncoding + Default> Visitor<'de> for GVisitor<G> {
        type Value = G;

        fn expecting(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "a base64 encoded string or tuple of bytes")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: DError,
        {
            let mut repr = G::Repr::default();
            let bytes = data_encoding::BASE64URL_NOPAD
                .decode(v.as_bytes())
                .map_err(|_| DError::invalid_value(Unexpected::Str(v), &self))?;
            repr.as_mut().copy_from_slice(bytes.as_slice());
            let res = G::from_bytes(&repr);
            if res.is_some().unwrap_u8() == 1u8 {
                Ok(res.unwrap())
            } else {
                Err(DError::invalid_value(Unexpected::Str(v), &self))
            }
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut repr = G::Repr::default();
            let input = repr.as_mut();
            for i in 0..input.len() {
                input[i] = seq
                    .next_element()?
                    .ok_or_else(|| DError::invalid_length(input.len(), &self))?;
            }
            let res = G::from_bytes(&repr);
            if res.is_some().unwrap_u8() == 1u8 {
                Ok(res.unwrap())
            } else {
                Err(DError::invalid_value(Unexpected::Seq, &self))
            }
        }
    }

    let visitor = GVisitor {
        marker: PhantomData,
    };
    if d.is_human_readable() {
        d.deserialize_str(visitor)
    } else {
        let repr = G::Repr::default();
        d.deserialize_tuple(repr.as_ref().len(), visitor)
    }
}

pub(crate) fn serialize_g_vec<G: Group + GroupEncoding + Default, S: Serializer>(
    g: &Vec<G>,
    s: S,
) -> Result<S::Ok, S::Error> {
    let v = g.iter().map(|p| p.to_bytes()).collect::<Vec<G::Repr>>();
    if s.is_human_readable() {
        let vv = v
            .iter()
            .map(|b| data_encoding::BASE64URL_NOPAD.encode(b.as_ref()))
            .collect::<Vec<String>>();
        vv.serialize(s)
    } else {
        let size = G::Repr::default().as_ref().len();
        let uint = uint_zigzag::Uint::from(g.len());
        let length_bytes = uint.to_vec();
        let mut seq = s.serialize_seq(Some(length_bytes.len() + size * g.len()))?;
        for b in &length_bytes {
            seq.serialize_element(b)?;
        }
        for c in &v {
            for b in c.as_ref() {
                seq.serialize_element(b)?;
            }
        }
        seq.end()
    }
}

pub(crate) fn deserialize_g_vec<'de, G: Group + GroupEncoding + Default, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<G>, D::Error> {
    struct NonReadableVisitor<G: Group + GroupEncoding + Default> {
        marker: PhantomData<G>,
    }

    impl<'de, G: Group + GroupEncoding + Default> Visitor<'de> for NonReadableVisitor<G> {
        type Value = Vec<G>;

        fn expecting(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "an array of bytes")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut buffer = [0u8; Uint::MAX_BYTES];
            let mut i = 0;
            while let Some(b) = seq.next_element()? {
                buffer[i] = b;
                if i == Uint::MAX_BYTES {
                    break;
                }
                i += 1;
            }
            let bytes_cnt_size = Uint::peek(&buffer)
                .ok_or_else(|| DError::invalid_value(Unexpected::Bytes(&buffer), &self))?;
            let points = Uint::try_from(&buffer[..bytes_cnt_size])
                .map_err(|_| DError::invalid_value(Unexpected::Bytes(&buffer), &self))?;

            i = Uint::MAX_BYTES - bytes_cnt_size;
            let mut repr = G::Repr::default();
            {
                let r = repr.as_mut();
                r[..i].copy_from_slice(&buffer[bytes_cnt_size..]);
            }
            let repr_len = repr.as_ref().len();
            let mut out = Vec::with_capacity(points.0 as usize);
            while let Some(b) = seq.next_element()? {
                repr.as_mut()[i] = b;
                if i == repr_len {
                    i = 0;
                    let pt = G::from_bytes(&repr);
                    if pt.is_none().unwrap_u8() == 1u8 {
                        return Err(DError::invalid_value(Unexpected::Bytes(&buffer), &self));
                    }
                    out.push(pt.unwrap());
                    if out.len() == points.0 as usize {
                        break;
                    }
                }
                i += 1;
            }
            if out.len() != points.0 as usize {
                return Err(DError::invalid_length(out.len(), &self));
            }
            Ok(out)
        }
    }

    if d.is_human_readable() {
        let s = Vec::<String>::deserialize(d)?;
        let mut out = Vec::with_capacity(s.len());
        for si in &s {
            let mut repr = G::Repr::default();
            let bytes = data_encoding::BASE64URL_NOPAD
                .decode(si.as_bytes())
                .map_err(|_| DError::custom("unable to decode string to bytes".to_string()))?;
            repr.as_mut().copy_from_slice(bytes.as_slice());
            let pt = G::from_bytes(&repr);
            if pt.is_none().unwrap_u8() == 1u8 {
                return Err(DError::custom(
                    "unable to convert string to point".to_string(),
                ));
            }
            out.push(pt.unwrap());
        }
        Ok(out)
    } else {
        d.deserialize_seq(NonReadableVisitor {
            marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vsss_rs::{combine_shares, Share};

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
        one_corrupted_party::<bls12_381_plus::G1Projective>();
        one_corrupted_party::<bls12_381_plus::G2Projective>();
    }

    fn one_corrupted_party<G: Group + GroupEncoding + Default>() {
        const THRESHOLD: usize = 2;
        const LIMIT: usize = 4;
        const BAD_ID: usize = 4;

        let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
        let limit = NonZeroUsize::new(LIMIT).unwrap();
        let parameters = Parameters::<G>::new(threshold, limit);
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
            r4shares.push(<Vec<u8> as Share>::from_field_element(p.get_id() as u8, share).unwrap());
            assert!(p.round4(&r3bdata).is_err());
        }

        for p in &participants {
            if BAD_ID == p.get_id() {
                continue;
            }
            assert!(p.round5(&r4bdata).is_ok());
        }

        let res = combine_shares::<G::Scalar, u8, Vec<u8>>(&r4shares);
        assert!(res.is_ok());
        let secret = res.unwrap();

        assert_eq!(r4bdata[&1].public_key, G::generator() * secret);
    }
}

pub extern crate elliptic_curve;
pub extern crate rand_core;
pub extern crate vsss_rs;

mod error;
mod round1;
mod round2;
mod round3;
mod round4;
mod round5;

use elliptic_curve::group::{Group, GroupEncoding};
use elliptic_curve::{Field, PrimeField};
use rand_core::SeedableRng;
use serde::de::{Error as DError, SeqAccess, Unexpected, Visitor};
use serde::ser::{SerializeSeq, SerializeTuple};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Formatter;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use uint_zigzag::Uint;
use vsss_rs::{FeldmanVerifier, Pedersen, PedersenResult, PedersenVerifier, Share};

pub use error::*;

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Parameters<G: Group + GroupEncoding + Default> {
    threshold: usize,
    limit: usize,
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    message_generator: G,
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    blinder_generator: G,
}

impl<G: Group + GroupEncoding + Default> Default for Parameters<G> {
    fn default() -> Self {
        Self {
            threshold: 0,
            limit: 0,
            message_generator: G::identity(),
            blinder_generator: G::identity(),
        }
    }
}

impl<G: Group + GroupEncoding + Default> Parameters<G> {
    /// Create regular parameters with the message_generator as the default generator
    /// and a random blinder_generator
    pub fn new(threshold: NonZeroUsize, limit: NonZeroUsize) -> Self {
        let message_generator = G::generator();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&message_generator.to_bytes().as_ref()[0..32]);
        let rng = rand_chacha::ChaChaRng::from_seed(seed);
        Self {
            threshold: threshold.get(),
            limit: limit.get(),
            message_generator: G::generator(),
            blinder_generator: G::random(rng),
        }
    }

    /// Use the provided parameters
    pub fn with_generators(
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
        message_generator: G,
        blinder_generator: G,
    ) -> Self {
        Self {
            threshold: threshold.get(),
            limit: limit.get(),
            message_generator,
            blinder_generator,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Participant<G: Group + GroupEncoding + Default> {
    id: usize,
    #[serde(bound(serialize = "PedersenResult<G::Scalar, G>: Serialize"))]
    #[serde(bound(deserialize = "PedersenResult<G::Scalar, G>: Deserialize<'de>"))]
    components: PedersenResult<G::Scalar, G>,
    threshold: usize,
    limit: usize,
    round: Round,
    #[serde(
        serialize_with = "serialize_scalar",
        deserialize_with = "deserialize_scalar"
    )]
    secret_share: G::Scalar,
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    public_key: G,
    round1_broadcast_data: BTreeMap<usize, Round1BroadcastData<G>>,
    round1_p2p_data: BTreeMap<usize, Round1P2PData>,
    valid_participant_ids: BTreeSet<usize>,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum Round {
    One,
    Two,
    Three,
    Four,
    Five,
}

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct Round2EchoBroadcastData {
    valid_participant_ids: BTreeSet<usize>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round3BroadcastData<G: Group + GroupEncoding + Default> {
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    message_generator: G,
    #[serde(
        serialize_with = "serialize_g_vec",
        deserialize_with = "deserialize_g_vec"
    )]
    commitments: Vec<G>,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Round4EchoBroadcastData<G: Group + GroupEncoding + Default> {
    #[serde(serialize_with = "serialize_g", deserialize_with = "deserialize_g")]
    pub public_key: G,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round1P2PData {
    #[serde(serialize_with = "serialize_share", deserialize_with = "deserialize_share")]
    secret_share: Share,
    #[serde(serialize_with = "serialize_share", deserialize_with = "deserialize_share")]
    blind_share: Share,
}

impl<G: Group + GroupEncoding + Default> Participant<G> {
    /// Create a new participant to generate a new key share
    pub fn new(id: NonZeroUsize, parameters: Parameters<G>) -> DkgResult<Self> {
        let mut rng = rand_core::OsRng;
        let secret = G::Scalar::random(&mut rng);
        let blinder = G::Scalar::random(&mut rng);
        let pedersen = Pedersen {
            t: parameters.threshold,
            n: parameters.limit,
        };
        let components = pedersen.split_secret(
            secret,
            Some(blinder),
            Some(parameters.message_generator),
            Some(parameters.blinder_generator),
            &mut rng,
        )?;

        if (components.verifier.generator.is_identity()
            | components.verifier.feldman_verifier.generator.is_identity())
        .unwrap_u8()
            == 1u8
        {
            return Err(Error::InitializationError("Invalid generators".to_string()));
        }
        if components
            .verifier
            .commitments
            .iter()
            .any(|c| c.is_identity().unwrap_u8() == 1u8)
            || components
                .verifier
                .feldman_verifier
                .commitments
                .iter()
                .any(|c| c.is_identity().unwrap_u8() == 1u8)
        {
            return Err(Error::InitializationError(
                "Invalid commitments".to_string(),
            ));
        }
        if components.secret_shares.iter().any(|s| s.is_zero())
            || components.blind_shares.iter().any(|s| s.is_zero())
        {
            return Err(Error::InitializationError("Invalid shares".to_string()));
        }
        Ok(Self {
            id: id.get(),
            components,
            threshold: parameters.threshold,
            limit: parameters.limit,
            round: Round::One,
            round1_broadcast_data: BTreeMap::new(),
            round1_p2p_data: BTreeMap::new(),
            secret_share: G::Scalar::zero(),
            public_key: G::identity(),
            valid_participant_ids: BTreeSet::new(),
        })
    }

    /// The identifier associated with this participant
    pub fn get_id(&self) -> usize {
        self.id
    }

    /// Computed secret share.
    /// This value is useless until all rounds have been run
    pub fn get_secret_share(&self) -> G::Scalar {
        self.secret_share
    }

    /// Computed public key
    /// This value is useless until all rounds have been run
    pub fn get_public_key(&self) -> G {
        self.public_key
    }
}

fn serialize_share<S: Serializer>(share: &Share, s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        s.serialize_str(&base64_url::encode(share.as_ref()))
    } else {
        share.serialize(s)
    }
}

fn deserialize_share<'de, D: Deserializer<'de>>(d: D) -> Result<Share, D::Error> {
    struct ShareVisitor;

    impl<'de> Visitor<'de> for ShareVisitor {
        type Value = Share;

        fn expecting(&self, f: &mut Formatter) -> std::fmt::Result {
            write!(f, "a base64 encoded string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: DError {
            let bytes = base64_url::decode(v)
                .map_err(|_| DError::invalid_value(Unexpected::Str(v), &self))?;
            Ok(Share(bytes))
        }
    }

    if d.is_human_readable() {
        d.deserialize_str(ShareVisitor)
    } else {
        Share::deserialize(d)
    }
}

fn serialize_scalar<F: PrimeField, S: Serializer>(scalar: &F, s: S) -> Result<S::Ok, S::Error> {
    let v = scalar.to_repr();
    let vv = v.as_ref();
    if s.is_human_readable() {
        s.serialize_str(&base64_url::encode(vv))
    } else {
        let len = vv.len();
        let mut t = s.serialize_tuple(len)?;
        for vi in vv {
            t.serialize_element(vi)?;
        }
        t.end()
    }
}

fn deserialize_scalar<'de, F: PrimeField, D: Deserializer<'de>>(d: D) -> Result<F, D::Error> {
    struct ScalarVisitor<F: PrimeField> {
        marker: PhantomData<F>,
    }

    impl<'de, F: PrimeField> Visitor<'de> for ScalarVisitor<F> {
        type Value = F;

        fn expecting(&self, f: &mut Formatter) -> std::fmt::Result {
            write!(f, "a byte sequence")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: DError,
        {
            let bytes = base64_url::decode(v)
                .map_err(|_| DError::invalid_value(Unexpected::Str(v), &self))?;
            let mut repr = F::default().to_repr();
            repr.as_mut().copy_from_slice(bytes.as_slice());
            let sc = F::from_repr(repr);
            if sc.is_some().unwrap_u8() == 1u8 {
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
                    if sc.is_some().unwrap_u8() == 1u8 {
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

fn serialize_g<G: Group + GroupEncoding + Default, S: Serializer>(
    g: &G,
    s: S,
) -> Result<S::Ok, S::Error> {
    let v = g.to_bytes();
    let vv = v.as_ref();
    if s.is_human_readable() {
        s.serialize_str(&base64_url::encode(vv))
    } else {
        let mut t = s.serialize_tuple(vv.len())?;
        for b in vv {
            t.serialize_element(b)?;
        }
        t.end()
    }
}

fn deserialize_g<'de, G: Group + GroupEncoding + Default, D: Deserializer<'de>>(
    d: D,
) -> Result<G, D::Error> {
    struct GVisitor<G: Group + GroupEncoding + Default> {
        marker: PhantomData<G>,
    }

    impl<'de, G: Group + GroupEncoding + Default> Visitor<'de> for GVisitor<G> {
        type Value = G;

        fn expecting(&self, f: &mut Formatter) -> std::fmt::Result {
            write!(f, "a base64 encoded string or tuple of bytes")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: DError,
        {
            let mut repr = G::Repr::default();
            let bytes = base64_url::decode(v)
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

fn serialize_g_vec<G: Group + GroupEncoding + Default, S: Serializer>(
    g: &Vec<G>,
    s: S,
) -> Result<S::Ok, S::Error> {
    let v = g.iter().map(|p| p.to_bytes()).collect::<Vec<G::Repr>>();
    if s.is_human_readable() {
        let vv = v
            .iter()
            .map(|b| base64_url::encode(b.as_ref()))
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

fn deserialize_g_vec<'de, G: Group + GroupEncoding + Default, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<G>, D::Error> {
    struct NonReadableVisitor<G: Group + GroupEncoding + Default> {
        marker: PhantomData<G>,
    }

    impl<'de, G: Group + GroupEncoding + Default> Visitor<'de> for NonReadableVisitor<G> {
        type Value = Vec<G>;

        fn expecting(&self, f: &mut Formatter) -> std::fmt::Result {
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
            let bytes = base64_url::decode(si)
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
    use vsss_rs::{Shamir, Share};

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
            Participant::<G>::new(NonZeroUsize::new(1).unwrap(), parameters).unwrap(),
            Participant::<G>::new(NonZeroUsize::new(2).unwrap(), parameters).unwrap(),
            Participant::<G>::new(NonZeroUsize::new(3).unwrap(), parameters).unwrap(),
            Participant::<G>::new(NonZeroUsize::new(4).unwrap(), parameters).unwrap(),
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
            let (bdata, share) = res.unwrap();
            r4bdata.insert(p.get_id(), bdata);
            let mut pshare = share.to_repr().as_ref().to_vec();
            pshare.insert(0, p.get_id() as u8);
            r4shares.push(Share(pshare));
            assert!(p.round4(&r3bdata).is_err());
        }

        for p in &participants {
            if BAD_ID == p.get_id() {
                continue;
            }
            assert!(p.round5(&r4bdata).is_ok());
        }

        let res = Shamir { t: THRESHOLD, n: LIMIT }.combine_shares::<G::Scalar>(&r4shares);
        assert!(res.is_ok());
        let secret = res.unwrap();

        assert_eq!(r4bdata[&1].public_key, G::generator() * secret);
    }
}
use crate::serdes::*;
use crate::{GroupHasher, SumOfProducts};
use blsful::inner_types::GroupEncoding;
use elliptic_curve::{Field, PrimeField};
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

/// Valid rounds
#[derive(Copy, Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Round {
    /// Zero round
    Zero,
    /// First round
    One,
    /// Second round
    Two,
    /// Third round
    Three,
    /// Fourth round
    Four,
    /// Fifth round
    Five,
}

impl Display for Round {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => write!(f, "0"),
            Self::One => write!(f, "1"),
            Self::Two => write!(f, "2"),
            Self::Three => write!(f, "3"),
            Self::Four => write!(f, "4"),
            Self::Five => write!(f, "5"),
        }
    }
}

macro_rules! impl_round_to_int {
    ($($ident:ident),+$(,)*) => {
        $(
            impl From<Round> for $ident {
                fn from(value: Round) -> Self {
                    match value {
                        Round::Zero => 0,
                        Round::One => 1,
                        Round::Two => 2,
                        Round::Three => 3,
                        Round::Four => 4,
                        Round::Five => 5,
                    }
                }
            }

            impl TryFrom<$ident> for Round {
                type Error = String;

                fn try_from(value: $ident) -> Result<Self, Self::Error> {
                    match value {
                        0 => Ok(Round::Zero),
                        1 => Ok(Round::One),
                        2 => Ok(Round::Two),
                        3 => Ok(Round::Three),
                        4 => Ok(Round::Four),
                        5 => Ok(Round::Five),
                        _ => Err(format!("Invalid round: {}", value)),
                    }
                }
            }
        )+
    };
}

impl_round_to_int!(u8, u16, u32, u128, usize);

/// The participant type
#[derive(Debug, Copy, Clone, Default, Deserialize, Serialize)]
pub enum ParticipantType {
    /// Secret participant
    #[default]
    Secret,
    /// Refresh participant
    Refresh,
}

macro_rules! impl_participant_to_int {
    ($($ident:ident),+$(,)*) => {
        $(
            impl From<ParticipantType> for $ident {
                fn from(value: ParticipantType) -> Self {
                    match value {
                        ParticipantType::Secret => 1,
                        ParticipantType::Refresh => 2,
                    }
                }
            }

            impl TryFrom<$ident> for ParticipantType {
                type Error = String;

                fn try_from(value: $ident) -> Result<Self, Self::Error> {
                    match value {
                        1 => Ok(ParticipantType::Secret),
                        2 => Ok(ParticipantType::Refresh),
                        _ => Err(format!("Invalid participant type: {}", value)),
                    }
                }
            }
        )+
    };
}

impl_participant_to_int!(u8, u16, u32, u128, usize);

/// The round output generator that callers use to get the data to send to
/// other participants. This handles both broadcast and peer 2 peer data.
#[derive(Debug, Clone)]
pub enum RoundOutputGenerator<G: GroupHasher + SumOfProducts + GroupEncoding + Default> {
    /// Round 0 output generator
    Round0(Round0OutputGenerator<G>),
    /// Round 1 output generator
    Round1(Round1OutputGenerator<G>),
    /// Round 2 output generator
    Round2(Round2OutputGenerator<G>),
    /// Round 3 output generator
    Round3(Round3OutputGenerator<G>),
    /// Round 4 output generator
    Round4(Round4OutputGenerator<G>),
    /// The public key
    Round5(Round4OutputGenerator<G>),
}

impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default> RoundOutputGenerator<G> {
    /// Iterate over the data to send to other participants
    /// The output is a triplet that is the caller sends the data to participant
    /// at ordinal index with id.
    pub fn iter(&self) -> Box<dyn Iterator<Item = (usize, G::Scalar, Vec<u8>)> + '_> {
        match self {
            Self::Round0(data) => {
                let round0_output_data: Round0Data<G> = Round0Data {
                    sender_ordinal: data.sender_ordinal,
                    sender_id: data.sender_id,
                    sender_type: data.sender_type,
                    pedersen_commitment_hash: data.pedersen_commitment_hash,
                    feldman_commitment_hash: data.feldman_commitment_hash,
                };
                let mut output =
                    postcard::to_stdvec(&round0_output_data).expect("to serialize into a bytes");
                output.insert(0, Round::Zero as u8);
                Box::new(
                    data.participant_ids
                        .iter()
                        .map(move |(index, id)| (*index, *id, output.clone())),
                )
            }
            Self::Round1(data) => {
                let mut round1_output_data: Round1Data<G> = Round1Data {
                    sender_ordinal: data.sender_ordinal,
                    sender_id: data.sender_id,
                    message_generator: data.message_generator,
                    blinder_generator: data.blinder_generator,
                    pedersen_commitments: data.pedersen_commitments.clone(),
                    secret_share: G::Scalar::ZERO,
                    blind_share: G::Scalar::ZERO,
                };
                Box::new(data.participant_ids.iter().map(move |(index, id)| {
                    round1_output_data.secret_share = data.secret_share[index];
                    round1_output_data.blind_share = data.blind_share[index];
                    let mut output = postcard::to_stdvec(&round1_output_data)
                        .expect("to serialize into a bytes");
                    output.insert(0, Round::One as u8);
                    (*index, *id, output)
                }))
            }
            Self::Round2(data) => {
                let round2_output_data: Round2Data<G> = Round2Data {
                    sender_ordinal: data.sender_ordinal,
                    sender_id: data.sender_id,
                    valid_participant_ids: data.valid_participant_ids.clone(),
                };
                let mut output =
                    postcard::to_stdvec(&round2_output_data).expect("to serialize into a bytes");
                output.insert(0, Round::Two as u8);
                Box::new(
                    data.participant_ids
                        .iter()
                        .map(move |(index, id)| (*index, *id, output.clone())),
                )
            }
            Self::Round3(data) => {
                let round3_output_data: Round3Data<G> = Round3Data {
                    sender_ordinal: data.sender_ordinal,
                    sender_id: data.sender_id,
                    feldman_commitments: data.feldman_commitments.clone(),
                };
                let mut output =
                    postcard::to_stdvec(&round3_output_data).expect("to serialize into a bytes");
                output.insert(0, Round::Three as u8);
                Box::new(
                    data.participant_ids
                        .iter()
                        .map(move |(index, id)| (*index, *id, output.clone())),
                )
            }
            Self::Round4(data) => {
                let round4_output_data: Round4Data<G> = Round4Data {
                    sender_ordinal: data.sender_ordinal,
                    sender_id: data.sender_id,
                    transcript_hash: data.transcript_hash,
                    public_key: data.public_key,
                };
                let mut output =
                    postcard::to_stdvec(&round4_output_data).expect("to serialize into a bytes");
                output.insert(0, Round::Four as u8);
                Box::new(
                    data.participant_ids
                        .iter()
                        .map(move |(index, id)| (*index, *id, output.clone())),
                )
            }
            Self::Round5(data) => {
                let mut output = data.public_key.to_bytes().as_ref().to_vec();
                output.insert(0, Round::Five as u8);
                Box::new(
                    data.participant_ids
                        .iter()
                        .map(move |(index, id)| (*index, *id, output.clone())),
                )
            }
        }
    }
}

/// The output generator for round 0
#[derive(Debug, Clone)]
pub struct Round0OutputGenerator<G: GroupHasher + SumOfProducts + GroupEncoding + Default> {
    /// The participant IDs to send to
    pub(crate) participant_ids: BTreeMap<usize, G::Scalar>,
    /// The sender's participant type
    pub(crate) sender_type: ParticipantType,
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    pub(crate) sender_id: G::Scalar,
    /// The commitment to the pedersen verifier set
    pub(crate) pedersen_commitment_hash: [u8; 32],
    /// The commitment to the feldman verifier set
    pub(crate) feldman_commitment_hash: [u8; 32],
}

/// The output generator for round 1
#[derive(Debug, Clone)]
pub struct Round1OutputGenerator<G: GroupHasher + SumOfProducts + GroupEncoding + Default> {
    /// The participant IDs to send to
    pub(crate) participant_ids: BTreeMap<usize, G::Scalar>,
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    pub(crate) sender_id: G::Scalar,
    /// The broadcast data
    pub(crate) message_generator: G,
    /// The broadcast data
    pub(crate) blinder_generator: G,
    /// The broadcast data
    pub(crate) pedersen_commitments: Vec<G>,
    /// The peer 2 peer data based on the participant ordinal index
    pub(crate) secret_share: BTreeMap<usize, G::Scalar>,
    /// The peer 2 peer data based on the participant ordinal index
    pub(crate) blind_share: BTreeMap<usize, G::Scalar>,
}

/// The output generator for round 2
#[derive(Debug, Clone)]
pub struct Round2OutputGenerator<G: GroupHasher + SumOfProducts + GroupEncoding + Default> {
    /// The participant IDs to send to
    pub(crate) participant_ids: BTreeMap<usize, G::Scalar>,
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    pub(crate) sender_id: G::Scalar,
    /// The list of remaining valid participant IDs
    pub(crate) valid_participant_ids: BTreeMap<usize, G::Scalar>,
}

/// The output generator for round 3
#[derive(Debug, Clone)]
pub struct Round3OutputGenerator<G: GroupHasher + GroupEncoding + Default> {
    /// The participant IDs to send to
    pub(crate) participant_ids: BTreeMap<usize, G::Scalar>,
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    pub(crate) sender_id: G::Scalar,
    /// The feldman commitments
    pub(crate) feldman_commitments: Vec<G>,
}

/// The output generator for round 4
#[derive(Debug, Clone)]
pub struct Round4OutputGenerator<G: GroupHasher + GroupEncoding + Default> {
    /// The participant IDs to send to
    pub(crate) participant_ids: BTreeMap<usize, G::Scalar>,
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    pub(crate) sender_id: G::Scalar,
    /// The transcript hash of all messages received
    pub(crate) transcript_hash: [u8; 32],
    /// The computed public key
    pub(crate) public_key: G,
}

/// Broadcast data for Round 0
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Round0Data<G: GroupHasher + SumOfProducts + GroupEncoding + Default> {
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    #[serde(with = "prime_field")]
    pub(crate) sender_id: G::Scalar,
    /// The sender's participant type
    pub(crate) sender_type: ParticipantType,
    /// A commitment to the pedersen verifier set
    /// This prevents rogue key attacks later in the protocol
    pub(crate) pedersen_commitment_hash: [u8; 32],
    /// A commitment to the feldman verifier set
    pub(crate) feldman_commitment_hash: [u8; 32],
}

#[cfg(test)]
impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    serde_encrypt::traits::SerdeEncryptSharedKey for Round0Data<G>
{
    type S = serde_encrypt::serialize::impls::BincodeSerializer<Self>;
}

impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default> Round0Data<G> {
    /// Add the payload to the transcript
    pub fn add_to_transcript(&self, transcript: &mut Transcript) {
        transcript.append_u64(b"sender ordinal", self.sender_ordinal as u64);
        transcript.append_message(b"sender id", self.sender_id.to_repr().as_ref());
        transcript.append_u64(b"sender type", self.sender_type as u64);
        transcript.append_message(b"pedersen commitment hash", &self.pedersen_commitment_hash);
        transcript.append_message(b"feldman commitment hash", &self.feldman_commitment_hash);
    }
}

/// Broadcast data from round 1 that should be sent to all other participants
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Data<G: GroupHasher + SumOfProducts + GroupEncoding + Default> {
    /// The sender's ordinal index
    pub sender_ordinal: usize,
    /// The sender's ID
    #[serde(with = "prime_field")]
    pub sender_id: G::Scalar,
    /// The broadcast data
    #[serde(with = "group")]
    pub message_generator: G,
    /// The broadcast data
    #[serde(with = "group")]
    pub blinder_generator: G,
    #[serde(with = "group_vec")]
    /// The broadcast data
    pub pedersen_commitments: Vec<G>,
    #[serde(with = "prime_field")]
    /// The peer 2 peer data
    pub secret_share: G::Scalar,
    /// The peer 2 peer data
    #[serde(with = "prime_field")]
    pub blind_share: G::Scalar,
}

#[cfg(test)]
impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    serde_encrypt::traits::SerdeEncryptSharedKey for Round1Data<G>
{
    type S = serde_encrypt::serialize::impls::BincodeSerializer<Self>;
}

impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default> Round1Data<G> {
    /// Add the payload to the transcript
    pub fn add_to_transcript(&self, transcript: &mut Transcript) {
        transcript.append_u64(b"sender ordinal", self.sender_ordinal as u64);
        transcript.append_message(b"sender id", self.sender_id.to_repr().as_ref());
        transcript.append_message(
            b"message generator",
            self.message_generator.to_bytes().as_ref(),
        );
        transcript.append_message(
            b"blinder generator",
            self.blinder_generator.to_bytes().as_ref(),
        );
        for (i, commitment) in self.pedersen_commitments.iter().enumerate() {
            transcript.append_u64(b"pedersen commitment_index", i as u64);
            transcript.append_message(b"pedersen commitment_value", commitment.to_bytes().as_ref());
        }
    }
}

/// Echo broadcast data from round 2 that should be sent to all valid participants
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Data<G: GroupHasher + SumOfProducts + GroupEncoding + Default> {
    /// The sender's ordinal index
    pub sender_ordinal: usize,
    /// The sender's ID
    #[serde(with = "prime_field")]
    pub sender_id: G::Scalar,
    /// The list of remaining valid participant IDs
    #[serde(with = "prime_field_map")]
    pub valid_participant_ids: BTreeMap<usize, G::Scalar>,
}

#[cfg(test)]
impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    serde_encrypt::traits::SerdeEncryptSharedKey for Round2Data<G>
{
    type S = serde_encrypt::serialize::impls::BincodeSerializer<Self>;
}

impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default> Round2Data<G> {
    /// Add the payload to the transcript
    pub fn add_to_transcript(&self, transcript: &mut Transcript) {
        transcript.append_u64(b"sender ordinal", self.sender_ordinal as u64);
        transcript.append_message(b"sender id", self.sender_id.to_repr().as_ref());
        for (ordinal, id) in &self.valid_participant_ids {
            transcript.append_u64(b"valid participant ordinal", *ordinal as u64);
            transcript.append_message(b"valid participant id", id.to_repr().as_ref());
        }
    }
}

/// Broadcast data from round 3 that should be sent to all valid participants
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round3Data<G: GroupHasher + GroupEncoding + Default> {
    /// The sender's ordinal index
    pub sender_ordinal: usize,
    /// The sender's ID
    #[serde(with = "prime_field")]
    pub sender_id: G::Scalar,
    /// The feldman commitments
    #[serde(with = "group_vec")]
    pub feldman_commitments: Vec<G>,
}

#[cfg(test)]
impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    serde_encrypt::traits::SerdeEncryptSharedKey for Round3Data<G>
{
    type S = serde_encrypt::serialize::impls::BincodeSerializer<Self>;
}

impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default> Round3Data<G> {
    /// Add the payload to the transcript
    pub fn add_to_transcript(&self, transcript: &mut Transcript) {
        transcript.append_u64(b"sender ordinal", self.sender_ordinal as u64);
        transcript.append_message(b"sender id", self.sender_id.to_repr().as_ref());
        for (i, commitment) in self.feldman_commitments.iter().enumerate() {
            transcript.append_u64(b"feldman commitment_index", i as u64);
            transcript.append_message(b"feldman commitment_value", commitment.to_bytes().as_ref());
        }
    }
}

/// Echo broadcast data from round 4 that should be sent to all valid participants
#[derive(Copy, Debug, Clone, Serialize, Deserialize)]
pub struct Round4Data<G: GroupHasher + SumOfProducts + GroupEncoding + Default> {
    /// The sender's ordinal index
    pub sender_ordinal: usize,
    /// The sender's ID
    #[serde(with = "prime_field")]
    pub sender_id: G::Scalar,
    /// The transcript hash of all messages received
    pub transcript_hash: [u8; 32],
    /// The computed public key
    #[serde(with = "group")]
    pub public_key: G,
}

#[cfg(test)]
impl<G: GroupHasher + SumOfProducts + GroupEncoding + Default>
    serde_encrypt::traits::SerdeEncryptSharedKey for Round4Data<G>
{
    type S = serde_encrypt::serialize::impls::BincodeSerializer<Self>;
}

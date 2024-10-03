use crate::Round;
use serde::{Deserialize, Serialize};
use thiserror::Error as DError;

/// Errors produced by the gennaro DKG
#[derive(DError, Debug)]
pub enum Error {
    /// Format errors
    #[error("fmt error")]
    FmtError(#[from] std::fmt::Error),
    /// Io errors
    #[error("io error")]
    IoError(#[from] std::io::Error),
    /// Verifiable secret sharing scheme errors
    #[error("vsss error")]
    VsssError(vsss_rs::Error),
    /// Postcard errors
    #[error("Postcard error: {0}")]
    PostcardError(#[from] postcard::Error),
    /// Errors during secret_participant initialization
    #[error("error during secret_participant creation: {0}")]
    InitializationError(String),
    /// Errors using rounds
    #[error("round {0} invalid input: `{1}`")]
    RoundError(Round, String),
}

impl From<vsss_rs::Error> for Error {
    fn from(value: vsss_rs::Error) -> Self {
        Self::VsssError(value)
    }
}

/// Dkg results
pub type DkgResult<T> = anyhow::Result<T, Error>;

/// Detailed errors to describe problems that occurred with specific participants
#[derive(DError, Debug, Deserialize, Serialize)]
pub enum ParticipantError {
    /// Round 2 - didn't receive any p2p data from secret_participant
    #[error("secret_participant {0} has broadcast data but no peer-to-peer data")]
    MissingP2PData(usize),
    /// Round 2 - didn't receive any broadcast data from secret_participant
    #[error("secret_participant {0} has peer-to-peer data but no broadcast data")]
    MissingBroadcastData(usize),
    /// Participant is using different parameters than expected
    #[error("secret_participant {0} is using the different parameters than expected")]
    MismatchedParameters(usize),
    /// Participant has identity elements for pedersen commitments
    #[error("secret_participant {0} has identity element pedersen commitments")]
    IdentityElementPedersenCommitments(usize),
    /// Participant has zero value shares
    #[error("secret_participant {0} has zero value shares")]
    ZeroValueShares(usize),
    /// Participant's shares do not verify with the given commitments
    #[error("secret_participant {0} has shares that do not verify with the given commitments")]
    NoVerifyShares(usize),
    /// Participant's shares are not valid field elements
    #[error("secret_participant {0} has shares that are not in the field")]
    BadFormatShare(usize),
    /// Received data from a secret_participant not in the valid set
    #[error("broadcast data for secret_participant {0} is not expected")]
    UnexpectedBroadcast(usize),
    /// Received data from a secret_participant in the valid set but has not peer-to-peer data from round 1
    #[error("secret_participant {0} is missing peer-to-peer data from round 1")]
    MissingP2PDataRound1(usize),
    /// Received data from a secret_participant in the valid set but has not broadcast data from round 1
    #[error("secret_participant {0} is missing broadcast data from round 1")]
    MissingBroadcastDataRound1(usize),
    /// Participant has identity elements for feldman commitments
    #[error("secret_participant {0} has identity element feldman commitments")]
    IdentityElementFeldmanCommitments(usize),
}

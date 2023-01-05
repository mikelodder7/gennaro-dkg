use thiserror::Error as DError;

/// Errors produced by the gennaro DKG
#[derive(DError, Debug)]
pub enum Error {
    /// Format errors
    #[error("fmt error")]
    FmtError(#[from] std::fmt::Error),
    /// Verifiable secret sharing scheme errors
    #[error("vsss error")]
    VsssError(#[from] vsss_rs::Error),
    /// Errors during participant initialization
    #[error("error during participant creation: {0}")]
    InitializationError(String),
    /// Errors using rounds
    #[error("round {0} invalid input: `{1}`")]
    RoundError(usize, String),
}

/// Dkg results
pub type DkgResult<T> = anyhow::Result<T, Error>;

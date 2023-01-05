use thiserror::Error as DError;

#[derive(DError, Debug)]
pub enum Error {
    #[error("fmt error")]
    FmtError(#[from] std::fmt::Error),
    #[error("vsss error")]
    VsssError(#[from] vsss_rs::Error),
    #[error("error during participant creation: {0}")]
    InitializationError(String),
    #[error("round {0} invalid input: `{1}`")]
    RoundError(usize, String),
}

pub type DkgResult<T> = anyhow::Result<T, Error>;

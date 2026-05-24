use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("frost: {0}")]
    Frost(#[from] frost_secp256k1_tr::Error),

    #[error("invariant: {0}")]
    Invariant(&'static str),
}

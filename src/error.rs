use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("bad mnemonic: {0}")]
    BadMnemonic(anyhow::Error),
    #[error("hdwallet error: {0}")]
    HdWallet(#[from] hdwallet::error::Error),
    #[error("blst erro: {0}")]
    Blst(u32),
}
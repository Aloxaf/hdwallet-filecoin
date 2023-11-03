use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

// TODO: 整理一下错误类型
#[derive(Error, Debug)]
pub enum Error {
    #[error("bad mnemonic: {0}")]
    BadMnemonic(#[from] bip39::Error),
    #[error("hdwallet error: {0}")]
    HdWallet(#[from] hdwallet::error::Error),
    #[error("blst erro: {0}")]
    Blst(u32),
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
    #[error("cannot derive secp256k1 imported by private key")]
    CannotDerive,
    #[error("bad signature")]
    BadSignature,
    #[error("hex error: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("serde error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[cfg(feature = "keystore")]
    #[error("eth keystore error: {0}")]
    EthStoreError(#[from] eth_keystore::KeystoreError),
}

impl From<blst::BLST_ERROR> for Error {
    fn from(err: blst::BLST_ERROR) -> Self {
        Self::Blst(err as u32)
    }
}

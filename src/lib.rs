mod error;
mod utils;

use blst::min_sig::SecretKey as BlsPrivate;
use hdwallet::ExtendedPrivKey as SecpExtendedPrivate;
use secp256k1::SecretKey as SecpPrivate;

use crate::error::{Error, Result};
use crate::utils::mnemonic_to_seed;


// TODO: zeroize it
pub enum SecretKey {
    Secp256k1(SecpPrivate),
    Secp256k1Extended(SecpExtendedPrivate),
    Bls(BlsPrivate),
}

impl SecretKey {
    pub fn from_mnemonic_secp(phrase: &str) -> Result<Self> {
        let seed = mnemonic_to_seed(phrase)?;
        let sk = SecpExtendedPrivate::with_seed(seed.as_bytes())?;
        Ok(Self::Secp256k1Extended(sk))
    }

    pub fn from_mnemonic_bls(phrase: &str) -> Result<Self> {
        let seed = mnemonic_to_seed(phrase)?;
        // TODO: 测试一下 min_sig 和 min_pk 是不是效果一样
        let sk = BlsPrivate::derive_master_eip2333(seed.as_bytes())
            .map_err(|e| Error::Blst(e as u32))?;
        Ok(Self::Bls(sk))
    }

    pub fn from_slice_secp(data: &[u8]) -> Result<Self> {
        let sk = SecpPrivate::from_slice(data)?;
        Ok(Self::Secp256k1(sk))
    }

    pub fn from_slice_bls(data: &[u8]) -> Result<Self> {
        let sk = BlsPrivate::from_bytes(data).map_err(|e| Error::Blst(e as u32))?;
        Ok(Self::Bls(sk))
    }
}



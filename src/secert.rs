use blst::min_pk::SecretKey as BlsPrivate;
use hdwallet::ExtendedPrivKey as SecpExtendedPrivate;
use hdwallet::KeyIndex;
use secp256k1::SecretKey as SecpPrivate;

use crate::error::{Error, Result};
use crate::public::PublicKey;
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

impl SecretKey {
    pub fn derive_key(&self, index: u32) -> Result<Self> {
        match self {
            Self::Secp256k1Extended(sk) => {
                let sk = sk.derive_private_key(KeyIndex::Hardened(index))?;
                Ok(Self::Secp256k1Extended(sk))
            }
            Self::Bls(sk) => {
                let sk = sk.derive_child_eip2333(index);
                Ok(Self::Bls(sk))
            }
            Self::Secp256k1(_) => Err(Error::CannotDerive),
        }
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        match self {
            Self::Secp256k1Extended(sk) => {
                let secp = secp256k1::Secp256k1::new();
                Ok(PublicKey::Secp256k1(sk.private_key.public_key(&secp)))
            }
            Self::Secp256k1(sk) => {
                let secp = secp256k1::Secp256k1::new();
                Ok(PublicKey::Secp256k1(sk.public_key(&secp)))
            }
            Self::Bls(sk) => Ok(PublicKey::Bls(sk.sk_to_pk())),
        }
    }
}

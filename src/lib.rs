mod error;

use crate::error::{Result, Error};
use bip39::{Language, Mnemonic, Seed};
use hdwallet::traits::Serialize;

#[derive(Debug, Copy, Clone)]
pub enum SignatureType {
    ExtendedSecp256k1,
    Bls,
}

pub struct SecretKey {
    pub sig_type: SignatureType,
    pub private_key: Vec<u8>,
}

impl SecretKey {
    pub fn from_mnemonic(phrase: &str, sig_type: SignatureType) -> Result<Self> {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).map_err(Error::BadMnemonic)?;
        let seed = Seed::new(&mnemonic, "");
        let bytes = match sig_type {
            SignatureType::ExtendedSecp256k1 => {
                let sk = hdwallet::ExtendedPrivKey::with_seed(seed.as_bytes())?;
                sk.serialize()
            },
            SignatureType::Bls => {
                // TODO: 测试一下 min_sig 和 min_pk 是不是效果一样
                let sk = blst::min_sig::SecretKey::derive_master_eip2333(seed.as_bytes()).map_err(|e| Error::Blst(e as u32))?;
                sk.serialize().to_vec()
            },
        };
        Ok(Self {
            sig_type,
            private_key: bytes,
        })
    }
}

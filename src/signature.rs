use crate::error::{Error, Result};
use crate::public::PublicKey;
use crate::utils::blake2b_256;
use blst::min_pk::Signature as BlsSignature;
use blst::BLST_ERROR;
use secp256k1::ecdsa::Signature as SecpSignature;

pub enum Signature {
    Secp256k1(SecpSignature),
    Bls(BlsSignature),
}

impl Signature {
    pub fn verify(&self, msg: &[u8], pk: &PublicKey) -> Result<()> {
        match self {
            Self::Secp256k1(sig) => {
                let hash = blake2b_256(msg);
                let msg = secp256k1::Message::from_slice(&hash)?;
                if let PublicKey::Secp256k1(pk) = pk {
                    sig.verify(&msg, pk)?;
                } else {
                    return Err(Error::BadSignature);
                }
            }
            Self::Bls(sig) => {
                let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
                if let PublicKey::Bls(pk) = pk {
                    let err = sig.verify(true, msg, dst, &[], pk, true);
                    if err != BLST_ERROR::BLST_SUCCESS {
                        return Err(Error::BadSignature);
                    }
                } else {
                    return Err(Error::BadSignature);
                }
            }
        }
        Ok(())
    }
}

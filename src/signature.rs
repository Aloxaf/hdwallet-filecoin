use blst::min_pk::Signature as BlsSignature;
use blst::BLST_ERROR;
use secp256k1::ecdsa::RecoverableSignature as SecpSignature;

use super::public::PublicKey;
use super::utils::blake2b_256;
use crate::error::{Error, Result};

pub enum Signature {
    Secp256k1(SecpSignature),
    Bls(BlsSignature),
}

impl Signature {
    /// verify signature with given message and public key
    pub fn verify(&self, msg: &[u8], pk: &PublicKey) -> Result<()> {
        match self {
            Self::Secp256k1(sig) => {
                let hash = blake2b_256(msg);
                let msg = secp256k1::Message::from_slice(&hash)?;
                if let PublicKey::Secp256k1(pk) = pk {
                    let rpk = sig.recover(&msg)?;
                    if &rpk != pk {
                        return Err(Error::BadSignature);
                    }
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

    /// convert to bytes with sig type
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = vec![self.sig_type()];
        v.extend_from_slice(&self.bytes());
        v
    }

    /// convert to bytes
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Secp256k1(sig) => {
                let (rid, b) = sig.serialize_compact();
                let mut v = vec![];
                v.extend_from_slice(&b);
                v.push(rid.to_i32() as u8);
                v
            }
            Self::Bls(sig) => sig.compress().to_vec(),
        }
    }

    /// get signature type
    pub fn sig_type(&self) -> u8 {
        match self {
            Self::Secp256k1(_) => 1,
            Self::Bls(_) => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use data_encoding_macro::hexlower;

    use crate::json::SecertKeyJson;
    use crate::PrivateKey;

    fn sk_from_slice(data: &[u8]) -> PrivateKey {
        let skj = serde_json::from_slice::<SecertKeyJson>(data).unwrap();
        PrivateKey::try_from(skj).unwrap()
    }

    #[test]
    fn secp256k1() {
        let hex = hexlower!("7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226a7244314c48516258503942453964505635787350454237337a717441442b61644c52747a685a6646556f3d227d");
        let sk = sk_from_slice(&hex);
        let msg = b"Hello World!";
        let sig = sk.sign(msg).unwrap();
        assert_eq!(
            sig.serialize(),
            hexlower!("01aa665dd45bdc2eb4500dc1446c5fb9472c1d02371dd55c8fb396659d3a08795873afee70c20de206820769ec343a6bb310bad4604ab3a3472ce6d0fd5b3ad9a000"),
        );
        assert!(sig.verify(msg, &sk.public_key()).is_ok());
    }

    #[test]
    fn bls() {
        let hex = hexlower!("7b2254797065223a22626c73222c22507269766174654b6579223a22746d39534b6349696537354e3664595459764f67794b4277676f366570567a315651776c675459427569733d227d");
        let sk = sk_from_slice(&hex);
        let msg = b"Hello World!";
        let sig = sk.sign(msg).unwrap();
        assert_eq!(
            sig.serialize(),
            hexlower!("02ad03104578a146f973d29609520f760b57657b74d00a91f55e019c3ca4f4452762678a63895b82dc0ae7e34905e2270106f238a05fa979453732105d2be77f1152ec8e4e829755e09346ea2ad8f8632b52b449218799e6960ac0e13d00332f35"),
        );
        assert!(sig.verify(msg, &sk.public_key()).is_ok());
    }
}

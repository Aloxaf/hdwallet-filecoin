use blst::min_pk::SecretKey as BlsPrivate;
use hdwallet::ExtendedPrivKey as SecpExtendedPrivate;
use hdwallet::KeyIndex;
use secp256k1::SecretKey as SecpPrivate;

use crate::error::{Error, Result};
use crate::public::PublicKey;
use crate::signature::Signature;
use crate::utils::blake2b_256;

// TODO: zeroize it
pub enum SecretKey {
    Secp256k1(SecpPrivate),
    Secp256k1Extended(SecpExtendedPrivate),
    Bls(BlsPrivate),
}

impl SecretKey {
    pub fn from_seed_secp(seed: &[u8]) -> Result<Self> {
        let sk = SecpExtendedPrivate::with_seed(seed)?;
        Ok(Self::Secp256k1Extended(sk))
    }

    pub fn from_seed_bls(seed: &[u8]) -> Result<Self> {
        let sk = BlsPrivate::derive_master_eip2333(seed).map_err(|e| Error::Blst(e as u32))?;
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
            Self::Secp256k1Extended(SecpExtendedPrivate {
                private_key: sk, ..
            })
            | Self::Secp256k1(sk) => {
                let secp = secp256k1::Secp256k1::new();
                Ok(PublicKey::Secp256k1(sk.public_key(&secp)))
            }
            Self::Bls(sk) => Ok(PublicKey::Bls(sk.sk_to_pk())),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        match self {
            Self::Secp256k1Extended(SecpExtendedPrivate {
                private_key: sk, ..
            })
            | Self::Secp256k1(sk) => {
                let secp = secp256k1::Secp256k1::new();
                let hash = blake2b_256(msg);
                let msg = secp256k1::Message::from_slice(&hash)?;
                let sig = secp.sign_ecdsa(&msg, sk);
                Ok(Signature::Secp256k1(sig))
            }
            Self::Bls(sk) => {
                let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
                let sig = sk.sign(msg, dst, &[]);
                Ok(Signature::Bls(sig))
            }
        }
    }

    pub fn to_raw_bytes(&self) -> Vec<u8> {
        match self {
            Self::Secp256k1Extended(SecpExtendedPrivate {
                private_key: sk, ..
            })
            | Self::Secp256k1(sk) => sk.secret_bytes().to_vec(),
            Self::Bls(sk) => sk.to_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SecretKey;
    use crate::utils::mnemonic_to_seed;
    use data_encoding_macro::{hexlower, hexupper};
    use ibig::ubig;

    // https://eips.ethereum.org/EIPS/eip-2333#test-case-0
    #[test]
    fn eip_2333_case0() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(phrase, Some("TREZOR")).unwrap();
        assert_eq!(seed.as_bytes(), hexlower!("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"));

        let sk = SecretKey::from_seed_bls(seed.as_bytes()).unwrap();
        assert_eq!(
            sk.to_raw_bytes(),
            ubig!(_6083874454709270928345386274498605044986640685124978867557563392430687146096)
                .to_be_bytes()
        );

        let sk = sk.derive_key(0).unwrap();
        assert_eq!(
            sk.to_raw_bytes(),
            ubig!(_20397789859736650942317412262472558107875392172444076792671091975210932703118)
                .to_be_bytes()
        );
    }

    #[test]
    fn eip_2333_case1() {
        let seed = hexlower!("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
        let sk = SecretKey::from_seed_bls(&seed).unwrap();
        assert_eq!(
            sk.to_raw_bytes(),
            ubig!(_19022158461524446591288038168518313374041767046816487870552872741050760015818)
                .to_be_bytes()
        );

        let sk = sk.derive_key(42).unwrap();
        assert_eq!(
            sk.to_raw_bytes(),
            ubig!(_31372231650479070279774297061823572166496564838472787488249775572789064611981)
                .to_be_bytes()
        );
    }

    #[test]
    fn eip_2333_case2() {
        let seed = hexupper!("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00");
        let sk = SecretKey::from_seed_bls(&seed).unwrap();
        assert_eq!(
            sk.to_raw_bytes(),
            ubig!(_27580842291869792442942448775674722299803720648445448686099262467207037398656)
                .to_be_bytes()
        );

        let sk = sk.derive_key(4294967295).unwrap();
        assert_eq!(
            sk.to_raw_bytes(),
            ubig!(_29358610794459428860402234341874281240803786294062035874021252734817515685787)
                .to_be_bytes()
        );
    }

    #[test]
    fn eip_2333_case3() {
        let seed = hexlower!("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
        let sk = SecretKey::from_seed_bls(&seed).unwrap();
        assert_eq!(
            sk.to_raw_bytes(),
            ubig!(_19022158461524446591288038168518313374041767046816487870552872741050760015818)
                .to_be_bytes()
        );

        let sk = sk.derive_key(42).unwrap();
        assert_eq!(
            sk.to_raw_bytes(),
            ubig!(_31372231650479070279774297061823572166496564838472787488249775572789064611981)
                .to_be_bytes()
        );
    }
}

use blst::min_pk::SecretKey as BlsPrivate;
use hdwallet::ExtendedPrivKey as SecpExtendedPrivate;
use hdwallet::KeyIndex;
use secp256k1::SecretKey as SecpPrivate;

use crate::error::{Error, Result};
use crate::json::{SecertKeyJson, SigType};
use crate::public::PublicKey;
use crate::signature::Signature;
use crate::utils::{blake2b_256, bls_deserialize, bls_serialize};

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
        let sk = BlsPrivate::deserialize(data).map_err(|e| Error::Blst(e as u32))?;
        Ok(Self::Bls(sk))
    }

    pub fn from_lotus_hex(data: &str) -> Result<Self> {
        let bytes = hex::decode(data)?;
        let skj = serde_json::from_slice::<SecertKeyJson>(&bytes)?;
        match skj.sig_type {
            SigType::Bls => {
                let sk = bls_deserialize(&skj.private_key).map_err(|e| Error::Blst(e as u32))?;
                Ok(Self::Bls(sk))
            }
            SigType::Secp256k1 => Self::from_slice_secp(&skj.private_key),
        }
    }

    pub fn to_lotus_hex(&self) -> Result<String> {
        let skj = match self {
            Self::Secp256k1(_) | Self::Secp256k1Extended(_) => SecertKeyJson {
                sig_type: SigType::Secp256k1,
                private_key: self.to_raw_bytes(),
            },
            Self::Bls(sk) => SecertKeyJson {
                sig_type: SigType::Bls,
                private_key: bls_serialize(sk)
                    .map_err(|e| Error::Blst(e as u32))?
                    .to_vec(),
            },
        };
        let json = serde_json::to_string(&skj)?;
        let hex = hex::encode(&json);
        Ok(hex)
    }
}

impl SecretKey {
    pub fn derive_key(&self, index: u32) -> Result<Self> {
        match self {
            Self::Secp256k1Extended(sk) => {
                let sk = sk.derive_private_key(KeyIndex::Hardened(2u32.pow(31) + index))?;
                Ok(Self::Secp256k1Extended(sk))
            }
            Self::Bls(sk) => {
                let sk = sk.derive_child_eip2333(index);
                Ok(Self::Bls(sk))
            }
            Self::Secp256k1(_) => Err(Error::CannotDerive),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Secp256k1Extended(SecpExtendedPrivate {
                private_key: sk, ..
            })
            | Self::Secp256k1(sk) => {
                let secp = secp256k1::Secp256k1::new();
                PublicKey::Secp256k1(sk.public_key(&secp))
            }
            Self::Bls(sk) => PublicKey::Bls(sk.sk_to_pk()),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        match self {
            Self::Secp256k1Extended(SecpExtendedPrivate {
                private_key: sk, ..
            })
            | Self::Secp256k1(sk) => {
                let hash = blake2b_256(msg);
                let msg = secp256k1::Message::from_slice(&hash)?;
                let sig = sk.sign_ecdsa(msg);
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
    use hdwallet::traits::Deserialize;
    use hdwallet_bitcoin::PrivKey as BtcPrivKey;
    use ibig::ubig;

    // https://eips.ethereum.org/EIPS/eip-2333#test-case-0
    #[test]
    fn eip_2333_case0() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(phrase, Some("TREZOR")).unwrap();
        assert_eq!(seed, hexlower!("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"));

        let sk = SecretKey::from_seed_bls(&seed).unwrap();
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

    fn bitcoin_sk_eq(a: &SecretKey, b: &BtcPrivKey) {
        assert_eq!(a.to_raw_bytes(), b.extended_key.private_key.secret_bytes());
    }

    #[test]
    fn bip_32_test_vector_1() {
        let seed = hexlower!("000102030405060708090a0b0c0d0e0f");
        let sk = SecretKey::from_seed_secp(&seed).unwrap();
        bitcoin_sk_eq(
            &sk,
            &BtcPrivKey::deserialize("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_string()).unwrap(),
        );

        let sk = sk.derive_key(0).unwrap();
        bitcoin_sk_eq(
            &sk,
            &BtcPrivKey::deserialize("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7".to_string()).unwrap(),
        );
    }

    #[test]
    fn bip_32_test_vector_3() {
        let seed = hexlower!("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");
        let sk = SecretKey::from_seed_secp(&seed).unwrap();
        bitcoin_sk_eq(
            &sk,
            &BtcPrivKey::deserialize("xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6".to_string()).unwrap(),
        );

        let sk = sk.derive_key(0).unwrap();
        bitcoin_sk_eq(
            &sk,
            &BtcPrivKey::deserialize("xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L".to_string()).unwrap(),
        );
    }

    #[test]
    fn import_export() {
        let hex = "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226a7244314c48516258503942453964505635787350454237337a717441442b61644c52747a685a6646556f3d227d";
        let sk = SecretKey::from_lotus_hex(hex).unwrap();
        let addr = sk.public_key().to_address();
        assert_eq!(
            addr.to_string(),
            "f162husxmdufmecnuuzwzjwlbvuv6vy6hvvzy7x5y"
        );
        assert_eq!(sk.to_lotus_hex().unwrap(), hex);

        let hex = "7b2254797065223a22626c73222c22507269766174654b6579223a22746d39534b6349696537354e3664595459764f67794b4277676f366570567a315651776c675459427569733d227d";
        let sk = SecretKey::from_lotus_hex(hex).unwrap();
        let addr = sk.public_key().to_address();
        assert_eq!(addr.to_string(), "f3wo44vs6uyzuzc7dipubydfzrdwfwhjzovcvdx5bqpish5srqx7veq7chbmew4uqiwakzvb6r6gquvt3xvksa");
        assert_eq!(sk.to_lotus_hex().unwrap(), hex);
    }
}

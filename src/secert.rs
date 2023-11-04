use blst::min_pk::SecretKey as BlsPrivate;
use hdwallet::traits::{Deserialize, Serialize};
use hdwallet::ExtendedPrivKey as SecpExtendedPrivate;
use hdwallet::KeyIndex;
use secp256k1::{Message as SecpMessage, SecretKey as SecpPrivate, SECP256K1};

use super::error::{Error, Result};
use super::json::SigType;
use super::public::PublicKey;
use super::signature::Signature;
use super::utils::blake2b_256;
use crate::json::SecertKeyJson;

// TODO: zeroize it
#[derive(Debug, Clone)]
pub enum PrivateKey {
    Secp256k1(SecpPrivate),
    Secp256k1Extended(SecpExtendedPrivate),
    Bls(BlsPrivate),
}

impl PrivateKey {
    pub fn from_seed(sig_type: SigType, seed: &[u8]) -> Result<Self> {
        match sig_type {
            SigType::Secp256k1 => Self::from_seed_secp(seed),
            SigType::Bls => Self::from_seed_bls(seed),
        }
    }

    /// Generate a new secp256k1 secret key from a seed.
    pub fn from_seed_secp(seed: &[u8]) -> Result<Self> {
        let sk = SecpExtendedPrivate::with_seed(seed)?;
        Ok(Self::Secp256k1Extended(sk))
    }

    /// Generate a new bls secret key from a seed.
    pub fn from_seed_bls(seed: &[u8]) -> Result<Self> {
        let sk = BlsPrivate::derive_master_eip2333(seed).map_err(|e| Error::Blst(e as u32))?;
        Ok(Self::Bls(sk))
    }

    /// import private key from lotus hex format
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        let json = serde_json::from_slice::<SecertKeyJson>(&bytes)?;
        PrivateKey::try_from(json)
    }

    /// export private key to lotus hex format
    pub fn to_hex(self) -> Result<String> {
        let json = SecertKeyJson::from(self);
        let bytes = serde_json::to_vec(&json)?;
        Ok(hex::encode(bytes))
    }

    fn sig_type(&self) -> u8 {
        match self {
            Self::Secp256k1(_) => 1,
            Self::Bls(_) => 2,
            Self::Secp256k1Extended(_) => 255,
        }
    }

    /// Convert to bytes with sig type
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = match self {
            Self::Secp256k1Extended(x) => x.serialize(),
            Self::Secp256k1(sk) => sk.secret_bytes().to_vec(),
            Self::Bls(sk) => sk.to_bytes().to_vec(),
        };
        data.insert(0, self.sig_type());
        data
    }

    /// Convert to bytes without sig type
    pub fn secret_bytes(&self) -> Vec<u8> {
        match self {
            Self::Secp256k1Extended(SecpExtendedPrivate {
                private_key: sk, ..
            })
            | Self::Secp256k1(sk) => sk.secret_bytes().to_vec(),
            Self::Bls(sk) => sk.to_bytes().to_vec(),
        }
    }

    /// Convert from bytes with sig type
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        match data[0] {
            1 => Ok(Self::Secp256k1(SecpPrivate::from_slice(&data[1..])?)),
            2 => Ok(Self::Bls(BlsPrivate::from_bytes(&data[1..])?)),
            255 => Ok(Self::Secp256k1Extended(SecpExtendedPrivate::deserialize(
                &data[1..],
            )?)),
            _ => unreachable!(),
        }
    }
}

impl PrivateKey {
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
                let msg = SecpMessage::from_slice(&hash)?;
                let sig = SECP256K1.sign_ecdsa_recoverable(&msg, sk);
                Ok(Signature::Secp256k1(sig))
            }
            Self::Bls(sk) => {
                let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
                let sig = sk.sign(msg, dst, &[]);
                Ok(Signature::Bls(sig))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use data_encoding_macro::{hexlower, hexupper};
    use hdwallet::traits::Deserialize;
    use hdwallet_bitcoin::PrivKey as BtcPrivKey;
    use ibig::ubig;

    use super::PrivateKey;
    use crate::utils::mnemonic_to_seed;

    // https://eips.ethereum.org/EIPS/eip-2333#test-case-0
    #[test]
    fn eip_2333_case0() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(phrase, Some("TREZOR")).unwrap();
        assert_eq!(seed, hexlower!("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"));

        let sk = PrivateKey::from_seed_bls(&seed).unwrap();
        assert_eq!(
            sk.secret_bytes(),
            ubig!(_6083874454709270928345386274498605044986640685124978867557563392430687146096)
                .to_be_bytes()
        );

        let sk = sk.derive_key(0).unwrap();
        assert_eq!(
            sk.secret_bytes(),
            ubig!(_20397789859736650942317412262472558107875392172444076792671091975210932703118)
                .to_be_bytes()
        );
    }

    #[test]
    fn eip_2333_case1() {
        let seed = hexlower!("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
        let sk = PrivateKey::from_seed_bls(&seed).unwrap();
        assert_eq!(
            sk.secret_bytes(),
            ubig!(_19022158461524446591288038168518313374041767046816487870552872741050760015818)
                .to_be_bytes()
        );

        let sk = sk.derive_key(42).unwrap();
        assert_eq!(
            sk.secret_bytes(),
            ubig!(_31372231650479070279774297061823572166496564838472787488249775572789064611981)
                .to_be_bytes()
        );
    }

    #[test]
    fn eip_2333_case2() {
        let seed = hexupper!("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00");
        let sk = PrivateKey::from_seed_bls(&seed).unwrap();
        assert_eq!(
            sk.secret_bytes(),
            ubig!(_27580842291869792442942448775674722299803720648445448686099262467207037398656)
                .to_be_bytes()
        );

        let sk = sk.derive_key(4294967295).unwrap();
        assert_eq!(
            sk.secret_bytes(),
            ubig!(_29358610794459428860402234341874281240803786294062035874021252734817515685787)
                .to_be_bytes()
        );
    }

    #[test]
    fn eip_2333_case3() {
        let seed = hexlower!("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
        let sk = PrivateKey::from_seed_bls(&seed).unwrap();
        assert_eq!(
            sk.secret_bytes(),
            ubig!(_19022158461524446591288038168518313374041767046816487870552872741050760015818)
                .to_be_bytes()
        );

        let sk = sk.derive_key(42).unwrap();
        assert_eq!(
            sk.secret_bytes(),
            ubig!(_31372231650479070279774297061823572166496564838472787488249775572789064611981)
                .to_be_bytes()
        );
    }

    fn bitcoin_sk_eq(a: &PrivateKey, b: &BtcPrivKey) {
        assert_eq!(a.secret_bytes(), b.extended_key.private_key.secret_bytes());
    }

    #[test]
    fn bip_32_test_vector_1() {
        let seed = hexlower!("000102030405060708090a0b0c0d0e0f");
        let sk = PrivateKey::from_seed_secp(&seed).unwrap();
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
        let sk = PrivateKey::from_seed_secp(&seed).unwrap();
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
    fn hex() {
        let hex = "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226a7244314c48516258503942453964505635787350454237337a717441442b61644c52747a685a6646556f3d227d";
        let sk = PrivateKey::from_hex(hex).unwrap();

        assert_eq!(
            sk.public_key().address().to_string(),
            "f162husxmdufmecnuuzwzjwlbvuv6vy6hvvzy7x5y"
        );

        assert_eq!(hex, sk.to_hex().unwrap());
    }
}

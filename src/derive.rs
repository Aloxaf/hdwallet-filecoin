use std::str::FromStr;

use hdpath::{CustomHDPath, PathValue};
use serde::Deserialize;

use crate::{error::Result, PrivateKey, Signature};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtendedPrivateKey {
    #[serde(serialize_with = "serde_sk", deserialize_with = "deserde_sk")]
    pub key: PrivateKey,
    #[serde(serialize_with = "serde_path", deserialize_with = "deserde_path")]
    pub path: CustomHDPath,
}

impl ExtendedPrivateKey {
    pub fn from_seed_secp(seed: &[u8]) -> Result<Self> {
        let key = PrivateKey::from_seed_secp(seed)?;
        let path = CustomHDPath(vec![]);
        Ok(Self { key, path })
    }

    pub fn from_seed_bls(seed: &[u8]) -> Result<Self> {
        let key = PrivateKey::from_seed_bls(seed)?;
        let path = CustomHDPath(vec![]);
        Ok(Self { key, path })
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        let key = PrivateKey::from_hex(hex)?;
        let path = CustomHDPath(vec![]);
        Ok(Self { key, path })
    }

    pub fn to_hex(&self) -> Result<String> {
        self.key.clone().to_hex()
    }

    pub fn derive_key(&self, index: u32) -> Result<Self> {
        let key = self.key.derive_key(index)?;
        let mut path = self.path.clone();
        path.0.push(PathValue::Hardened(index));
        Ok(Self { key, path })
    }

    pub fn address(&self) -> String {
        self.key.public_key().address().to_string()
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        self.key.sign(msg)
    }
}

fn serde_sk<S>(sk: &PrivateKey, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(sk.serialize()))
}

fn deserde_sk<'de, D>(deserializer: D) -> std::result::Result<PrivateKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let data = <String>::deserialize(deserializer)?;
    let bytes = hex::decode(data).map_err(|_| serde::de::Error::custom("invalid"))?;
    PrivateKey::deserialize(&bytes).map_err(serde::de::Error::custom)
}

fn serde_path<S>(path: &CustomHDPath, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&path.to_string())
}

fn deserde_path<'de, D>(deserializer: D) -> std::result::Result<CustomHDPath, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let data = <&str>::deserialize(deserializer)?;
    CustomHDPath::from_str(data).map_err(|_| serde::de::Error::custom("invalid"))
}

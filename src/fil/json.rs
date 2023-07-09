use base64_serde::base64_serde_type;
use hdwallet::ExtendedPrivKey as SecpExtendedPrivate;
use secp256k1::SecretKey as SecpPrivate;
use serde::{Deserialize, Serialize};

use super::secert::SecretKey;
use crate::error::Error;
use crate::fil::utils::{bls_deserialize, bls_serialize};

base64_serde_type!(Base64Standard, base64::engine::general_purpose::STANDARD);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigType {
    Secp256k1,
    Bls,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SecertKeyJson {
    #[serde(rename = "Type")]
    pub sig_type: SigType,
    #[serde(with = "Base64Standard")]
    pub private_key: Vec<u8>,
}

impl From<SecretKey> for SecertKeyJson {
    fn from(value: SecretKey) -> Self {
        match value {
            SecretKey::Bls(sk) => Self {
                sig_type: SigType::Bls,
                private_key: bls_serialize(&sk).unwrap().to_vec(),
            },
            SecretKey::Secp256k1Extended(SecpExtendedPrivate {
                private_key: sk, ..
            })
            | SecretKey::Secp256k1(sk) => Self {
                sig_type: SigType::Secp256k1,
                private_key: sk.secret_bytes().to_vec(),
            },
        }
    }
}

impl TryFrom<SecertKeyJson> for SecretKey {
    type Error = Error;

    fn try_from(v: SecertKeyJson) -> Result<Self, Self::Error> {
        match v.sig_type {
            SigType::Bls => Ok(Self::Bls(bls_deserialize(&v.private_key)?)),
            SigType::Secp256k1 => Ok(Self::Secp256k1(SecpPrivate::from_slice(&v.private_key)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use data_encoding_macro::hexlower;

    use super::*;

    #[test]
    fn json_serialize() {
        let json = r#"{"Type":"bls","PrivateKey":"tm9SKcIie75N6dYTYvOgyKBwgo6epVz1VQwlgTYBuis="}"#;
        let sk = serde_json::from_str::<SecertKeyJson>(json).unwrap();
        assert_eq!(json, serde_json::to_string(&sk).unwrap(),);
    }

    #[test]
    fn secp_serialize() {
        let hex = hexlower!("7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226a7244314c48516258503942453964505635787350454237337a717441442b61644c52747a685a6646556f3d227d");
        let skj = serde_json::from_slice::<SecertKeyJson>(&hex).unwrap();
        let sk = SecretKey::try_from(skj).unwrap();
        let addr = sk.public_key().to_address();
        assert_eq!(
            addr.to_string(),
            "f162husxmdufmecnuuzwzjwlbvuv6vy6hvvzy7x5y"
        );

        let skj = SecertKeyJson::from(sk);
        let hex2 = serde_json::to_string(&skj).unwrap();
        assert_eq!(hex2.as_bytes(), hex);
    }

    #[test]
    fn bls_serialize() {
        let hex = hexlower!("7b2254797065223a22626c73222c22507269766174654b6579223a22746d39534b6349696537354e3664595459764f67794b4277676f366570567a315651776c675459427569733d227d");
        let skj = serde_json::from_slice::<SecertKeyJson>(&hex).unwrap();
        let sk = SecretKey::try_from(skj).unwrap();
        let addr = sk.public_key().to_address();
        assert_eq!(addr.to_string(), "f3wo44vs6uyzuzc7dipubydfzrdwfwhjzovcvdx5bqpish5srqx7veq7chbmew4uqiwakzvb6r6gquvt3xvksa");

        let skj = SecertKeyJson::from(sk);
        let hex2 = serde_json::to_string(&skj).unwrap();
        assert_eq!(hex2.as_bytes(), hex);
    }
}

use crate::secert::SecretKey;
use base64_serde::base64_serde_type;
use hdwallet::ExtendedPrivKey as SecpExtendedPrivate;
use serde::{Deserialize, Serialize};

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
                private_key: sk.serialize().to_vec(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secert_key() {
        let json = r#"{"Type":"bls","PrivateKey":"tm9SKcIie75N6dYTYvOgyKBwgo6epVz1VQwlgTYBuis="}"#;
        let sk = serde_json::from_str::<SecertKeyJson>(json).unwrap();
        assert_eq!(json, serde_json::to_string(&sk).unwrap(),);
    }
}

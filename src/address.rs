use crate::utils::address_hash;
use data_encoding::Encoding;
use data_encoding_macro::new_encoding;
use std::fmt;

pub const CHECKSUM_HASH_LEN: usize = 4;
pub const PAYLOAD_HASH_LEN: usize = 20;
pub const SECP_PUB_LEN: usize = 65;
pub const BLS_PUB_LEN: usize = 48;

const ADDRESS_ENCODER: Encoding = new_encoding! {
    symbols: "abcdefghijklmnopqrstuvwxyz234567",
    padding: None,
};

pub enum Address {
    Secp256k1([u8; PAYLOAD_HASH_LEN]),
    Bls([u8; BLS_PUB_LEN]),
}

impl Address {
    /// Generates new address using Secp256k1 pubkey.
    pub fn new_secp256k1(pubkey: &[u8]) -> Self {
        assert_eq!(pubkey.len(), SECP_PUB_LEN);
        Self::Secp256k1(address_hash(pubkey))
    }

    /// Generates new address using BLS pubkey.
    pub fn new_bls(pubkey: &[u8]) -> Self {
        assert_eq!(pubkey.len(), BLS_PUB_LEN);
        let mut key = [0u8; BLS_PUB_LEN];
        key.copy_from_slice(pubkey);
        Self::Bls(key)
    }

    /// Returns encoded bytes of Address without the protocol byte.
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        match self {
            Self::Secp256k1(arr) => arr.to_vec(),
            Self::Bls(arr) => arr.to_vec(),
        }
    }

    /// Returns encoded bytes of Address including the protocol byte.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bz = self.to_raw_bytes();
        match self {
            Self::Secp256k1(_) => bz.insert(0, 1),
            Self::Bls(_) => bz.insert(0, 3),
        }
        bz
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(CHECKSUM_HASH_LEN)
            .to_state();
        hasher.update(&self.to_bytes());

        let mut buf = self.to_raw_bytes();
        buf.extend(hasher.finalize().as_bytes());

        match self {
            Self::Secp256k1(_) => f.write_str("f1")?,
            Self::Bls(_) => f.write_str("f3")?,
        }

        f.write_str(&ADDRESS_ENCODER.encode(&buf))?;

        Ok(())
    }
}

use blst::min_pk::PublicKey as BlsPublic;
use secp256k1::PublicKey as SecpPublic;

use super::address::Address;

pub enum PublicKey {
    Secp256k1(SecpPublic),
    Bls(BlsPublic),
}

impl PublicKey {
    pub fn to_address(&self) -> Address {
        match self {
            Self::Secp256k1(pk) => Address::new_secp256k1(&pk.serialize_uncompressed()),
            Self::Bls(pk) => Address::new_bls(&pk.compress()),
        }
    }
}

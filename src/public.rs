use blst::min_pk::PublicKey as BlsPublic;
use secp256k1::PublicKey as SecpPublic;
use std::fmt;

pub enum PublicKey {
    Secp256k1(SecpPublic),
    Bls(BlsPublic),
}

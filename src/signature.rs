use blst::min_pk::Signature as BlsSignature;
use secp256k1::ecdsa::Signature as SecpSignature;

pub enum Signature {
    Secp256k1(SecpSignature),
    Bls(BlsSignature),
}

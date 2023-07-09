use bip39::Mnemonic;
use blake2b_simd::Params;
use blst::min_pk::SecretKey as BlsPrivate;
use blst::{
    blst_bendian_from_scalar, blst_lendian_from_scalar, blst_scalar, blst_scalar_from_bendian,
    blst_scalar_from_lendian, blst_sk_check, BLST_ERROR,
};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::Result;

pub fn mnemonic_to_seed(phrase: &str, passphrase: Option<&str>) -> Result<[u8; 64]> {
    let mnemonic = Mnemonic::parse(phrase)?;
    Ok(mnemonic.to_seed(passphrase.unwrap_or_default()))
}

pub fn new_mnemonic() -> Result<Vec<String>> {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy)?;
    Ok(mnemonic.word_iter().map(|s| s.to_owned()).collect())
}

pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let digest = Params::new()
        .hash_length(32)
        .to_state()
        .update(data)
        .finalize();
    let mut ret = [0u8; 32];
    ret.copy_from_slice(digest.as_bytes());
    ret
}

pub fn address_hash(ingest: &[u8]) -> [u8; 20] {
    let digest = Params::new()
        .hash_length(20)
        .to_state()
        .update(ingest)
        .finalize();

    let mut hash = [0u8; 20];
    hash.copy_from_slice(digest.as_bytes());
    hash
}

// filecoin 使用小端序来进行序列化
// 但 blst 使用的大端序来进行序列化，并且改不了，无语
pub fn bls_serialize(sk: &BlsPrivate) -> std::result::Result<[u8; 32], BLST_ERROR> {
    // 先使用大端序序列化
    let sk_in = sk.serialize();
    // 再使用大端序反序列化，拿到内部值
    let mut sk = blst_scalar::default();
    if sk_in.len() != 32 {
        return Err(BLST_ERROR::BLST_BAD_ENCODING);
    }
    unsafe {
        blst_scalar_from_bendian(&mut sk, sk_in.as_ptr());
        if !blst_sk_check(&sk) {
            return Err(BLST_ERROR::BLST_BAD_ENCODING);
        }
    }
    // 最后使用小端序序列化
    let mut sk_out = [0; 32];
    unsafe {
        blst_lendian_from_scalar(sk_out.as_mut_ptr(), &sk);
    }
    Ok(sk_out)
}

pub fn bls_deserialize(sk_in: &[u8]) -> std::result::Result<BlsPrivate, BLST_ERROR> {
    // 先使用小端序反序列化
    let mut sk = blst_scalar::default();
    if sk_in.len() != 32 {
        return Err(BLST_ERROR::BLST_BAD_ENCODING);
    }
    unsafe {
        blst_scalar_from_lendian(&mut sk, sk_in.as_ptr());
        if !blst_sk_check(&sk) {
            return Err(BLST_ERROR::BLST_BAD_ENCODING);
        }
    }
    // 再使用大端序序列化
    let mut sk_out = [0; 32];
    unsafe {
        blst_bendian_from_scalar(sk_out.as_mut_ptr(), &sk);
    }
    // 最后使用大端序反序列化
    BlsPrivate::deserialize(&sk_out)
}

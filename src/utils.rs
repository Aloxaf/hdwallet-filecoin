use crate::error::{Error, Result};
use bip39::{Language, Mnemonic, Seed};
use blake2b_simd::Params;

pub fn mnemonic_to_seed(phrase: &str, passphrase: Option<&str>) -> Result<Seed> {
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English).map_err(Error::BadMnemonic)?;
    Ok(Seed::new(&mnemonic, passphrase.unwrap_or_default()))
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

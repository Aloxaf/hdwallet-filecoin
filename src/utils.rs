use bip39::{Mnemonic, Seed, Language};
use crate::error::{Error, Result};

pub fn mnemonic_to_seed(phrase: &str) -> Result<Seed> {
    let mnemonic =
            Mnemonic::from_phrase(phrase, Language::English).map_err(Error::BadMnemonic)?;
    Ok(Seed::new(&mnemonic, ""))
}

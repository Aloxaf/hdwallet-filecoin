use std::path::PathBuf;

use bip39::Mnemonic;
use data_encoding::BASE32_NOPAD;
use eth_keystore::{decrypt_key, encrypt_key};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::Result;
use crate::fil::json::{SecertKeyJson, SigType};
use crate::SecretKey;

pub struct LocalWallet {
    path: PathBuf,
}

impl LocalWallet {
    pub fn new<P: Into<PathBuf>>(path: P, passphrase: &str) -> Result<Self> {
        let path = path.into();
        if !path.exists() {
            std::fs::create_dir_all(&path).unwrap();
        }
        let s = Self { path: path.clone() };

        if path.join(key_name("init")).exists() {
            s.decrypt("init", passphrase)?;
        } else {
            let mut random = [0u8; 32];
            OsRng.fill_bytes(&mut random);
            s.encrypt("init", &random, passphrase)?;
        }

        Ok(s)
    }

    /// generate a new key, return the address and mnemonic words
    pub fn generate(&self, sig_type: SigType, passphrase: &str) -> Result<(String, Vec<String>)> {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy)?;
        let sk = SecretKey::from_seed(sig_type, &mnemonic.to_seed(passphrase))?;
        let addr = sk.public_key().address().to_string();
        self.encrypt(&addr, &sk.serialize(), passphrase)?;
        Ok((addr, mnemonic.word_iter().map(|s| s.to_owned()).collect()))
    }

    /// import private key from lotus hex format
    pub fn import(&self, hex: &str, passphrase: &str) -> Result<()> {
        let bytes = hex::decode(hex)?;
        let json = serde_json::from_slice::<SecertKeyJson>(&bytes)?;
        let sk = SecretKey::try_from(json)?;
        let addr = sk.public_key().address().to_string();
        self.encrypt(&addr, &sk.serialize(), passphrase)?;
        Ok(())
    }

    /// export private key to lotus hex format
    pub fn export(&self, addr: &str, passphrase: &str) -> Result<String> {
        let sk = self.get(addr, passphrase)?;
        let json = SecertKeyJson::from(sk);
        let bytes = serde_json::to_vec(&json)?;
        Ok(hex::encode(bytes))
    }

    /// derive child key from given addr
    pub fn derive(&self, addr: &str, index: u32, passphrase: &str) -> Result<String> {
        let sk = self.get(addr, passphrase)?;
        let child_sk = sk.derive_key(index)?;
        let child_addr = child_sk.public_key().address().to_string();
        self.encrypt(&child_addr, &child_sk.serialize(), passphrase)?;
        Ok(child_addr)
    }

    /// list all addresses
    pub fn list(&self) -> Result<Vec<String>> {
        let mut addrs = vec![];
        for entry in std::fs::read_dir(&self.path)? {
            let name = BASE32_NOPAD
                .decode(entry?.file_name().to_str().unwrap().as_bytes())
                .ok()
                .and_then(|v| String::from_utf8(v).ok());
            if let Some(name) = name {
                if name != "init" {
                    addrs.push(name);
                }
            }
        }
        Ok(addrs)
    }

    /// sign message with given addr
    pub fn sign(&self, addr: &str, msg: &[u8], passphrase: &str) -> Result<Vec<u8>> {
        let sk = self.get(addr, passphrase)?;
        let sig = sk.sign(msg)?;
        Ok(sig.serialize())
    }

    /// delete key with given addr
    pub fn delete(&self, addr: &str, passphrase: &str) -> Result<()> {
        let _ = self.get(addr, passphrase)?;
        let path = self.path.join(key_name(addr));
        std::fs::remove_file(path)?;
        Ok(())
    }

    fn get(&self, addr: &str, passphrase: &str) -> Result<SecretKey> {
        let bytes = self.decrypt(addr, passphrase)?;
        SecretKey::deserialize(&bytes)
    }

    fn decrypt(&self, addr: &str, passphrase: &str) -> Result<Vec<u8>> {
        let path = self.path.join(key_name(addr));
        Ok(decrypt_key(path, passphrase)?)
    }

    fn encrypt(&self, addr: &str, data: &[u8], passphrase: &str) -> Result<String> {
        Ok(encrypt_key(
            &self.path,
            &mut OsRng,
            data,
            passphrase.as_bytes(),
            Some(&*key_name(addr)),
        )?)
    }
}

fn key_name(addr: &str) -> String {
    BASE32_NOPAD.encode(addr.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::LocalWallet;

    #[test]
    fn import_export() {
        let hex = "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226a7244314c48516258503942453964505635787350454237337a717441442b61644c52747a685a6646556f3d227d";
        let passphrase = "123456";
        let lw = LocalWallet::new("/tmp/keystore", passphrase).unwrap();
        lw.import(hex, passphrase).unwrap();
        let hex2 = lw
            .export("f162husxmdufmecnuuzwzjwlbvuv6vy6hvvzy7x5y", passphrase)
            .unwrap();
        assert_eq!(hex, hex2);

        assert_eq!(
            lw.list().unwrap(),
            vec!["f162husxmdufmecnuuzwzjwlbvuv6vy6hvvzy7x5y"]
        );

        let lw = LocalWallet::new("/tmp/keystore", "bad");
        assert!(lw.is_err());
    }
}

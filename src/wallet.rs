use std::path::PathBuf;

use eth_keystore::{decrypt_key, encrypt_key};
use rand::rngs::OsRng;
use uuid::Uuid;

use crate::error::Result;
use crate::fil::json::SecertKeyJson;
use crate::SecretKey;

const NAMESPACE_FILADDR: Uuid = Uuid::from_bytes([
    0xb0, 0x28, 0x17, 0x47, 0x10, 0xc6, 0x4a, 0xb6, 0x8e, 0xaa, 0x1b, 0x0e, 0x2d, 0x07, 0xed, 0xc5,
]);

pub struct LocalWallet {
    path: PathBuf,
}

impl LocalWallet {
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        let path = path.into();
        if !path.exists() {
            std::fs::create_dir_all(&path).unwrap();
        }
        Self { path }
    }

    /// import private key from lotus hex format
    pub fn import(&self, hex: &str, passphrase: &str) -> Result<()> {
        let bytes = hex::decode(hex)?;
        let json = serde_json::from_slice::<SecertKeyJson>(&bytes)?;
        let sk = SecretKey::try_from(json)?;
        // TODO: 这里使用 to_bytes 是不是更好？
        let addr = sk.public_key().to_address().to_string();
        encrypt_key(
            &self.path,
            &mut OsRng,
            sk.serialize(),
            passphrase.as_bytes(),
            Some(&*key_name(&addr)),
        )?;
        Ok(())
    }

    /// export private key to lotus hex format
    pub fn export(&self, addr: &str, passphrase: &str) -> Result<String> {
        let sk = self.get(addr, passphrase)?;
        let json = SecertKeyJson::from(sk);
        let bytes = serde_json::to_vec(&json)?;
        Ok(hex::encode(bytes))
    }

    fn get(&self, addr: &str, passphrase: &str) -> Result<SecretKey> {
        let path = self.path.join(key_name(addr));
        let bytes = decrypt_key(path, passphrase)?;
        SecretKey::deserialize(&bytes)
    }
}

fn key_name(addr: &str) -> String {
    let uuid = Uuid::new_v5(&NAMESPACE_FILADDR, &addr.as_bytes());
    format!("{}.json", uuid.to_string())
}

#[cfg(test)]
mod tests {
    use super::LocalWallet;

    #[test]
    fn import_export() {
        let hex = "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226a7244314c48516258503942453964505635787350454237337a717441442b61644c52747a685a6646556f3d227d";
        let passphrase = "123456";
        let lw = LocalWallet::new("/tmp/keystore");
        lw.import(hex, passphrase).unwrap();
        let hex2 = lw.export("f162husxmdufmecnuuzwzjwlbvuv6vy6hvvzy7x5y", passphrase).unwrap();
        assert_eq!(hex, hex2);
    }
}
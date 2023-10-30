use rand::RngCore;

use super::error::Result;
use super::json::{SecertKeyJson};
use super::SecretKey;


/// import private key from lotus hex format
/// return public address
pub fn import_hex(hex: &str) -> Result<SecretKey> {
    let bytes = hex::decode(hex)?;
    let json = serde_json::from_slice::<SecertKeyJson>(&bytes)?;
    Ok(SecretKey::try_from(json)?)
}

/// export private key to lotus hex format
pub fn export_hex(sk: SecretKey) -> Result<String> {
    let json = SecertKeyJson::from(sk);
    let bytes = serde_json::to_vec(&json)?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::{export_hex, import_hex};

    #[test]
    fn import_export() {
        let hex = "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226a7244314c48516258503942453964505635787350454237337a717441442b61644c52747a685a6646556f3d227d";
        let sk = import_hex(hex).unwrap();

        assert_eq!(
            sk.public_key().address().to_string(),
            "f162husxmdufmecnuuzwzjwlbvuv6vy6hvvzy7x5y"
        );

        assert_eq!(hex, export_hex(sk).unwrap());
    }
}

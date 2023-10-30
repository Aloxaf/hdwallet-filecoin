//! # Usage
//!
//! ```rust
//! use hdwallet_filecoin::{new_mnemonic, SecretKey};
//!
//! let mnemonic = new_mnemonic().unwrap();
//! println!("{}", mnemonic);
//! let seed = mnemonic.to_seed("");
//!
//! let sk = SecretKey::from_seed_bls(&seed).unwrap();
//! let pk = sk.public_key();
//! println!("{}", pk.address());
//!
//! let msg = b"hello world";
//! let sig = sk.sign(msg).unwrap();
//!
//! assert!(sig.verify(msg, &pk).is_ok());
//! ```

mod error;
//mod wallet;
mod address;
mod hex;
mod json;
mod public;
mod secert;
mod signature;
mod utils;

pub use address::Address;
pub use hex::{export_hex, import_hex};
pub use json::SigType;
pub use public::PublicKey;
pub use secert::SecretKey;
pub use signature::Signature;
pub use utils::{mnemonic_to_seed, new_mnemonic};

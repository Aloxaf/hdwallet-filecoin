# hdwallet-filecoin

Hierarchical Deterministic Wallet for filecoin.

This implemention follows:

- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) for mnemonic word
- [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) for secp256k1 derivation
- [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333) for bls12-381 derivation
~~- [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) for hierarchical deterministic path~~
- [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition) for keystore

**NOTE: Filecoin has not officially announced that it is compatible with any of the above proposals**

**Please do not expect this library to be compatible with third-party wallets.**

## Usage

```rust
use hdwallet_filecoin::{new_mnemonic, SecretKey};

fn main() {
    let mnemonic = new_mnemonic().unwrap();
    println!("{}", mnemonic);
    let seed = mnemonic.to_seed("");

    let sk = SecretKey::from_seed_bls(&seed).unwrap();
    // You can also use SecretKey::from_seed_secp256k1 to generate a secp256k1 key
    let pk = sk.public_key();
    println!("{}", pk.address());

    let msg = b"hello world";
    let sig = sk.sign(msg).unwrap();

    assert!(sig.verify(msg, &pk).is_ok());
}
```

## Thanks to these projects for reference
- https://github.com/ChainSafe/forest
- https://github.com/filecoin-project/ref-fvm

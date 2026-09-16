use client_core::identity::CipherIdentity;
use sha3::{Digest, Keccak256};

#[test]
fn test_standard_derivation() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let identity = CipherIdentity::from_mnemonic(mnemonic).unwrap();

    let addr = identity.evm_address();
    println!("Mnemonic: {}", mnemonic);
    println!("Derived Address: {}", addr);

    // Standard Ethereum address for this mnemonic (m/44'/60'/0'/0/0) is:
    let expected = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    println!("Expected Address: {}", expected);

    if addr.to_lowercase() == expected.to_lowercase() {
        println!("✅ MATCHES STANDARD!");
    } else {
        println!("❌ DOES NOT MATCH STANDARD");
    }
}

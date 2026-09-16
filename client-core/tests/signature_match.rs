use secp256k1::{Message, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

#[test]
fn test_signature_matching() {
    let payload_hex = "1400146e696e6a61000000c80000000100000063fa0b7e306a6674bfa6fe708a7d6f0e32c1fac1cbaef10eef7a3a7da0c6186563fa0b7e306a6674bfa6fe708a7d6f0e32c1fac1cbaef10eef7a3a7da0c61865";
    let key_hex = "239dc889a39a3156643c88deaee933cd17808e3963acac5334b1e46bc9089d89";

    let payload = hex::decode(payload_hex).unwrap();
    let sk_bytes = hex::decode(key_hex).unwrap();
    let sk = SecretKey::from_slice(&sk_bytes).unwrap();

    // JS signs the hash of the payload
    let hash = Keccak256::digest(&payload);
    let msg = Message::from_digest(hash.into());

    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa_recoverable(&msg, &sk);
    let (rec_id, sig_bytes_compact) = sig.serialize_compact();

    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&sig_bytes_compact);
    sig_bytes[64] = rec_id.to_i32() as u8;

    println!("Rust Signature: 0x{}", hex::encode(sig_bytes));

    // JS result from index.js:
    let expected = "d311fe8fe38e5e0cbb65808639e4415e22f2c07f550d241c4bbe747d315bff9a60a6a65eed566193b20be9b6daf4986988938abda68302453e06c031c322247a00";
    println!("JS expected:   0x{}", expected);

    if hex::encode(sig_bytes) == expected {
        println!("✅ SIGNATURES MATCH!");
    } else {
        println!("❌ SIGNATURES MISMATCH");
    }
}

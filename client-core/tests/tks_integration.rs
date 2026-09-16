/// Integration test: register @ninja on the TKS node directly.
/// Run with: cargo test --test tks_integration -- --nocapture
use client_core::identity::CipherIdentity;
use client_core::tks_rpc::TksRpcClient;

const TEST_MNEMONIC: &str =
    "tribe input replace filter attract switch party dream raven similar weather draft";

#[test]
fn register_ninja_on_chain() {
    let identity = CipherIdentity::from_mnemonic(TEST_MNEMONIC).expect("valid mnemonic");
    let addr = identity.display_address();
    println!("Identity address (k256): {}", addr);

    // Verify address derivation consistency between k256 and secp256k1
    let k256_key = identity.secp256k1_signing_key().clone();
    let k256_bytes = k256_key.to_bytes();
    println!("Secret key bytes: {}", hex::encode(&k256_bytes));

    // Derive address via k256
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let k256_pub = k256_key.verifying_key();
    let k256_pub_bytes = k256_pub.to_encoded_point(false);
    let k256_pub_raw = &k256_pub_bytes.as_bytes()[1..]; // skip 0x04 prefix
    println!("k256 public key (64 bytes): {}", hex::encode(k256_pub_raw));

    use sha3::{digest::Digest, Keccak256};
    let k256_hash = Keccak256::digest(k256_pub_raw);
    let k256_addr = &k256_hash[12..];
    println!("k256 address: 0x{}", hex::encode(k256_addr));

    // Derive address via secp256k1
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&k256_bytes).expect("valid key");
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let pk_bytes = pk.serialize_uncompressed();
    let secp_pub_raw = &pk_bytes[1..]; // skip 0x04 prefix
    println!(
        "secp256k1 public key (64 bytes): {}",
        hex::encode(secp_pub_raw)
    );

    let secp_hash = Keccak256::digest(secp_pub_raw);
    let secp_addr = &secp_hash[12..];
    println!("secp256k1 address: 0x{}", hex::encode(secp_addr));

    assert_eq!(
        k256_addr, secp_addr,
        "Address mismatch between k256 and secp256k1!"
    );
    println!("✅ Address derivation consistent between k256 and secp256k1");

    // Now test signing and verification roundtrip
    let test_payload = b"test payload for signing";
    let msg_hash = Keccak256::digest(test_payload);
    let msg_hash_arr: [u8; 32] = msg_hash.into();

    let msg = secp256k1::Message::from_digest(msg_hash_arr);
    let sig = secp.sign_ecdsa_recoverable(&msg, &sk);
    let (rec_id, sig_bytes) = sig.serialize_compact();

    // Verify we can recover the correct address
    let recovered_pk = secp.recover_ecdsa(&msg, &sig).expect("recovery");
    let recovered_bytes = recovered_pk.serialize_uncompressed();
    let recovered_hash = Keccak256::digest(&recovered_bytes[1..]);
    let recovered_addr = &recovered_hash[12..];
    println!("Recovered address: 0x{}", hex::encode(recovered_addr));
    assert_eq!(
        secp_addr, recovered_addr,
        "Recovered address doesn't match!"
    );
    println!("✅ Signature recovery works correctly");

    // Test TKS node registration
    let rpc = TksRpcClient::new("http://127.0.0.1:9944");
    assert!(rpc.is_connected(), "TKS node is not reachable");
    println!("\n✅ Node connected");

    let version = rpc.runtime_version().expect("runtime_version");
    let genesis = rpc.genesis_hash().expect("genesis_hash");
    println!(
        "spec={}, tx={}, genesis=0x{}",
        version.spec_version,
        version.transaction_version,
        hex::encode(&genesis[..8])
    );

    // Submit registration
    match rpc.submit_name_register("ninja", &k256_key) {
        Ok(tx_hash) => println!("✅ Extrinsic submitted! Hash: {}", tx_hash),
        Err(e) => {
            println!("❌ Registration failed: {}", e);
            // Don't panic, let's continue to analyze
        }
    }

    // Wait and verify
    std::thread::sleep(std::time::Duration::from_secs(6));

    match rpc.query_username("ninja") {
        Ok(Some(address)) => println!("✅ VERIFIED: @ninja -> {}", address),
        Ok(None) => println!("⚠ @ninja not found on-chain"),
        Err(e) => println!("⚠ Query error: {}", e),
    }
}

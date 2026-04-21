use rand::rngs::ThreadRng;
use rand::RngCore;
use secp256k1::schnorr::Signature;
use secp256k1::Message;
use secp256k1::Secp256k1;
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};

fn main() {
    println!("🎲 Generating Sv2 Keys...\n");

    let mut rng = ThreadRng::default();
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);

    let secret_key = secp256k1::SecretKey::from_slice(&secret_bytes).expect("Invalid secret key");

    let secp = Secp256k1::new();
    let (public_key, _) =
        secp256k1::PublicKey::from_secret_key(&secp, &secret_key).x_only_public_key();

    let sv2_secret = Secp256k1SecretKey(secret_key);
    let sv2_public = Secp256k1PublicKey(public_key);

    run_tests(&sv2_secret, &sv2_public, &secp);

    println!("\n📋 Config values:");
    println!("authority_secret_key = \"{}\"", sv2_secret);
    println!("authority_pubkey = \"{}\"", sv2_public);
}

fn run_tests(
    secret: &Secp256k1SecretKey,
    public: &Secp256k1PublicKey,
    secp: &Secp256k1<secp256k1::All>,
) {
    println!("\n✓ Running tests:");

    let secret_str = secret.to_string();
    let parsed_secret: Secp256k1SecretKey = secret_str.parse().expect("Failed to parse secret key");
    assert_eq!(parsed_secret.0.secret_bytes(), secret.0.secret_bytes());
    println!("  - Secret key parses correctly");

    let public_str = public.to_string();
    let parsed_public: Secp256k1PublicKey = public_str.parse().expect("Failed to parse public key");
    assert_eq!(parsed_public.0.serialize(), public.0.serialize());
    println!("  - Public key parses correctly");

    let derived_public: Secp256k1PublicKey = Secp256k1PublicKey::from(*secret);
    assert_eq!(derived_public.0.serialize(), public.0.serialize());
    println!("  - Derived public key matches");

    let message = Message::from_digest_slice(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ])
    .expect("Invalid message");

    let keypair = secp256k1::Keypair::from_secret_key(secp, &secret.0);
    let sig: Signature = secp.sign_schnorr(&message, &keypair);
    let verify_result = secp.verify_schnorr(&sig, &message, &public.0);
    assert!(verify_result.is_ok());
    println!("  - Signature verification passed");

    println!("\n✅ All tests passed!");
}

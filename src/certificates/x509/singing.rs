use rcgen::SignatureAlgorithm;

pub fn gen_rsa_key_pair(bits: usize) -> Result<rcgen::KeyPair, anyhow::Error> {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};

    let mut rng = rand::thread_rng();

    let rsa_private_key =
        rsa::RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pem_private = rsa_private_key
        // .to_pkcs8_encrypted_pem(LineEnding::LF)
        .to_pkcs8_pem(LineEnding::LF)
        .expect("Create PEM from private key");

    // let pem_private_encrypted = rsa_private_key
    //     .to_pkcs8_encrypted_pem(rng, "SuperSafe123", LineEnding::LF)
    //     // .to_pkcs8_pem(LineEnding::LF)
    //     .expect("Create PEM from private key");

    let key_pair = rcgen::KeyPair::from_pem(&pem_private)?;
    // debug!("key pair: {:?}", key_pair);
    Ok(key_pair)
}

pub fn gen_ecdsa_key_pair() -> Result<rcgen::KeyPair, anyhow::Error> {
    use p384::pkcs8::{EncodePrivateKey, LineEnding};

    let private_key = p384::SecretKey::random(&mut rand_core::OsRng);
    let pem = private_key
        // .to_pkcs8_encrypted_pem(LineEnding::LF)
        .to_pkcs8_pem(LineEnding::LF)
        .expect("ECDSA to pkcs8 DER");

    // let pem_enc = private_key
    //     .to_pkcs8_encrypted_pem(rng, "SuperSafe123", LineEnding::LF)
    //     // .to_pkcs8_pem(LineEnding::LF)
    //     .expect("ECDSA to pkcs8 DER");

    let key_pair = rcgen::KeyPair::from_pem(pem.as_str()).expect("KeyPair from ECDSA DER");
    // debug!("key pair: {:?}", key_pair);
    Ok(key_pair)
}

pub fn gen_ed25519_key_pair() -> Result<rcgen::KeyPair, anyhow::Error> {
    // use ed25519::pkcs8::spki::der::pem::LineEnding;
    // use ed25519::pkcs8::EncodePrivateKey;
    // use rand::rngs::OsRng;
    // Currently, ed25519 depends on rand < 0.8

    // let key_pair_raw = ed25519_dalek::Keypair::generate(&mut OsRng {});
    // let key_pair_bytes = ed25519_dalek::Key::from_bytes(&key_pair_raw.to_bytes());
    // let key_pair_bytes = ed25519::KeypairBytes::from_bytes(&key_pair_raw.to_bytes());
    // let der = key_pair_bytes
    //     .to_pkcs8_pem(LineEnding::LF)
    //     .expect("ed25519 KeyPairBytes to DER");
    let alg = SignatureAlgorithm::from_oid(&[1, 3, 101, 112])?;
    let key_pair = rcgen::KeyPair::generate(alg)?;

    // TODO this currently panics and cannot convert
    // let key_pair = rcgen::KeyPair::from_pem(der.as_str()).expect("Parsing ed25519 KeyPair");
    // debug!("key pair: {:?}", key_pair);
    Ok(key_pair)
}

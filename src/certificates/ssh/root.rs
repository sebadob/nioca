use crate::certificates::encryption::{encrypt, kdf_danger_static, prompt_password};
use crate::certificates::ssh::bootstrap::{check_out_dir, OUT_DIR_ROOT};
use crate::cli::SshOptions;
use crate::util::fingerprint;
use anyhow::Error;
use der::pem::LineEnding;
use rand_core::OsRng;
use ssh_key::PrivateKey;
use tokio::fs;

pub async fn build_root_ca(opt: &SshOptions) -> Result<(), Error> {
    println!("Building root certificate");

    let out_dir_root = format!("{}{}", opt.out_dir, OUT_DIR_ROOT);
    check_out_dir(&out_dir_root, opt, false).await?;

    // Read in passwords
    println!("Enter a new Root CA password");
    let pwd = prompt_password("Password: ")?;
    let pwd_confirm = prompt_password("Confirm Password: ")?;
    if pwd != pwd_confirm {
        return Err(Error::msg("Passwords do not match"));
    }
    if pwd.len() < 16 {
        return Err(Error::msg(
            "The password should be at least 16 characters long",
        ));
    }

    // build secret key
    let secret = kdf_danger_static(pwd.as_bytes()).await?;

    // Generate the certificate authority's KeyPair
    let key = PrivateKey::random(&mut OsRng, opt.get_alg())?;
    let pub_key = key.public_key().to_openssh().unwrap();
    let finger = fingerprint(pub_key.as_bytes());
    println!("Public Key Fingerprint: {}", finger);

    // encrypt the private key
    let key_openssh = key.to_openssh(LineEnding::LF).unwrap();
    let key_enc = encrypt(key_openssh.as_bytes(), &secret).unwrap();
    let key_enc_hex = hex::encode(&key_enc);

    // file paths
    let path_key = format!("{}/key.enc", out_dir_root);
    let path_key_hex = format!("{}/key.enc.hex", out_dir_root);
    let path_pub_key = format!("{}/key.pub", out_dir_root);
    let path_fingerprint = format!("{}/fingerprint.txt", out_dir_root);

    // save to disk
    fs::write(&path_key, &key_enc).await?;
    fs::write(&path_key_hex, &key_enc_hex).await?;
    fs::write(&path_pub_key, &pub_key).await?;
    fs::write(&path_fingerprint, &finger).await?;

    println!("Building root CA successful\n");

    Ok(())
}

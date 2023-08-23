use crate::config::EncKeys;
use crate::models::api::error_response::ErrorResponse;
use crate::models::db::enc_key::EncKeyEntity;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, PasswordHasher, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, OsRng},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum EncAlg {
    ChaCha20Poly1305,
}

impl Default for EncAlg {
    fn default() -> Self {
        Self::ChaCha20Poly1305
    }
}

impl ToString for EncAlg {
    fn to_string(&self) -> String {
        "ChaCha20Poly1305".to_string()
    }
}

impl From<String> for EncAlg {
    fn from(value: String) -> Self {
        match value.as_str() {
            "ChaCha20Poly1305" => Self::ChaCha20Poly1305,
            _ => Self::ChaCha20Poly1305,
        }
    }
}

// TODO do encryption and decryption on a dedicated thread?
pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorResponse> {
    let k = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(k);
    // 96 bits nonce is always the first bytes, if the `encrypt()` was used before
    let (n, text) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(n);
    let plaintext = cipher.decrypt(nonce, text)?;

    Ok(plaintext)
}

/// Decrypts a given ciphertext by enc key id and re-encrypts, it the current enc key id does not
/// match the active one.
pub async fn decrypt_by_kid(
    ciphertext: &[u8],
    enc_key_id: &Uuid,
    enc_keys: &EncKeys,
) -> Result<(Vec<u8>, Option<Vec<u8>>), ErrorResponse> {
    if enc_key_id != &enc_keys.enc_key.id {
        let enc_key = EncKeyEntity::find(enc_key_id, &enc_keys.master_key).await?;
        let bytes = decrypt(ciphertext, &enc_key.value)?;

        // re-encrypt with the new key
        let bytes_new = encrypt(&bytes, &enc_keys.enc_key.value)?;

        Ok((bytes, Some(bytes_new)))
    } else {
        let res = decrypt(ciphertext, &enc_keys.enc_key.value)?;
        Ok((res, None))
    }
}

// #[allow(dead_code)]
// pub fn decrypt_with_password(ciphertext: &[u8], password: &str) -> Result<Vec<u8>, ErrorResponse> {
//     let digest = digest::digest(&digest::SHA256, password.as_bytes());
//     let secret = digest.as_ref();
//     decrypt(ciphertext, secret)
// }

pub fn encrypt(plain: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorResponse> {
    let k = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(k);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plain)?;

    let mut res = nonce.to_vec();
    res.extend(ciphertext);

    Ok(res)
}

// #[allow(dead_code)]
// pub fn encrypt_with_password(plain: &[u8], password: &str) -> Result<Vec<u8>, ErrorResponse> {
//     let digest = digest::digest(&digest::SHA256, password.as_ref());
//     let secret = digest.as_ref();
//     encrypt(plain, secret)
// }

pub fn prompt_password(msg: impl ToString) -> Result<String, anyhow::Error> {
    let password = rpassword::prompt_password(msg)?;
    Ok(password)
}

/// CAUTION: This implementation MUST NOT change between versions!
/// The output must always be the same to be able to decrypt "old" certificates correctly!
///
/// The `_danger_` is on purpose -> This KDF does use a static Salt to always produce the same hash!
pub async fn kdf_danger_static(password: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let params = argon2::Params::new(262_144, 2, 8, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::encode_b64(b"12345678").unwrap();
    let pwd = password.to_vec();
    let hash = tokio::task::spawn_blocking(move || {
        anyhow::Ok(argon2.hash_password(&pwd, &salt)?.hash.unwrap())
    })
    .await??;
    let res = hash.as_bytes().to_vec();
    assert_eq!(res.len(), 32);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::secure_random;
    use pretty_assertions::assert_eq;
    use ring::digest;
    use tokio::fs;

    #[tokio::test]
    async fn test_encrypt_decrypt() -> Result<(), Box<dyn std::error::Error>> {
        // this is the mocked password read in from tty
        let password = "123SuperSafe";
        let digest = digest::digest(&digest::SHA256, password.as_ref());
        let secret = digest.as_ref();

        let rnd = secure_random(16);
        let data = rnd.as_bytes();

        // encrypt
        let enc = encrypt(data, secret).unwrap();
        assert_ne!(enc.as_slice(), data);
        // as hex
        let enc_hex = hex::encode(&enc);

        // write to file and read back in
        fs::write("./tmp", enc).await?;
        let from_file = fs::read("./tmp").await?;
        fs::write("./tmp.hex", enc_hex).await?;
        let from_file_hex = fs::read("./tmp.hex").await?;

        // decrypt
        let dec = decrypt(from_file.as_slice(), secret).unwrap();
        assert_eq!(dec.as_slice(), data);
        // from hex
        let vec_dec = hex::decode(&from_file_hex).unwrap();
        let dec_hex = decrypt(vec_dec.as_slice(), secret).unwrap();
        assert_eq!(dec_hex.as_slice(), data);

        // cleanup
        fs::remove_file("./tmp").await?;
        fs::remove_file("./tmp.hex").await?;

        Ok(())
    }
}

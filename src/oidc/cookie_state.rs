use crate::certificates::encryption::{decrypt, encrypt};
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::oidc::generate_pkce_challenge;
use crate::util::{b64_decode, b64_encode, secure_random};
use axum_extra::extract::CookieJar;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

pub(crate) static STATE_COOKIE: &str = "OIDC_STATE";
// static COOKIE_STORE_SECRET: Lazy<Vec<u8>> = Lazy::new(|| {
//     let b64 = env::var("COOKIE_STORE_SECRET").expect("COOKIE_STORE_SECRET is not set");
//     b64_decode(&b64).expect("COOKIE_STORE_SECRET cannot be decoded - no valid base64")
// });

#[derive(Serialize, Deserialize)]
pub struct OidcCookieState {
    pub nonce: String,
    pub pkce_verifier: String,
    pub state: String,
    pub timestamp: DateTime<Utc>,
}

impl OidcCookieState {
    pub fn generate() -> (Self, String) {
        let (pkce_verifier, challenge) = generate_pkce_challenge();
        let slf = Self {
            nonce: secure_random(32),
            pkce_verifier,
            state: secure_random(24),
            timestamp: Utc::now(),
        };
        (slf, challenge)
    }

    pub fn from_cookie_value(jar: &CookieJar, key: &[u8]) -> Result<Self, ErrorResponse> {
        match jar.get(STATE_COOKIE) {
            None => {
                warn!("STATE_COOKIE is missing - Request may have expired");
                Err(ErrorResponse::new(
                    ErrorResponseType::BadRequest,
                    "Request has expired".to_string(),
                ))
            }
            Some(cookie) => {
                let enc = b64_decode(cookie.value())?;
                let dec = decrypt(&enc, key)?;
                let slf = bincode::deserialize::<Self>(&dec)?;
                Ok(slf)
            }
        }
    }

    pub fn to_cookie_value(&self, key: &[u8]) -> String {
        let ser = bincode::serialize(self).unwrap();
        let enc = encrypt(&ser, key).unwrap();
        b64_encode(&enc)
    }
}

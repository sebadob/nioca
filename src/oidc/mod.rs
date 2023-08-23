use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::oidc::principal::{JwtAccessClaims, JwtIdClaims, JwtType};
use crate::oidc::validation::OIDC_CONFIG;
use crate::util::secure_random;
use base64::{engine, engine::general_purpose, Engine as _};
use ring::digest;
use tracing::error;

pub mod cookie_state;
pub mod handler;
pub mod principal;
pub mod validation;

const B64_ENGINE: engine::GeneralPurpose = general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug, PartialEq, Eq)]
pub enum CacheMethod {
    Get,
    Set,
    Exit,
}

/// Generates a secure random pkce s256 challenge and returns `(verifier, challenge)`
#[inline]
pub fn generate_pkce_challenge() -> (String, String) {
    let plain = secure_random(24);
    let s256 = digest::digest(&digest::SHA256, plain.as_bytes());
    let challenge = base64_url_encode(s256.as_ref());
    (plain, challenge)
}

/// Returns the given input as a base64 URL Encoded String
#[inline]
pub fn base64_url_encode(input: &[u8]) -> String {
    let b64 = general_purpose::STANDARD.encode(input);
    b64.chars()
        .filter_map(|c| match c {
            '=' => None,
            '+' => Some('-'),
            '/' => Some('_'),
            x => Some(x),
        })
        .collect()
}

/// Extracts the claims from a given token into a HashMap.
/// Returns an empty HashMap if no values could be extracted at all.
/// CAUTION: Does not validate the token!
pub fn extract_token_claims<T>(token: &str) -> Result<T, ErrorResponse>
where
    T: for<'a> serde::Deserialize<'a>,
{
    let body = match token.split_once('.') {
        None => None,
        Some((_metadata, rest)) => rest.split_once('.').map(|(body, _validation_str)| body),
    };
    if body.is_none() {
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Invalid or malformed JWT Token",
        ));
    }
    let body = body.unwrap();

    let b64 = match B64_ENGINE.decode(body) {
        Ok(values) => values,
        Err(err) => {
            error!(
                "Error decoding JWT token body '{}' from base64: {}",
                body, err
            );
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "Invalid JWT Token body",
            ));
        }
    };
    let s = String::from_utf8_lossy(b64.as_slice());
    let claims = match serde_json::from_str::<T>(s.as_ref()) {
        Ok(claims) => claims,
        Err(err) => {
            error!("Error deserializing JWT Token claims: {}", err);
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "Invalid JWT Token claims",
            ));
        }
    };

    Ok(claims)
}

pub async fn validate_access_claims(claims: &JwtAccessClaims) -> Result<(), ErrorResponse> {
    if claims.typ != JwtType::Bearer {
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Must provide an access token".to_string(),
        ));
    }

    let config = OIDC_CONFIG.read().await;
    if config.is_none() {
        return Err(ErrorResponse::new(
            ErrorResponseType::Internal,
            "OIDC Provider has not been initialized yet".to_string(),
        ));
    }
    let config = config.as_ref().unwrap();

    if claims.iss != config.iss {
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Wrong JWT token issuer".to_string(),
        ));
    }
    if claims.aud != config.aud {
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Wrong JWT token audience".to_string(),
        ));
    }

    Ok(())
}

pub async fn validate_id_claims(claims: &JwtIdClaims, nonce: &str) -> Result<(), ErrorResponse> {
    if claims.typ != JwtType::Id {
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Must provide an id token".to_string(),
        ));
    }
    {
        let config = OIDC_CONFIG.read().await;
        if config.is_none() {
            return Err(ErrorResponse::new(
                ErrorResponseType::Internal,
                "OIDC Provider has not been initialized yet".to_string(),
            ));
        }
        let config = config.as_ref().unwrap();

        if claims.iss != config.iss {
            return Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "Wrong JWT token issuer".to_string(),
            ));
        }
        if claims.aud != config.aud {
            return Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "Wrong JWT token audience".to_string(),
            ));
        }
        if config.email_verified && claims.email_verified != Some(true) {
            return Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "'email_verified' is missing or false".to_string(),
            ));
        }
        if claims.nonce.as_deref() != Some(nonce) {
            return Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "'nonce' is not correct".to_string(),
            ));
        }
    }

    Ok(())
}

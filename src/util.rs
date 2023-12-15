use crate::constants::{
    DEV_MODE, MAX_SESSION_TIME, SESSION_COOKIE, SESSION_COOKIE_XSRF, SESSION_COOKIE_XSRF_LIFESPAN,
};
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use base64::{engine::general_purpose, DecodeError, Engine as _};
use der::Document;
use rand::{distributions, Rng};
use std::fmt::Write;
use std::str::FromStr;
use tracing::{error, warn};
use uuid::Uuid;

#[allow(dead_code)]
pub fn b64_decode(value: &str) -> Result<Vec<u8>, DecodeError> {
    let b = general_purpose::STANDARD.decode(value)?;
    Ok(b)
}

pub fn b64_encode(value: &[u8]) -> String {
    general_purpose::STANDARD.encode(value)
}

pub fn build_session_cookie<'a>(sid: String) -> Cookie<'a> {
    if *DEV_MODE {
        warn!("Building an INSECURE cookie - DO NOT USE IN PRODUCTION");
        Cookie::build((SESSION_COOKIE, sid))
            .path("/api")
            .secure(false)
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(MAX_SESSION_TIME)
            .build()
    } else {
        Cookie::build((SESSION_COOKIE, sid))
            .path("/api")
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(MAX_SESSION_TIME)
            .build()
    }
}

pub fn build_session_cookie_xsrf<'a>(xsrf: String) -> Cookie<'a> {
    if *DEV_MODE {
        warn!("Building an INSECURE cookie - DO NOT USE IN PRODUCTION");
        Cookie::build((SESSION_COOKIE_XSRF, xsrf))
            .path("/")
            .secure(false)
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(SESSION_COOKIE_XSRF_LIFESPAN)
            .build()
    } else {
        Cookie::build((SESSION_COOKIE_XSRF, xsrf))
            .path("/")
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(SESSION_COOKIE_XSRF_LIFESPAN)
            .build()
    }
}

pub fn delete_session_cookie_xsrf<'a>() -> Cookie<'a> {
    Cookie::build((SESSION_COOKIE_XSRF, ""))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(1))
        .build()
}

pub fn csv_to_vec(value: &str) -> Vec<String> {
    let values = value.split(',');
    let mut res = Vec::with_capacity(4);
    values.for_each(|v| res.push(v.trim().to_string()));
    res
}

pub fn fingerprint(value: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, value);
    let fingerprint = hex::encode(digest.as_ref());
    let fingerprint_full = format!("sha256:{}", fingerprint);
    fingerprint_full
}

pub fn get_rand_between(start: u64, end: u64) -> u64 {
    let mut rng = rand::thread_rng();
    rng.gen_range(start..end)
}

pub fn get_session_cookie(jar: &CookieJar) -> Result<Uuid, ErrorResponse> {
    let cookie = match jar.get(SESSION_COOKIE) {
        Some(c) => c,
        None => {
            return Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "Session not found".to_string(),
            ));
        }
    };

    let sid = match Uuid::from_str(cookie.value()) {
        Ok(uuid) => uuid,
        Err(err) => {
            error!("{}", err);
            return Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "Malformed Session Cookie".to_string(),
            ));
        }
    };

    Ok(sid)
}

pub fn pem_to_der(pem: &str) -> Result<Document, ErrorResponse> {
    match Document::from_pem(pem) {
        Ok(der) => Ok(der.1),
        Err(err) => {
            error!("{}", err);
            Err(ErrorResponse::from(err))
        }
    }
}

pub fn vec_to_csv(values: &[String]) -> String {
    let mut res = String::new();
    values.iter().for_each(|v| {
        if res.is_empty() {
            write!(&mut res, "{}", v).expect("converting vec to csv");
        } else {
            write!(&mut res, ",{}", v).expect("converting vec to csv");
        }
    });
    res
}

pub fn secure_random(count: usize) -> String {
    rand::thread_rng()
        .sample_iter(&distributions::Alphanumeric)
        .take(count)
        .map(char::from)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use ring::digest;
    use tokio::fs;

    #[tokio::test]
    async fn test_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
        // this is the mocked password read in from tty
        let data = "-----BEGIN CERTIFICATE-----
MIIB0zCCAVqgAwIBAgIJAMT8pCIIgDxAMAoGCCqGSM49BAMDMC4xEzARBgNVBAMM
Ck5pb2NhIFJvb3QxFzAVBgNVBAoMDk5ldElULVNlcnZpY2VzMCAXDTIxMTAwNDIx
MjIwNFoYDzIwNTMwMjA4MTQxMjA0WjAuMRMwEQYDVQQDDApOaW9jYSBSb290MRcw
FQYDVQQKDA5OZXRJVC1TZXJ2aWNlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABI5x
DRP95epg59iEUed78w7SDmyEzrk7o3GpkbiUnduUmIv1ecJ51orrYDtCYuu0eOnu
MQGSgbHx4kTO0x3h5t3kepngV3ZuxTAIUEbcnx6uNFsn/LBnWdzT57AqR7xA06NC
MEAwDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBRAPIAIIqT8xIWL1MH6gYCneVZr
1DAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMDA2cAMGQCMF6lIH80Ixpv3WIZ
lrKvR1lElDgw04Of2NxM1Sorvclwlkh96ZkbS/ikFomkJ9wi/QIwcBcnokSFK5a5
zTQweD8qKBECdi7DYHDUahNaQiTCLyXFPXa5QfDMQetyMfM3R8pA
-----END CERTIFICATE-----";

        // write to file and read back in
        fs::write("./tmp.finger", data.as_bytes()).await?;
        let from_file = fs::read("./tmp.finger").await?;

        // direct hash
        let digest = digest::digest(&digest::SHA256, data.as_bytes());
        let finger_slice = digest.as_ref();

        let digest_file = digest::digest(&digest::SHA256, from_file.as_slice());
        let finger_slice_file = digest_file.as_ref();

        assert_eq!(finger_slice, finger_slice_file);

        // fingerprinting function
        let finger_fn = fingerprint(data.as_bytes());
        let finger_fn_file = fingerprint(from_file.as_slice());

        assert_eq!(finger_fn, finger_fn_file);

        // cleanup
        fs::remove_file("./tmp.finger").await?;

        Ok(())
    }
}

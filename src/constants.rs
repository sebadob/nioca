use axum::http::header;
use once_cell::sync::Lazy;
use regex::Regex;
use std::env;
use std::string::ToString;
use uuid::Uuid;

pub const DEV_MODE_OIDC_REDIRECT: &str = "http://localhost:5173";

pub const MAX_SESSION_TIME: time::Duration = time::Duration::hours(2);
pub const SESSION_COOKIE: &str = "nioca_session";
pub const SESSION_COOKIE_XSRF: &str = "nioca_session_xsrf";
pub const SESSION_COOKIE_XSRF_LIFESPAN: time::Duration = time::Duration::seconds(30);
pub const SESSION_TIMEOUT: time::Duration = time::Duration::minutes(15);
pub const SESSION_TIMEOUT_NEW: time::Duration = time::Duration::minutes(3);

pub const XSRF_HEADER: &str = "X-NIOCA-XSRF";

pub const TOKEN_CACHE_LIFESPAN: u64 = 30;

pub static DEV_MODE: Lazy<bool> = Lazy::new(|| {
    env::var("DEV_MODE")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .expect("DEV_MODE cannot be parsed to bool")
});
pub static AUTO_UNSEAL: Lazy<bool> = Lazy::new(|| {
    env::var("AUTO_UNSEAL")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .expect("AUTO_UNSEAL cannot be parsed to bool")
});

pub static UNSEAL_RATE_LIMIT: Lazy<u32> = Lazy::new(|| {
    env::var("UNSEAL_RATE_LIMIT")
        .unwrap_or_else(|_| "10".to_string())
        .parse::<u32>()
        .expect("UNSEAL_RATE_LIMIT cannot be parsed to u32")
});

// The public url for direct access in case of a HA deployment behind a load balancer
pub static DIRECT_ACCESS_PUB_URL: Lazy<Option<String>> =
    Lazy::new(|| match env::var("DIRECT_ACCESS_PUB_URL") {
        Ok(url) => Some(url),
        Err(_) => None,
    });

pub static INSTANCE_UUID: Lazy<Uuid> = Lazy::new(Uuid::new_v4);

pub static PUB_URL: Lazy<String> = Lazy::new(|| env::var("PUB_URL").expect("PUB_URL is not set"));

pub static PUB_URL_WITH_SCHEME: Lazy<String> = Lazy::new(|| {
    let url = &*PUB_URL;
    let without_scheme = if let Some((_, url)) = url.split_once("://") {
        url
    } else {
        url
    };
    // we will never allow access via http
    if !*DEV_MODE {
        format!("https://{}", without_scheme)
    } else {
        format!("http://{}", without_scheme)
    }
});

pub static PUB_URL_FULL: Lazy<String> = Lazy::new(|| {
    let pub_port = if *DEV_MODE {
        "8080".to_string()
    } else {
        env::var("PORT_HTTPS_PUB").unwrap_or_else(|_| "8443".to_string())
    };
    if &pub_port != "443" {
        format!("{}:{}", *PUB_URL_WITH_SCHEME, pub_port)
    } else {
        (*PUB_URL_WITH_SCHEME).clone()
    }
});

pub static OIDC_CALLBACK_URI: Lazy<String> =
    Lazy::new(|| format!("{}/api/oidc/callback", *PUB_URL_FULL));

pub const HEADER_OCTET_STREAM: [(headers::HeaderName, &str); 2] = [
    (header::CONTENT_TYPE, "application/octet-stream"),
    (
        header::CONTENT_DISPOSITION,
        "attachment; filename=\"x509.p12\"",
    ),
];

pub static RE_CA_NAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9\-_.\s]+$").unwrap());
pub static RE_CLIENT_NAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9\-_.\s]+$").unwrap());
pub static RE_JWT_CLAIM: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9-_/,]{2,32}$").unwrap());
pub static RE_JWT_SCOPE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9-_/,\s]{2,32}$").unwrap());
pub static RE_HEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-fA-F0-9]+$").unwrap());
pub static RE_INIT_KEY: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9]{0,128}$").unwrap());
pub static RE_LINUX_USER: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9-_@.]{2,30}$").unwrap());
// Lazy::new(|| Regex::new(r"^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)$").unwrap());
pub static RE_MASTER_SHARD_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9]{48}$").unwrap());
pub static RE_XSRF: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9]{48}$").unwrap());

// X509 validation regexes
pub static RE_SUBJECT_NAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9.*-]+$").unwrap());
pub static RE_SUBJECT_NAME_OPT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9-.*\s]+$").unwrap());
pub static RE_DNS_SIMPLE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[a-zA-Z0-9.\-*]+").unwrap());

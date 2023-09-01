use crate::constants::OIDC_CALLBACK_URI;
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::db::config_oidc::{ConfigOidcEntity, JwtClaim};
use crate::oidc::CacheMethod;
use crate::VERSION;
use cached::{Cached, TimedCache};
use once_cell::sync::Lazy;
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use std::string::ToString;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{oneshot, RwLock};
use tracing::{debug, error, info, warn};

pub(crate) static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

pub(crate) static OIDC_CONFIG: Lazy<RwLock<Option<OidcConfig>>> = Lazy::new(|| RwLock::new(None));
pub(crate) static USERINFO_URL: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    pub aud: String,
    pub auth_url_base: String,
    pub client_id: String,
    pub email_verified: bool,
    pub iss: String,
    pub oidc_config_url: String,
    pub provider: OidcProvider,
    pub redirect_uri: String,
    pub secret: String,
    pub admin_claim: Option<JwtClaim>,
    pub user_claim: Option<JwtClaim>,
}

impl OidcConfig {
    pub async fn from_db_entity(entity: ConfigOidcEntity) -> anyhow::Result<Self> {
        let callback_url = OIDC_CALLBACK_URI.replace(':', "%3A").replace('/', "%2F");
        let scope = entity.scope.replace(' ', "+");
        Self::build_from_values(
            callback_url,
            entity.iss,
            scope,
            entity.client_id,
            entity.aud,
            entity.email_verified,
            entity.secret,
            entity.admin_claim,
            entity.user_claim,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn build_from_values(
        redirect_uri: String,
        iss: String,
        scope: String,
        client_id: String,
        aud: String,
        email_verified: bool,
        secret: String,
        admin_claim: Option<JwtClaim>,
        user_claim: Option<JwtClaim>,
    ) -> anyhow::Result<Self> {
        let append = if iss.ends_with('/') {
            ".well-known/openid-configuration"
        } else {
            "/.well-known/openid-configuration"
        };
        let oidc_config_url = format!("{}{}", iss, append);
        let provider = OidcProvider::fetch(&oidc_config_url).await?;

        let auth_endpoint = &provider.authorization_endpoint;
        let auth_url_base = format!(
            "{auth_endpoint}?client_id={client_id}&redirect_uri={redirect_uri}&\
            response_type=code&code_challenge_method=S256&scope={scope}"
        );

        Ok(Self {
            aud,
            auth_url_base,
            client_id,
            email_verified,
            iss,
            oidc_config_url,
            provider,
            redirect_uri,
            secret,
            admin_claim,
            user_claim,
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcProvider {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub introspection_endpoint: String,
    pub userinfo_endpoint: String,
    pub end_session_endpoint: String,
    pub jwks_uri: String,
    // pub registration_endpoint: String,
    // pub check_session_iframe: String,
    pub grant_types_supported: Vec<Flows>,
    pub response_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<Algorithm>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<Algorithm>,
    pub claims_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<Challenge>,
}

impl OidcProvider {
    pub async fn fetch(oidc_config_endpoint: &str) -> anyhow::Result<Self> {
        let res = Self::client()
            .get(oidc_config_endpoint)
            .send()
            .await?
            .json::<Self>()
            .await?;

        // panic, if s256 pkce challenges are not supported
        if res.code_challenge_methods_supported.is_empty()
            || !res
                .code_challenge_methods_supported
                .contains(&Challenge::S256)
        {
            panic!("The given OidcProvider does not support S256 challenges - exiting");
        }

        Ok(res)
    }

    pub fn init_client(root_certificate: reqwest::Certificate) {
        CLIENT.get_or_init(|| {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(10))
                .https_only(true)
                .user_agent(format!("Rusty OIDC Client v{}", VERSION))
                .brotli(true)
                .http2_prior_knowledge()
                .add_root_certificate(root_certificate)
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap()
        });
    }

    pub fn client<'a>() -> &'a reqwest::Client {
        CLIENT.get().expect(
            "OIDC Client has not been initialized - run OidcProvider::init_client() at startup",
        )
    }
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    RS256,
    RS384,
    RS512,
    EdDSA,
}

#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Challenge {
    plain,
    S256,
}

#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Flows {
    authorization_code,
    client_credentials,
    password,
    refresh_token,
}

/// Used internally to cache token validation requests for a short amount of time
#[derive(Debug)]
pub struct TokenCacheReq {
    pub key: String,
    pub method: CacheMethod,
    pub resp: Option<oneshot::Sender<TokenCacheResp>>,
    pub value: Option<Result<(), ErrorResponse>>,
}

impl TokenCacheReq {
    pub fn from_token(
        token: &str,
        method: CacheMethod,
        value: Option<Result<(), ErrorResponse>>,
    ) -> Option<(Self, Option<oneshot::Receiver<TokenCacheResp>>)> {
        match token.split_once('.') {
            None => None,
            Some((_metadata, rest)) => match rest.split_once('.') {
                None => None,
                Some((_body, validation_str)) => {
                    if method == CacheMethod::Get {
                        let (tx, rx) = oneshot::channel();
                        let req = Self {
                            key: validation_str.to_string(),
                            method,
                            resp: Some(tx),
                            value,
                        };
                        Some((req, Some(rx)))
                    } else {
                        let req = Self {
                            key: validation_str.to_string(),
                            method,
                            resp: None,
                            value,
                        };
                        Some((req, None))
                    }
                }
            },
        }
    }
}

/// Used internally to cache token validation requests for a short amount of time
#[derive(Debug)]
pub struct TokenCacheResp {
    pub result: Option<Result<(), ErrorResponse>>,
}

/// Spawns the token validation cache
pub async fn init(
    config: OidcConfig,
    cache_lifespan: u64,
) -> anyhow::Result<flume::Sender<TokenCacheReq>> {
    info!("Initializing the Token Validation Cache");

    {
        let mut lock = USERINFO_URL.write().await;
        *lock = Some(config.provider.userinfo_endpoint.clone());
    }
    {
        let mut lock = OIDC_CONFIG.write().await;
        *lock = Some(config);
    }

    let (tx, rx) = flume::unbounded::<TokenCacheReq>();

    tokio::spawn(async move {
        let mut cache: TimedCache<String, Result<(), ErrorResponse>> =
            TimedCache::with_lifespan(cache_lifespan);

        while let Ok(req) = rx.recv_async().await {
            match req.method {
                CacheMethod::Get => {
                    if let Some(entry) = cache.cache_get(&req.key) {
                        debug!(
                            "Found cached token validation response for key {}",
                            &req.key
                        );
                        let channel: oneshot::Sender<TokenCacheResp> = req.resp.unwrap();
                        if let Err(err) = channel.send(TokenCacheResp {
                            result: Some(entry.clone()),
                        }) {
                            error!("Error sending cache result over channel: {:?}", err);
                        }
                    }
                }

                CacheMethod::Set => {
                    debug!("Setting new token cache response for key {}", &req.key);
                    cache.cache_set(req.key, req.value.unwrap());
                }

                CacheMethod::Exit => {
                    warn!("Received CacheMethod::Exit - exiting TokenCache");
                    if let Some(tx) = req.resp {
                        tx.send(TokenCacheResp { result: None }).unwrap();
                    }
                    break;
                }
            }
        }
    });

    Ok(tx)
}

/// Used internally for serializing user-service requests
#[derive(Debug, Clone, ::serde::Serialize)]
struct TokenValidationBody {
    pub token: String,
}

/// Used internally for deserializing user-service responses
#[allow(dead_code)]
#[derive(Debug, Clone, ::serde::Deserialize)]
struct TokenValidationResponse {
    access_token: String,
    expires_in: String,
    refresh_token: String,
}

/// Validates a `Bearer` token from the `Authorization` Header
pub async fn validate_token(
    token: String,
    tx: &Arc<flume::Sender<TokenCacheReq>>,
) -> Result<(), ErrorResponse> {
    debug!("Executing validate_token");

    // check the cache first
    if let Some((req, rx)) = TokenCacheReq::from_token(&token, CacheMethod::Get, None) {
        if let Err(err) = tx.send_async(req).await {
            let msg = format!("Error sending cache request over channel: {}", err);
            error!("{}", msg);
            return Err(ErrorResponse::new(ErrorResponseType::Internal, msg));
        }

        if let Ok(res) = rx.unwrap().await {
            if let Some(resp) = res.result {
                debug!("Found cached token validation response");
                return resp;
            }
        }
    } else {
        // If the `TokenCacheReq::from_token` returns None, the Token is malformed -> return early
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Malformed JWT Token".to_string(),
        ));
    }

    let res = {
        let info = USERINFO_URL.read().await;
        if info.is_none() {
            return Err(ErrorResponse::new(
                ErrorResponseType::Internal,
                "USERINFO_URL has not been initialized yet".to_string(),
            ));
        }
        let url = info.as_ref().unwrap();

        // build the client inside and await outside to use the url as ref but not lock too long
        // while awaiting the result
        OidcProvider::client()
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .send()
    }
    .await?;

    let res = if res.status().as_u16() < 300 {
        Ok(())
    } else {
        info!("Token Validation Response: {:?}", res);
        Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Invalid JWT Token".to_string(),
        ))
    };

    // set the result in the cache
    // unwrap is safe here, since we already know, that the token is correctly formed
    let (req, _rx) =
        TokenCacheReq::from_token(&token, CacheMethod::Set, Some(res.clone())).unwrap();
    if let Err(err) = tx.send_async(req).await {
        error!(
            "Error setting token validation request in the cache: {}",
            err
        );
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tracing::info;

    fn tracing() {
        dotenvy::dotenv().ok();
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::INFO)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    #[ignore]
    #[tokio::test]
    async fn hello_oidc() {
        tracing();

        let provider = OidcProvider::fetch("").await.unwrap();
        info!("{:?}", provider);

        assert_eq!(1, 2);
    }
}

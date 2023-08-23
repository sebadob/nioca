use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::oidc::cookie_state::{OidcCookieState, STATE_COOKIE};
use crate::oidc::principal::{JwtAccessClaims, JwtIdClaims, PrincipalOidc};
use crate::oidc::validation::{CLIENT, OIDC_CONFIG};
use crate::oidc::{extract_token_claims, validate_access_claims, validate_id_claims};
use axum::body::Body;
use axum::extract::Query;
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use utoipa::IntoParams;

#[derive(Debug, Deserialize, IntoParams)]
pub struct OidcCallbackParams {
    code: String,
    state: String,
}

#[derive(Debug, Serialize)]
struct OidcCodeRequestParams {
    client_id: String,
    client_secret: String,
    code: String,
    code_verifier: String,
    grant_type: &'static str,
    redirect_uri: String,
}

impl OidcCodeRequestParams {
    pub async fn new(code: String, code_verifier: String, redirect_uri: String) -> Self {
        let lock = OIDC_CONFIG.read().await;
        let cfg = lock.as_ref().unwrap();
        let client_id = cfg.client_id.clone();
        let client_secret = cfg.secret.clone();
        Self {
            client_id,
            client_secret,
            code,
            code_verifier,
            grant_type: "authorization_code",
            redirect_uri,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcTokenSet {
    pub access_token: String,
    pub token_type: Option<String>,
    pub id_token: Option<String>,
    pub expires_in: i32,
    pub refresh_token: Option<String>,
}

/// Check the authentication
///
/// Extracts the `Bearer` token from the `Authorization` header. It redirects to the OIDC login if
/// the token is not valid.
pub async fn validate_redirect_principal(
    principal: Option<PrincipalOidc>,
    enc_key: &[u8],
    insecure: bool,
    redirect: bool,
) -> Response<Body> {
    if principal.is_some() {
        Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(Body::empty())
            .unwrap()
    } else {
        let (cookie_state, challenge) = OidcCookieState::generate();
        let loc = {
            let lock = OIDC_CONFIG.read().await;
            let base = &lock.as_ref().unwrap().auth_url_base;
            format!(
                "{base}&code_challenge={challenge}&nonce={}&state={}",
                cookie_state.nonce, cookie_state.state
            )
        };

        let value = cookie_state.to_cookie_value(enc_key);
        let mut builder = Cookie::build(STATE_COOKIE, value)
            .path("/")
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(time::Duration::seconds(300));
        builder = if insecure {
            warn!("Building an INSECURE cookie - DO NOT USE IN PRODUCTION");
            builder.secure(false)
        } else {
            builder.secure(true)
        };
        let cookie = builder.finish().to_string();

        let code = if redirect { 302 } else { 200 };
        Response::builder()
            .status(code)
            .header(header::LOCATION, loc)
            .header(header::SET_COOKIE, cookie)
            .body(Body::empty())
            .unwrap()
    }
}

/// Handles the OIDC callback
pub async fn oidc_callback(
    jar: &CookieJar,
    params: Query<OidcCallbackParams>,
    enc_key: &[u8],
    insecure: bool,
) -> Result<(CookieJar, OidcTokenSet, JwtIdClaims), ErrorResponse> {
    let cookie_state = OidcCookieState::from_cookie_value(jar, enc_key)?;
    // validate the state to prevent xsrf attacks
    if params.state != cookie_state.state {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Bad state".to_string(),
        ));
    }

    let (token_uri, redirect_uri) = {
        let lock = OIDC_CONFIG.read().await;
        let cfg = lock.as_ref().unwrap();
        let t = cfg.provider.token_endpoint.clone();
        let r = cfg.redirect_uri.clone();
        (t, r)
    };
    let req_data = OidcCodeRequestParams::new(
        params.code.clone(),
        cookie_state.pkce_verifier,
        redirect_uri,
    )
    .await;

    let res = CLIENT.post(&token_uri).form(&req_data).send().await?;
    if res.status().as_u16() >= 300 {
        error!("{:?}", res);
        let body = res.text().await;
        let msg = match body {
            Ok(value) => {
                error!("raw OIDC provider response: {:?}", value);
                value
            }
            Err(_) => "Internal Error - Bad response status".to_string(),
        };

        Err(ErrorResponse::new(ErrorResponseType::Internal, msg))
    } else {
        match res.json::<OidcTokenSet>().await {
            Ok(ts) => {
                // validate access token
                let access_claims = extract_token_claims::<JwtAccessClaims>(&ts.access_token)?;
                validate_access_claims(&access_claims).await?;

                // validate id token
                if ts.id_token.is_none() {
                    return Err(ErrorResponse::new(
                        ErrorResponseType::InvalidToken,
                        "ID token is missing".to_string(),
                    ));
                }
                let id_claims = extract_token_claims::<JwtIdClaims>(ts.id_token.as_ref().unwrap())?;
                validate_id_claims(&id_claims, &cookie_state.nonce).await?;

                // reset STATE_COOKIE
                let mut builder = Cookie::build(STATE_COOKIE, "")
                    .path("/")
                    .http_only(true)
                    .same_site(SameSite::Lax)
                    .max_age(time::Duration::seconds(1));
                builder = if insecure {
                    warn!("Building an INSECURE cookie - DO NOT USE IN PRODUCTION");
                    builder.secure(false)
                } else {
                    builder.secure(true)
                };
                let cookie = builder.finish();
                let jar = CookieJar::new().add(cookie);

                Ok((jar, ts, id_claims))
            }
            Err(err) => {
                error!("Deserializing OIDC response to OidcTokenSet: {}", err);
                Err(ErrorResponse::new(
                    ErrorResponseType::Internal,
                    "Internal Error - Deserializing OIDC response".to_string(),
                ))
            }
        }
    }
}
//
// #[cfg(test)]
// mod tests {
//     const KEY: &str = "bQMr84TTHCz2YGt57rjgBNu5PLs8A8fz";
//
//     fn setup_logging() {
//         dotenv::dotenv().ok();
//         let subscriber = tracing_subscriber::FmtSubscriber::builder()
//             .with_max_level(tracing::Level::DEBUG)
//             .finish();
//         tracing::subscriber::set_global_default(subscriber)
//             .expect("setting default subscriber failed");
//     }
//
//     #[tokio::test]
//     async fn test_validate_redirect_principal() -> anyhow::Result<()> {
//         setup_logging();
//
//         let redirect_uri = "http://localhost:8080/oidc/callback".to_string();
//         let config = OidcConfig::from_(redirect_uri).await?;
//         let _tx = init(config, 10).await?;
//
//         let resp = validate_redirect_principal(None, KEY.as_bytes(), false, true).await;
//         assert_eq!(resp.status().as_u16(), 302);
//
//         let headers = resp.headers();
//         let loc = headers.get(header::LOCATION).unwrap();
//         assert!(!loc.is_empty());
//         debug!("{:?}", loc);
//         debug!("{}", loc.to_str().unwrap());
//         assert!(loc
//             .to_str()
//             .unwrap()
//             .starts_with("https://auth.meteo.netitservices.com/auth/v1"));
//
//         Ok(())
//     }
// }

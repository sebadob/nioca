use crate::constants::{DEV_MODE, DEV_MODE_OIDC_REDIRECT, PUB_URL_FULL, TOKEN_CACHE_LIFESPAN};
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::api::principal::Principal;
use crate::models::api::request::ConfigOidcEntityRequest;
use crate::models::api::response::ConfigOidcEntityResponse;
use crate::models::db::config_oidc::ConfigOidcEntity;
use crate::models::db::session::SessionEntity;
use crate::oidc::cookie_state::STATE_COOKIE;
use crate::oidc::handler as oidc_handler;
use crate::oidc::handler::OidcCallbackParams;
use crate::oidc::principal::PrincipalOidc;
use crate::oidc::validation::{OidcConfig, TokenCacheReq};
use crate::oidc::{validation, CacheMethod};
use crate::routes::AppStateExtract;
use crate::util::{build_session_cookie, build_session_cookie_xsrf};
use axum::body::Body;
use axum::extract::Query;
use axum::http::header;
use axum::response::Response;
use axum::Json;
use axum_extra::extract::CookieJar;
use tokio::sync::oneshot;
use tracing::{error, info};
use validator::Validate;

/// Get information if OIDC is configured
#[utoipa::path(
    get,
    tag = "oidc",
    path = "/api/oidc/exists",
    responses(
        (status = 200, description = "Ok"),
        (status = 404, description = "NotFound", body = ErrorResponse),
    ),
)]
pub async fn get_oidc_exists(state: AppStateExtract) -> Result<(), ErrorResponse> {
    let exists = state.read().await.tx_token_cache.is_some();
    if exists {
        Ok(())
    } else {
        Err(ErrorResponse::new(
            ErrorResponseType::NotFound,
            "OIDC is not configured".to_string(),
        ))
    }
}

/// OIDC Auth check and login
///
/// Endpoint with no redirect on purpose to use the result inside Javascript from the frontend.
/// HTTP 200 will have a location header and a manual redirect must be done
/// HTTP 202 means logged in Principal
#[utoipa::path(
    get,
    tag = "oidc",
    path = "/api/oidc/auth",
    responses(
        (status = 200, description = "Ok"),
        (status = 202, description = "Accepted"),
    ),
)]
pub async fn get_oidc_auth(
    state: AppStateExtract,
    principal: Option<PrincipalOidc>,
) -> Response<Body> {
    let enc_key = state.read().await.enc_keys.enc_key.value.clone();
    if *DEV_MODE {
        oidc_handler::validate_redirect_principal(principal, &enc_key, true, false).await
    } else {
        oidc_handler::validate_redirect_principal(principal, &enc_key, false, false).await
    }
}

/// OIDC Auth check and login
///
/// Endpoint with redirect if the user is not logged in
#[utoipa::path(
    get,
    tag = "oidc",
    path = "/api/oidc/auth/redirect",
    responses(
        (status = 202, description = "Accepted"),
        (status = 302, description = "TemporarilyMoved"),
    ),
)]
pub async fn get_oidc_auth_redirect(
    state: AppStateExtract,
    principal: Option<PrincipalOidc>,
) -> Response<Body> {
    let enc_key = state.read().await.enc_keys.enc_key.value.clone();
    if *DEV_MODE {
        oidc_handler::validate_redirect_principal(principal, &enc_key, true, true).await
    } else {
        oidc_handler::validate_redirect_principal(principal, &enc_key, false, true).await
    }
}

/// OIDC Callback
#[utoipa::path(
    get,
    tag = "oidc",
    path = "/api/oidc/callback",
    params(OidcCallbackParams),
    responses(
        (status = 200, description = "Ok"),
    ),
)]
pub async fn get_oidc_callback(
    jar: CookieJar,
    params: Query<OidcCallbackParams>,
    state: AppStateExtract,
) -> Result<Response<Body>, ErrorResponse> {
    let enc_key_entity = state.read().await.enc_keys.enc_key.clone();

    let (jar, _token_set, id_claims) = if *DEV_MODE {
        oidc_handler::oidc_callback(&jar, params, &enc_key_entity.value, true).await?
    } else {
        oidc_handler::oidc_callback(&jar, params, &enc_key_entity.value, false).await?
    };

    let (session, xsrf) = SessionEntity::from_id_claims(id_claims).await?;
    tracing::warn!("\n\nxsrf in oidc callback: {}\n", xsrf);
    let session_cookie = build_session_cookie(session.id.to_string());
    let session_cookie_xsrf = build_session_cookie_xsrf(xsrf);

    let redirect_url = if *DEV_MODE {
        DEV_MODE_OIDC_REDIRECT
    } else {
        &*PUB_URL_FULL
    };

    Ok(Response::builder()
        .status(302)
        .header(header::LOCATION, redirect_url)
        .header(
            header::SET_COOKIE,
            jar.get(STATE_COOKIE).unwrap().to_string(),
        )
        .header(header::SET_COOKIE, session_cookie.to_string())
        .header(header::SET_COOKIE, session_cookie_xsrf.to_string())
        .body(Body::empty())
        .unwrap())
}

/// Get OIDC config
#[utoipa::path(
    get,
    tag = "oidc",
    path = "/api/oidc/config",
    responses(
        (status = 200, description = "Ok", body = ConfigOidcEntity),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn get_config_oidc(
    state: AppStateExtract,
    principal: Principal,
) -> Result<Json<ConfigOidcEntityResponse>, ErrorResponse> {
    principal.is_admin()?;

    let enc_keys = state.read().await.enc_keys.clone();
    let res = ConfigOidcEntity::find(&enc_keys).await?;
    let resp = ConfigOidcEntityResponse::from(res);
    Ok(Json(resp))
}

/// Update OIDC config
#[utoipa::path(
    put,
    tag = "oidc",
    path = "/api/oidc/config",
    request_body = ConfigOidcEntityRequest,
    responses(
        (status = 200, description = "Ok"),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn put_config_oidc(
    state: AppStateExtract,
    principal: Principal,
    Json(payload): Json<ConfigOidcEntityRequest>,
) -> Result<(), ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    // try to build the entity first and check the connection
    let entity = ConfigOidcEntity::from(payload);
    // If this config builds fine, the OidcProvider is reachable and supports the correct values
    let config = match OidcConfig::from_db_entity(entity.clone()).await {
        Ok(c) => c,
        Err(err) => {
            let msg = "OIDC automatic config lookup failure".to_string();
            error!("{}: {}", msg, err);
            return Err(ErrorResponse::new(ErrorResponseType::Connection, msg));
        }
    };

    // Persist the new config
    let enc_keys = state.read().await.enc_keys.clone();
    entity.save(&enc_keys).await?;

    // stop any possibly running token cache
    if let Some(tx) = &state.read().await.tx_token_cache {
        let (tx_one, rx_one) = oneshot::channel();
        tx.send_async(TokenCacheReq {
            key: String::default(),
            method: CacheMethod::Exit,
            resp: Some(tx_one),
            value: None,
        })
        .await
        .expect("Bad Config - No TokenCacheReq receiver");

        // we don't care about the result, just the ack
        let _ = rx_one.await;
        info!("Current TokenCache has been stopped");
    }

    // Start a new TokenCache instance with the new config
    let tx = validation::init(config, TOKEN_CACHE_LIFESPAN).await?;
    state.write().await.tx_token_cache = Some(tx);

    Ok(())
}

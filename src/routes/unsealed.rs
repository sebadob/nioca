use crate::constants::{PUB_URL, SESSION_COOKIE, SESSION_COOKIE_XSRF, UNSEAL_RATE_LIMIT};
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::api::principal::Principal;
use crate::models::api::request::{LoginRequest, PasswordChangeRequest};
use crate::models::api::response::{AuthCheckResponse, SealedStatus, SessionResponse};
use crate::models::db::master_key::MasterKeyRow;
use crate::models::db::session::SessionEntity;
use crate::routes::AppStateExtract;
use crate::service::password_hasher::{ComparePasswords, HashPassword};
use crate::util::{build_session_cookie, delete_session_cookie_xsrf, get_session_cookie};
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::{Json, TypedHeader};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;
use validator::Validate;

/// Local Database login
#[utoipa::path(
    post,
    tag = "unsealed",
    path = "/api/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Ok"),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn post_login(
    jar: CookieJar,
    state: AppStateExtract,
    TypedHeader(xsrf): TypedHeader<Authorization<Bearer>>,
    Json(payload): Json<LoginRequest>,
) -> Result<(), ErrorResponse> {
    payload.validate()?;

    let sid = get_session_cookie(&jar)?;
    let session = SessionEntity::find(sid).await?;

    // check xsrf
    if xsrf.0.token() != session.xsrf {
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Bad Credentials".to_string(),
        ));
    }

    // check password
    let pepper = state.read().await.enc_keys.pepper.clone();
    let password_hash = MasterKeyRow::find_local_password().await?;
    let password_match =
        ComparePasswords::is_match(&payload.password, password_hash, &pepper).await?;
    if !password_match {
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Bad Credentials".to_string(),
        ));
    }

    // expand the session lifetime
    session.set_authenticated().await?;

    Ok(())
}

/// Check the logged in status
#[utoipa::path(
    get,
    tag = "unsealed",
    path = "/api/login/check",
    responses(
        (status = 200, description = "Ok", body = AuthCheckResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn get_login_check(
    jar: CookieJar,
    principal: Result<Principal, ErrorResponse>,
) -> Result<(CookieJar, Json<AuthCheckResponse>), ErrorResponse> {
    if let Ok(p) = principal {
        let resp = AuthCheckResponse {
            principal: p,
            xsrf: None,
        };

        let jar = CookieJar::new();
        Ok((jar, Json(resp)))
    } else {
        let sid = jar
            .get(SESSION_COOKIE)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                ErrorResponse::new(ErrorResponseType::Unauthorized, "Unauthorized".to_string())
            })?;
        let (_, sid) = sid.split_once('=').unwrap();

        let xsrf = jar
            .get(SESSION_COOKIE_XSRF)
            .map(|c| c.to_string())
            .ok_or_else(|| {
                ErrorResponse::new(ErrorResponseType::Unauthorized, "Unauthorized".to_string())
            })?;
        let (_, xsrf) = xsrf.split_once('=').unwrap();

        let id = match Uuid::from_str(sid) {
            Ok(id) => id,
            Err(_) => {
                return Err(ErrorResponse::new(
                    ErrorResponseType::BadRequest,
                    "Bad session ID".to_string(),
                ));
            }
        };
        let session = SessionEntity::find(id).await?;

        if session.xsrf != xsrf {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "Bad XSRF Token".to_string(),
            ));
        }

        let principal = Principal::from_session(session);

        let resp = AuthCheckResponse {
            principal,
            xsrf: Some(xsrf.to_string()),
        };

        let jar = CookieJar::new().add(delete_session_cookie_xsrf());
        Ok((jar, Json(resp)))
    }
}

/// Logout
#[utoipa::path(
    post,
    tag = "unsealed",
    path = "/api/logout",
    responses(
        (status = 200, description = "Ok"),
    ),
)]
pub async fn post_logout(
    jar: CookieJar,
    TypedHeader(xsrf): TypedHeader<Authorization<Bearer>>,
) -> Result<CookieJar, ErrorResponse> {
    let sid = get_session_cookie(&jar)?;
    let session = SessionEntity::find(sid).await?;

    // check xsrf
    if xsrf.0.token() != session.xsrf {
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "Bad Credentials".to_string(),
        ));
    }

    SessionEntity::invalidate(sid).await?;

    let cookie = Cookie::build(SESSION_COOKIE, sid.to_string())
        .domain(&*PUB_URL)
        .path("/api")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .expires(OffsetDateTime::now_utc())
        .finish();
    let jar = CookieJar::new().add(cookie);

    Ok(jar)
}

/// Change the local root users password
#[utoipa::path(
put,
tag = "unsealed",
path = "/api/password_change",
responses(
(status = 200, description = "Ok"),
(status = 403, description = "Forbidden", body = ErrorResponse),
),
)]
pub async fn put_password_change(
    principal: Principal,
    state: AppStateExtract,
    Json(payload): Json<PasswordChangeRequest>,
) -> Result<(), ErrorResponse> {
    payload.validate()?;

    // only the local root user can change this password -> not allowed from SOO admin
    if !principal.local || principal.is_admin.is_none() || !principal.is_admin.unwrap() {
        return Err(ErrorResponse::new(
            ErrorResponseType::Forbidden,
            "Only the local root user can change this password",
        ));
    }

    // check current password
    let pepper = state.read().await.enc_keys.pepper.clone();
    let password_hash = MasterKeyRow::find_local_password().await?;
    let password_match =
        ComparePasswords::is_match(&payload.current_password, password_hash, &pepper).await?;
    if !password_match {
        return Err(ErrorResponse::new(
            ErrorResponseType::Forbidden,
            "Bad Credentials".to_string(),
        ));
    }

    // hash and save the new password
    let new_hash = HashPassword::hash_password(&payload.new_password, &pepper).await?;
    MasterKeyRow::update_local_password(&new_hash).await?;

    Ok(())
}

/// Create and get a new session
///
/// Sets a session cookie, which must be provided with every request.<br>
/// A session must exist before attempting a login with a local account.
#[utoipa::path(
    post,
    tag = "unsealed",
    path = "/api/sessions",
    responses(
        (status = 200, description = "Ok", body = SessionResponse),
    ),
)]
pub async fn post_session() -> Result<(CookieJar, Json<SessionResponse>), ErrorResponse> {
    let session = SessionEntity::new_local().await?;

    let cookie = build_session_cookie(session.id.to_string());
    let jar = CookieJar::new().add(cookie);

    let resp = SessionResponse {
        xsrf: session.xsrf,
        expires: session.expires.to_string(),
    };

    Ok((jar, Json(resp)))
}

/// Returns the current unsealed status and the added keys
#[utoipa::path(
    get,
    tag = "unsealed",
    path = "/api/status",
    responses(
        (status = 200, description = "Ok", body = SealedStatus),
    ),
)]
pub async fn get_status() -> Result<Json<SealedStatus>, ErrorResponse> {
    let status = SealedStatus {
        is_initialized: true,
        is_sealed: false,
        master_shard_1: true,
        master_shard_2: true,
        is_ready: true,
        key_add_rate_limit: *UNSEAL_RATE_LIMIT,
    };
    Ok(Json(status))
}

/// The root certificate in PEM format
#[utoipa::path(
    get,
    tag = "common",
    path = "/root.pem",
    responses(
        (status = 200, description = "Ok"),
    ),
)]
pub async fn get_root_pem(state: AppStateExtract) -> Result<String, ErrorResponse> {
    let pem = state.read().await.root_cert.cert_pem.clone();
    Ok(pem)
}

/// The root fingerprint
#[utoipa::path(
    get,
    tag = "common",
    path = "/root.fingerprint",
    responses(
        (status = 200, description = "Ok"),
    ),
)]
pub async fn get_root_fingerprint(state: AppStateExtract) -> Result<String, ErrorResponse> {
    let pem = state.read().await.root_cert.fingerprint.clone();
    Ok(pem)
}

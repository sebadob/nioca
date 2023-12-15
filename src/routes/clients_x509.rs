use crate::certificates::CertFormat;
use crate::constants::HEADER_OCTET_STREAM;
use crate::models::api::error_response::ErrorResponse;
use crate::models::api::principal::Principal;
use crate::models::api::request::ClientX509Request;
use crate::models::api::response::{CertX509Response, ClientSecretResponse, ClientX509Response};
use crate::models::db::ca_cert_x509::CaCertX509Full;
use crate::models::db::client_x509::{ClientX509Entity, ClientX509EntityCert};
use crate::routes::AppStateExtract;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::headers::Authorization;
use axum_extra::{headers, TypedHeader};
use headers::authorization::Bearer;
use std::str::FromStr;
use uuid::Uuid;
use validator::Validate;

/// Get x509 clients
#[utoipa::path(
    get,
    tag = "clients",
    path = "/api/clients/x509",
    responses(
        (status = 200, description = "Ok", body = Vec<ClientX509Response>),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn get_clients(
    principal: Principal,
) -> Result<Json<Vec<ClientX509Response>>, ErrorResponse> {
    principal.is_admin()?;

    let mut clients = ClientX509Entity::find_all().await?;
    let res = clients
        .drain(..)
        .map(ClientX509Response::from)
        .collect::<Vec<ClientX509Response>>();
    Ok(Json(res))
}

/// Create an x509 client
#[utoipa::path(
    post,
    tag = "clients",
    path = "/api/clients/x509",
    request_body = ClientX509Request,
    responses(
        (status = 200, description = "Ok", body = ClientX509Response),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn post_client(
    state: AppStateExtract,
    principal: Principal,
    Json(payload): Json<ClientX509Request>,
) -> Result<Json<ClientX509Response>, ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    let enc_key = state.read().await.enc_keys.enc_key.clone();
    let client = ClientX509Entity::create(payload, &enc_key).await?;

    let resp = ClientX509Response::from(client);
    Ok(Json(resp))
}

/// Get an x509 client
#[utoipa::path(
    get,
    tag = "clients",
    path = "/api/clients/x509/:id",
    responses(
        (status = 200, description = "Ok", body = ClientX509Response),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn get_client(
    Path(id): Path<String>,
    principal: Principal,
) -> Result<Json<ClientX509Response>, ErrorResponse> {
    principal.is_admin()?;

    let uuid = Uuid::from_str(&id)?;
    let client = ClientX509Entity::find(&uuid).await?;
    Ok(Json(ClientX509Response::from(client)))
}

/// Update an x509 client
#[utoipa::path(
    put,
    tag = "clients",
    path = "/api/clients/x509/:id",
    request_body = ClientX509Request,
    responses(
        (status = 200, description = "Ok", body = ClientX509Response),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn put_client(
    Path(id): Path<String>,
    principal: Principal,
    Json(payload): Json<ClientX509Request>,
) -> Result<Json<ClientX509Response>, ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    let uuid = Uuid::from_str(&id)?;
    let client = ClientX509Entity::update(&uuid, payload).await?;

    let resp = ClientX509Response::from(client);
    Ok(Json(resp))
}

/// Delete an x509 client
#[utoipa::path(
    delete,
    tag = "clients",
    path = "/api/clients/x509/:id",
    responses(
        (status = 200, description = "Ok"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn delete_client(
    Path(id): Path<String>,
    principal: Principal,
) -> Result<(), ErrorResponse> {
    principal.is_admin()?;

    let uuid = Uuid::from_str(&id)?;
    ClientX509Entity::delete(&uuid).await?;

    Ok(())
}

/// Get preconfigured x509 client certificate
///
/// Requests the clients API key given as `Bearer` token in the `Authorization` header.
#[utoipa::path(
    post,
    tag = "clients",
    path = "/api/clients/x509/:id/cert",
    responses(
        (status = 200, description = "Ok", body = CertX509Response),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn post_build_client_cert(
    state: AppStateExtract,
    TypedHeader(api_key): TypedHeader<Authorization<Bearer>>,
    Path(id): Path<String>,
) -> Result<Json<CertX509Response>, ErrorResponse> {
    let uuid = Uuid::from_str(&id)?;
    let client = ClientX509Entity::find(&uuid).await?;

    let ca_id = client
        .validate_active_enabled(state.clone(), api_key.token())
        .await?;
    let enc_keys = state.read().await.enc_keys.clone();
    let ca = CaCertX509Full::build_by_id(&ca_id, &enc_keys).await?;
    let resp = match client.build_cert(&ca, CertFormat::Pem, None).await? {
        // let resp = match client.build_cert(state, CertFormat::Pem, None).await? {
        ClientX509EntityCert::Pem(resp) => resp,
        _ => unreachable!(),
    };
    Ok(Json(resp))
}

/// Get preconfigured x509 client certificate in PKCS12 format
///
/// Requests the clients API key given as `Bearer` token in the `Authorization` header.
#[utoipa::path(
    post,
    tag = "clients",
    path = "/api/clients/x509/:id/cert/p12",
    responses(
        (status = 200, description = "Ok", body = CertX509Response),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn post_build_client_cert_p12(
    state: AppStateExtract,
    TypedHeader(api_key): TypedHeader<Authorization<Bearer>>,
    Path(id): Path<String>,
) -> Result<Response, ErrorResponse> {
    let uuid = Uuid::from_str(&id)?;
    let client = ClientX509Entity::find(&uuid).await?;

    let ca_id = client
        .validate_active_enabled(state.clone(), api_key.token())
        .await?;
    let enc_keys = state.read().await.enc_keys.clone();
    let ca = CaCertX509Full::build_by_id(&ca_id, &enc_keys).await?;
    let pkcs12 = match client
        .build_cert(&ca, CertFormat::PKCS12, Some(api_key.token()))
        .await?
    {
        ClientX509EntityCert::PKCS12(pkcs12) => pkcs12,
        _ => unreachable!(),
    };

    // This template is used for bigger files from disk only - not needed in this case
    // --> https://github.com/tokio-rs/axum/discussions/608
    // // convert the `AsyncRead` into a `Stream`
    // let stream = ReaderStream::new(file_from_disk);
    // // convert the `Stream` into an `axum::body::HttpBody`
    // let body = StreamBody::new(stream);

    Ok((HEADER_OCTET_STREAM, pkcs12).into_response())
}

/// Get x509 client secret in cleartext
#[utoipa::path(
    get,
    tag = "clients",
    path = "/api/clients/x509/:id/secret",
    responses(
        (status = 200, description = "Ok", body = ClientX509SecretResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn get_client_secret(
    state: AppStateExtract,
    Path(id): Path<String>,
    principal: Principal,
) -> Result<Json<ClientSecretResponse>, ErrorResponse> {
    principal.is_admin()?;

    let enc_keys = state.read().await.enc_keys.clone();

    let uuid = Uuid::from_str(&id)?;
    let secret = ClientX509Entity::find_secret(&uuid, &enc_keys).await?;
    let resp = ClientSecretResponse { secret };
    Ok(Json(resp))
}

/// Generates a new random x509 client secret
#[utoipa::path(
    put,
    tag = "clients",
    path = "/api/clients/x509/:id/secret",
    responses(
        (status = 200, description = "Ok", body = ClientSecretResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn put_client_secret(
    state: AppStateExtract,
    Path(id): Path<String>,
    principal: Principal,
) -> Result<Json<ClientSecretResponse>, ErrorResponse> {
    principal.is_admin()?;

    let enc_keys = state.read().await.enc_keys.clone();
    let uuid = Uuid::from_str(&id)?;
    let secret = ClientX509Entity::new_secret(&uuid, &enc_keys).await?;
    let resp = ClientSecretResponse { secret };
    Ok(Json(resp))
}

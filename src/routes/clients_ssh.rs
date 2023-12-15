use crate::models::api::error_response::ErrorResponse;
use crate::models::api::principal::Principal;
use crate::models::api::request::ClientSshRequest;
use crate::models::api::response::{
    ClientSecretResponse, ClientSshResponse, SshCertificateResponse,
};
use crate::models::db::client_ssh::ClientSshEntity;
use crate::routes::AppStateExtract;
use axum::extract::Path;
use axum::Json;
use axum_extra::{headers, TypedHeader};
use headers::authorization::Bearer;
use headers::Authorization;
use std::str::FromStr;
use uuid::Uuid;
use validator::Validate;

/// Get SSH clients
#[utoipa::path(
    get,
    tag = "clients",
    path = "/api/clients/ssh",
    responses(
        (status = 200, description = "Ok", body = Vec<ClientSshResponse>),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn get_clients(
    principal: Principal,
) -> Result<Json<Vec<ClientSshResponse>>, ErrorResponse> {
    principal.is_admin()?;

    let mut clients = ClientSshEntity::find_all().await?;
    let res = clients
        .drain(..)
        .map(ClientSshResponse::from)
        .collect::<Vec<ClientSshResponse>>();
    Ok(Json(res))
}

/// Create SSH clients
#[utoipa::path(
    post,
    tag = "clients",
    path = "/api/clients/ssh",
    request_body = ClientSshRequest,
    responses(
        (status = 200, description = "Ok", body = ClientSshResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn post_client(
    state: AppStateExtract,
    principal: Principal,
    Json(payload): Json<ClientSshRequest>,
) -> Result<Json<ClientSshResponse>, ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    let enc_key = state.read().await.enc_keys.enc_key.clone();
    let client = ClientSshEntity::create(payload, &enc_key).await?;

    Ok(Json(ClientSshResponse::from(client)))
}

/// Get an SSH client
#[utoipa::path(
    get,
    tag = "clients",
    path = "/api/clients/ssh/:id",
    responses(
        (status = 200, description = "Ok", body = ClientSshResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn get_client(
    Path(id): Path<String>,
    principal: Principal,
) -> Result<Json<ClientSshResponse>, ErrorResponse> {
    principal.is_admin()?;

    let uuid = Uuid::from_str(&id)?;
    let client = ClientSshEntity::find(&uuid).await?;

    Ok(Json(ClientSshResponse::from(client)))
}

/// Update an SSH client
#[utoipa::path(
    put,
    tag = "clients",
    path = "/api/clients/ssh/:id",
    request_body = ClientSshRequest,
    responses(
        (status = 200, description = "Ok", body = ClientSshResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn put_client(
    Path(id): Path<String>,
    principal: Principal,
    Json(payload): Json<ClientSshRequest>,
) -> Result<Json<ClientSshResponse>, ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    let uuid = Uuid::from_str(&id)?;
    let client = ClientSshEntity::update(&uuid, payload).await?;

    let resp = ClientSshResponse::from(client);
    Ok(Json(resp))
}

/// Delete an SSH client
#[utoipa::path(
    delete,
    tag = "clients",
    path = "/api/clients/ssh/:id",
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
    ClientSshEntity::delete(&uuid).await?;

    Ok(())
}

/// Get preconfigured SSH client certificate
///
/// Requests the clients API key given as `Bearer` token in the `Authorization` header.
#[utoipa::path(
    post,
    tag = "clients",
    path = "/api/clients/ssh/:id/cert",
    responses(
        (status = 200, description = "Ok", body = SshCertificateResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn post_build_client_cert(
    state: AppStateExtract,
    TypedHeader(api_key): TypedHeader<Authorization<Bearer>>,
    Path(id): Path<String>,
) -> Result<Json<SshCertificateResponse>, ErrorResponse> {
    let uuid = Uuid::from_str(&id)?;
    let client = ClientSshEntity::find(&uuid).await?;

    let group = client
        .validate_active_enabled(&state, api_key.token())
        .await?;
    let resp = client.build_cert(&state, &group).await?;
    Ok(Json(resp))
}

/// Get SSH client secret in cleartext
#[utoipa::path(
    get,
    tag = "clients",
    path = "/api/clients/ssh/:id/secret",
    responses(
        (status = 200, description = "Ok", body = ClientSecretResponse),
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
    let secret = ClientSshEntity::find_secret(&uuid, &enc_keys).await?;
    let resp = ClientSecretResponse { secret };
    Ok(Json(resp))
}

/// Generates a new random SSH client secret
#[utoipa::path(
    put,
    tag = "clients",
    path = "/api/clients/ssh/:id/secret",
    responses(
        (status = 200, description = "Ok", body = ClientX509SecretResponse),
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
    let secret = ClientSshEntity::new_secret(&uuid, &enc_keys).await?;

    let resp = ClientSecretResponse { secret };
    Ok(Json(resp))
}

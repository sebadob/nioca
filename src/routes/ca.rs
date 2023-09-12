use crate::certificates::x509::verification::{x509_der_from_bytes, x509_pem_from_bytes};
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::api::principal::Principal;
use crate::models::api::request::{ExternalSshKeyRequest, GenerateSshKeyRequest, X509CaAddRequest};
use crate::models::api::response::{
    CaCertSshResponse, CasSshResponse, CasX509Response, CertificateInspectResponse,
};
use crate::models::db::ca_cert_ssh::{CaCertSshEntity, SshKeyPairOpenssh};
use crate::models::db::ca_cert_x509::{CaCertX509Entity, CaCertX509Type};
use crate::models::db::groups::GroupEntity;
use crate::routes::AppStateExtract;
use crate::service;
use axum::Json;
use validator::Validate;
use x509_parser::nom::AsBytes;

/// Get configured SSH CA's
#[utoipa::path(
    get,
    tag = "ca",
    path = "/api/ca/ssh",
    responses(
        (status = 200, description = "Ok", body = CasSshResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn get_ca_ssh(principal: Principal) -> Result<Json<CasSshResponse>, ErrorResponse> {
    principal.is_admin()?;

    let cas_ssh = CaCertSshEntity::find_all()
        .await?
        .drain(..)
        .map(CaCertSshResponse::from)
        .collect();
    let resp = CasSshResponse { cas_ssh };
    Ok(Json(resp))
}

/// Generate a new default SSH CA
#[utoipa::path(
    post,
    tag = "ca",
    path = "/api/ca/ssh/generate",
    request_body = GenerateSshKeyRequest,
    responses(
        (status = 200, description = "Ok", body = CaCertSshExtendedEntity),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn post_generate_ca_ssh(
    state: AppStateExtract,
    principal: Principal,
    Json(payload): Json<GenerateSshKeyRequest>,
) -> Result<Json<CaCertSshResponse>, ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    let enc_key = state.read().await.enc_keys.enc_key.clone();
    let group = GroupEntity::find_by_name("default").await?;

    // make sure we do not have a root CA yet
    if let Ok(entity) = CaCertSshEntity::find_by_group(&group.id).await {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            format!("SSH default CA already exists with id {}", entity.id),
        ));
    }

    let entity = CaCertSshEntity::generate_new(
        payload.name.unwrap_or_else(|| "default".to_string()),
        payload.alg,
        &enc_key,
    )
    .await?;
    let resp = CaCertSshResponse::from(entity);
    Ok(Json(resp))
}

/// Add an external default SSH CA
#[utoipa::path(
    post,
    tag = "ca",
    path = "/api/ca/ssh/external",
    request_body = ExternalSshKeyRequest,
    responses(
        (status = 200, description = "Ok", body = CaCertSshExtendedEntity),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
)]
pub async fn post_external_ca_ssh(
    state: AppStateExtract,
    principal: Principal,
    Json(payload): Json<ExternalSshKeyRequest>,
) -> Result<Json<CaCertSshResponse>, ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    // try to decrypt and decode the given key
    let kp = SshKeyPairOpenssh::from_key_enc(&payload.key_enc_hex, &payload.password).await?;

    // key is valid - create a new entity
    let enc_key = state.read().await.enc_keys.enc_key.clone();
    let group = GroupEntity::find_by_name("default").await?;

    // make sure we do not have a root CA yet
    if let Ok(entity) = CaCertSshEntity::find_by_group(&group.id).await {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            format!("SSH default CA already exists with id {}", entity.id),
        ));
    }

    let entity = CaCertSshEntity::insert(
        payload.name.unwrap_or_else(|| "default".to_string()),
        kp,
        &enc_key,
    )
    .await?;
    let resp = CaCertSshResponse::from(entity);
    Ok(Json(resp))
}

/// Get the X509 CA's
#[utoipa::path(
get,
tag = "ca",
path = "/api/ca/x509",
responses(
(status = 200, description = "Ok", body = CasX509Response),
(status = 401, description = "Unauthorized", body = ErrorResponse),
),
)]
pub async fn get_ca_x509(principal: Principal) -> Result<Json<CasX509Response>, ErrorResponse> {
    principal.is_admin()?;

    let cas_x509 = CaCertX509Entity::find_all_by_type(CaCertX509Type::Certificate)
        .await?
        .drain(..)
        // TODO necessary cache response for some longer time?
        .filter_map(|cert_entity| {
            if let Ok(pem) = x509_pem_from_bytes(cert_entity.data.as_bytes()).map_err(|err| {
                ErrorResponse::new(
                    ErrorResponseType::BadRequest,
                    format!("Bad Intermediate PEM: {}", err.message),
                )
            }) {
                if let Ok(cert) = x509_der_from_bytes(pem.contents.as_bytes()) {
                    return Some(CertificateInspectResponse::from_certificate(
                        cert_entity.id,
                        cert_entity.name,
                        cert,
                    ));
                }
            }
            None
        })
        .collect();
    let resp = CasX509Response { cas_x509 };
    Ok(Json(resp))
}

/// Add a new X509 Intermediate CA
#[utoipa::path(
post,
tag = "ca",
path = "/api/ca/x509",
responses(
(status = 200, description = "Ok"),
(status = 401, description = "Unauthorized", body = ErrorResponse),
),
)]
pub async fn post_ca_x509(
    state: AppStateExtract,
    principal: Principal,
    Json(payload): Json<X509CaAddRequest>,
) -> Result<(), ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    service::x509::add_x509_ca(&state.0, payload).await
}

use crate::constants::UNSEAL_RATE_LIMIT;
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::api::request::{AddMasterShardRequest, InitRequest, UnsealRequest};
use crate::models::api::response::{CertificateInitInspectResponse, InitResponse, SealedStatus};
use crate::routes::AppStateSealedExtract;
use crate::service::sealed::{add_unseal_shard, init, init_values_check, unseal};
use axum::Json;
use validator::Validate;

/// Initialize Nioca with a fully empty database
#[utoipa::path(
    tag = "sealed",
    post,
    path = "/sealed/init",
    request_body = InitRequest,
    responses(
        (status = 200, description = "Ok", body = InitResponse),
        (status = 400, description = "BadRequest", body = ErrorResponse),
    ),
)]
pub async fn post_init(
    state: AppStateSealedExtract,
    Json(payload): Json<InitRequest>,
) -> Result<Json<InitResponse>, ErrorResponse> {
    payload.validate()?;
    check_init_state(&state).await?;

    let init_resp = init(state, payload).await?;
    Ok(Json(init_resp))
}

/// Checks the given certificates for the Nioca initialization
#[utoipa::path(
    tag = "sealed",
    post,
    path = "/sealed/init/check",
    request_body = InitRequest,
    responses(
        (status = 200, description = "Ok", body = CheckedCerts),
        (status = 400, description = "BadRequest", body = ErrorResponse),
    ),
)]
pub async fn post_init_check(
    state: AppStateSealedExtract,
    Json(payload): Json<InitRequest>,
) -> Result<Json<CertificateInitInspectResponse>, ErrorResponse> {
    payload.validate()?;
    check_init_state(&state).await?;

    let state = state.read().await.clone();
    let (_, resp) = init_values_check(&state, &payload).await?;

    Ok(Json(resp))
}

/// Add a master key for the unsealing operation
#[utoipa::path(
    tag = "sealed",
    post,
    path = "/sealed/key",
    request_body = AddMasterShardRequest,
    responses(
        (status = 200, description = "Ok", body = SealedStatus),
        (status = 400, description = "BadRequest", body = ErrorResponse),
    ),
)]
pub async fn post_master_shard(
    state: AppStateSealedExtract,
    Json(payload): Json<AddMasterShardRequest>,
) -> Result<Json<SealedStatus>, ErrorResponse> {
    payload.validate()?;

    let status = add_unseal_shard(state, payload).await?;
    Ok(Json(status))
}

/// Returns the current sealed status and the added keys
#[utoipa::path(
    tag = "sealed",
    get,
    path = "/sealed/status",
    responses(
        (status = 200, description = "Ok", body = SealedStatus),
    ),
)]
pub async fn get_status(state: AppStateSealedExtract) -> Result<Json<SealedStatus>, ErrorResponse> {
    let config = state.read().await;
    let status = SealedStatus {
        is_initialized: config.init_key.is_none(),
        is_sealed: true,
        master_shard_1: config.enc_keys.master_shard_1.is_some(),
        master_shard_2: config.enc_keys.master_shard_2.is_some(),
        is_ready: config.enc_keys.master_shard_1.is_some()
            && config.enc_keys.master_shard_2.is_some(),
        key_add_rate_limit: *UNSEAL_RATE_LIMIT,
    };
    Ok(Json(status))
}

/// Unseal Nioca if all the keys have been added
#[utoipa::path(
    tag = "sealed",
    post,
    path = "/sealed/execute",
    request_body = UnsealRequest,
    responses(
        (status = 200, description = "Ok", body = SealedStatus),
        (status = 400, description = "BadRequest", body = ErrorResponse),
    ),
)]
pub async fn post_unseal(
    state: AppStateSealedExtract,
    Json(payload): Json<UnsealRequest>,
) -> Result<(), ErrorResponse> {
    payload.validate()?;
    unseal(state, payload).await
}

/// Get the XSRF token for an unsealing operation
#[utoipa::path(
    tag = "sealed",
    post,
    path = "/sealed/xsrf",
    responses(
        (status = 200, description = "Ok"),
    ),
)]
pub async fn get_xsrf(state: AppStateSealedExtract) -> Result<String, ErrorResponse> {
    Ok(state.read().await.xsrf_key.clone())
}

async fn check_init_state(state: &AppStateSealedExtract) -> Result<(), ErrorResponse> {
    if state.read().await.init_key.is_none() {
        Err(ErrorResponse::new(
            ErrorResponseType::ServiceUnavailable,
            "Nioca is not in the init state".to_string(),
        ))
    } else {
        Ok(())
    }
}

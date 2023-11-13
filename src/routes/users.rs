use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::api::principal::Principal;
use crate::models::api::request::UsersGroupAccessRequest;
use crate::models::api::response::{UserResponse, UsersGroupAccessResponse};
use crate::models::db::user::UserEntity;
use crate::models::db::user_group_access::UsersGroupAccess;
use crate::routes::AppStateExtract;
use axum::extract::Path;
use axum::Json;
use std::str::FromStr;
use uuid::Uuid;
use validator::Validate;

#[utoipa::path(
    get,
    tag = "unsealed",
    path = "/api/users",
    responses(
        (status = 200, description = "Ok", body = UserResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
pub async fn get_users(principal: Principal) -> Result<Json<Vec<UserResponse>>, ErrorResponse> {
    principal.is_admin()?;

    let users = UserEntity::find_all()
        .await?
        .into_iter()
        .map(UserResponse::from)
        .collect();

    Ok(Json(users))
}

#[utoipa::path(
    get,
    tag = "unsealed",
    path = "/api/users/:id/access",
    responses(
        (status = 200, description = "Ok", body = UsersGroupAccessResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
pub async fn get_user_group_access(
    state: AppStateExtract,
    Path(id): Path<String>,
    principal: Principal,
) -> Result<Json<Vec<UsersGroupAccessResponse>>, ErrorResponse> {
    if principal.is_user(&id).is_ok() || principal.is_admin().is_ok() {
        let enc_keys = state.read().await.enc_keys.clone();
        let user_id = Uuid::from_str(&id)?;
        let access = UsersGroupAccess::find_all_user(&enc_keys, &user_id)
            .await?
            .into_iter()
            .map(UsersGroupAccessResponse::from)
            .collect();

        Ok(Json(access))
    } else {
        Err(ErrorResponse::new(
            ErrorResponseType::Forbidden,
            "You do not have access to this resource".to_string(),
        ))
    }
}

#[utoipa::path(
    post,
    tag = "unsealed",
    path = "/api/users/:user_id/access/:group_id",
    responses(
        (status = 200, description = "Ok"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
pub async fn post_user_group_access(
    state: AppStateExtract,
    Path((user_id, group_id)): Path<(String, String)>,
    principal: Principal,
) -> Result<(), ErrorResponse> {
    principal.is_admin()?;

    let enc_key = state.read().await.enc_keys.enc_key.clone();
    let user_id = Uuid::from_str(&user_id)?;
    let group_id = Uuid::from_str(&group_id)?;

    UsersGroupAccess::create(user_id, group_id, &enc_key).await?;

    Ok(())
}

#[utoipa::path(
    put,
    tag = "unsealed",
    path = "/api/users/:user_id/access/:group_id",
    request_body = UsersGroupAccessRequest,
    responses(
        (status = 200, description = "Ok"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
pub async fn put_user_group_access(
    state: AppStateExtract,
    Path((user_id, group_id)): Path<(String, String)>,
    principal: Principal,
    Json(payload): Json<UsersGroupAccessRequest>,
) -> Result<(), ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    let group_access = UsersGroupAccess::try_from(payload)?;
    let user_id = Uuid::from_str(&user_id)?;
    let group_id = Uuid::from_str(&group_id)?;
    if group_access.user_id != user_id || group_access.group_id != group_id {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Invalid values for user_id / group_id".to_string(),
        ));
    }

    let enc_key = state.read().await.enc_keys.enc_key.clone();
    UsersGroupAccess::update(&enc_key, user_id, group_id, &group_access).await?;

    Ok(())
}

#[utoipa::path(
    delete,
    tag = "unsealed",
    path = "/api/users/:user_id/access/:group_id",
    responses(
        (status = 200, description = "Ok"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
pub async fn delete_user_group_access(
    Path((user_id, group_id)): Path<(String, String)>,
    principal: Principal,
) -> Result<(), ErrorResponse> {
    principal.is_admin()?;

    let user_id = Uuid::from_str(&user_id)?;
    let group_id = Uuid::from_str(&group_id)?;

    UsersGroupAccess::delete(user_id, group_id).await?;

    Ok(())
}

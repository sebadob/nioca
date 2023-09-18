use crate::models::api::error_response::ErrorResponse;
use crate::models::api::principal::Principal;
use crate::models::api::request::{GroupCreateRequest, GroupUpdateRequest};
use crate::models::api::response::GroupResponse;
use crate::models::db::groups::GroupEntity;
use axum::extract::Path;
use axum::Json;
use std::str::FromStr;
use uuid::Uuid;
use validator::Validate;

#[utoipa::path(
get,
tag = "unsealed",
path = "/api/groups",
responses(
(status = 200, description = "Ok", body = GroupResponse),
(status = 401, description = "Unauthorized", body = ErrorResponse),
(status = 403, description = "Forbidden", body = ErrorResponse),
),
)]
pub async fn get_groups(principal: Principal) -> Result<Json<Vec<GroupResponse>>, ErrorResponse> {
    principal.is_admin()?;
    let groups = GroupEntity::find_all()
        .await?
        .into_iter()
        .map(GroupResponse::from)
        .collect();
    Ok(Json(groups))
}

#[utoipa::path(
post,
tag = "unsealed",
path = "/api/groups",
responses(
(status = 200, description = "Ok"),
(status = 401, description = "Unauthorized", body = ErrorResponse),
(status = 403, description = "Forbidden", body = ErrorResponse),
),
)]
pub async fn post_group(
    principal: Principal,
    Json(payload): Json<GroupCreateRequest>,
) -> Result<(), ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    GroupEntity::insert(payload).await?;
    Ok(())
}

#[utoipa::path(
put,
tag = "unsealed",
path = "/api/groups/:id",
responses(
(status = 200, description = "Ok"),
(status = 401, description = "Unauthorized", body = ErrorResponse),
(status = 403, description = "Forbidden", body = ErrorResponse),
),
)]
pub async fn put_group(
    principal: Principal,
    Json(payload): Json<GroupUpdateRequest>,
) -> Result<(), ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    GroupEntity::update(payload).await?;
    Ok(())
}

#[utoipa::path(
delete,
tag = "unsealed",
path = "/api/groups/:id",
responses(
(status = 200, description = "Ok"),
(status = 401, description = "Unauthorized", body = ErrorResponse),
(status = 403, description = "Forbidden", body = ErrorResponse),
),
)]
pub async fn delete_group(
    principal: Principal,
    Path(id): Path<String>,
) -> Result<(), ErrorResponse> {
    principal.is_admin()?;

    let id = Uuid::from_str(&id)?;
    GroupEntity::delete(&id).await?;
    Ok(())
}

use std::str::FromStr;

use axum::extract::Path;
use axum::Json;
use tracing::{error, warn};
use uuid::Uuid;
use validator::Validate;

use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::api::principal::Principal;
use crate::models::api::request::{GroupCreateRequest, GroupUpdateRequest};
use crate::models::api::response::GroupResponse;
use crate::models::db::client_ssh::ClientSshEntity;
use crate::models::db::client_x509::ClientX509Entity;
use crate::models::db::groups::GroupEntity;

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
    request_body = GroupCreateRequest,
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
    request_body = GroupUpdateRequest,
    responses(
        (status = 200, description = "Ok"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
)]
pub async fn put_group(
    principal: Principal,
    Path(id): Path<String>,
    Json(payload): Json<GroupUpdateRequest>,
) -> Result<(), ErrorResponse> {
    principal.is_admin()?;
    payload.validate()?;

    let id = Uuid::from_str(&id)?;
    GroupEntity::update(&id, payload).await?;
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
    if let Err(err) = GroupEntity::delete(&id).await {
        return if err.message.contains("foreign key") {
            // if we violate a foreign key constraint, it means that the group is still in use
            // for a better UX, provide the linked clients to the user
            warn!("Cannot delete group in use: {}", id);

            let clients_ssh = ClientSshEntity::find_with_group(&id).await?;
            let clients_x509 = ClientX509Entity::find_with_group(&id).await?;

            // TODO may be removed after enough testing
            if clients_ssh.is_empty() && clients_x509.is_empty() {
                error!("foreign key constraint violation when deleting group but no linked clients found");
            }

            let msg_ssh = clients_ssh.join("<br/>");
            let msg_x509 = clients_x509.join("<br/>");
            let err_msg = format!(
                r#"<p><b>Cannot delete group which is still in use</b></p>
                <p>SSH Clients:<br/>{}</p>
                <p>X509 Clients:<br/>{}</p>"#,
                msg_ssh, msg_x509
            );

            Err(ErrorResponse::new(ErrorResponseType::BadRequest, err_msg))
        } else {
            error!("{:?}", err);
            Err(err)
        };
    }

    Ok(())
}

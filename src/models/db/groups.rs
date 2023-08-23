use crate::config::Db;
use crate::models::api::error_response::ErrorResponse;
use crate::models::api::request::GroupUpdateRequest;
use serde::{Deserialize, Serialize};
use sqlx::{query, query_as};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupEntity {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub ca_ssh: Option<Uuid>,
    pub ca_x509: Option<Uuid>,
    pub ca_x509_typ: Option<String>,
}

impl GroupEntity {
    pub async fn find_all() -> Result<Vec<Self>, ErrorResponse> {
        let res = query_as!(Self, "SELECT * FROM groups")
            .fetch_all(Db::conn())
            .await?;

        Ok(res)
    }

    pub async fn find_default_id() -> Result<Uuid, ErrorResponse> {
        let res = query!("SELECT id FROM groups WHERE name = 'default'")
            .fetch_one(Db::conn())
            .await?;

        Ok(res.id)
    }

    pub async fn find_by_id(id: &Uuid) -> Result<Self, ErrorResponse> {
        let res = query_as!(Self, "SELECT * FROM groups WHERE id = $1", id)
            .fetch_one(Db::conn())
            .await?;

        Ok(res)
    }

    pub async fn find_by_name(name: &str) -> Result<Self, ErrorResponse> {
        let res = query_as!(Self, "SELECT * FROM groups WHERE name = $1", name)
            .fetch_one(Db::conn())
            .await?;

        Ok(res)
    }

    pub async fn update(req: GroupUpdateRequest) -> Result<(), ErrorResponse> {
        query!(
            "UPDATE groups SET name = $1, enabled = $2, ca_ssh = $3, ca_x509 = $4 WHERE id = $5",
            req.name,
            req.enabled,
            req.ca_ssh,
            req.ca_x509,
            req.id,
        )
        .execute(Db::conn())
        .await?;

        Ok(())
    }
}

use crate::config::Db;
use crate::constants::{DIRECT_ACCESS_PUB_URL, INSTANCE_UUID, PUB_URL_WITH_SCHEME};
use crate::models::api::error_response::ErrorResponse;
use sqlx::{query, query_as};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SealedEntity {
    pub id: Uuid,
    pub timestamp: OffsetDateTime,
    pub direct_access: bool,
    pub url: String,
}

impl SealedEntity {
    pub async fn add() -> Result<(), ErrorResponse> {
        // Clean up possibly old values before creating a new entry
        Self::delete().await?;

        let (direct_access, url) = if let Some(url) = &*DIRECT_ACCESS_PUB_URL {
            (true, url.clone())
        } else {
            (false, PUB_URL_WITH_SCHEME.to_string())
        };
        let now = OffsetDateTime::now_utc();

        query!(
            "insert into sealed (id, timestamp, direct_access, url) values ($1, $2, $3, $4)",
            *INSTANCE_UUID,
            now,
            direct_access,
            url
        )
        .execute(Db::conn())
        .await?;
        Ok(())
    }

    pub async fn find_all() -> Result<Vec<Self>, ErrorResponse> {
        query_as!(SealedEntity, "select * from sealed")
            .fetch_all(Db::conn())
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn delete() -> Result<(), ErrorResponse> {
        let db = Db::conn();
        query!("delete from sealed where id = $1", *INSTANCE_UUID)
            .execute(db)
            .await?;

        // cleanup possibly existing old entries for this very pub url
        if let Some(url) = &*DIRECT_ACCESS_PUB_URL {
            query!(
                "delete from sealed where direct_access = true and url = $1",
                url
            )
            .execute(db)
            .await?;
        }
        Ok(())
    }
}

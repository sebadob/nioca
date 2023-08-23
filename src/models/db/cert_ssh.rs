use crate::config::Db;
use crate::models::api::error_response::ErrorResponse;
use crate::models::db::client_ssh::ClientSshEntity;
use sqlx::{query, query_as};
use std::ops::Add;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct CertSshEntity {
    pub serial: i32,
    pub id: Uuid,
    pub created: OffsetDateTime,
    pub expires: OffsetDateTime,
    pub client_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub data: Vec<u8>,
}

// CRUD
impl CertSshEntity {
    pub async fn insert(&self) -> Result<Self, ErrorResponse> {
        query!(
            "insert into certs_ssh (id, created, expires, client_id, user_id, data) \
            values ($1, $2, $3, $4, $5, $6)",
            self.id,
            self.created,
            self.expires,
            self.client_id,
            self.user_id,
            self.data
        )
        .execute(Db::conn())
        .await?;

        // we need to query the entity again to get the generated serial
        let res = Self::find_by_id(&self.id).await?;

        Ok(res)
    }

    // pub async fn find_by_serial(db: DbPool, serial: i32) -> Result<Self, ErrorResponse> {
    //     query_as!(Self, "select * from certs where serial = $1", serial)
    //         .fetch_one(&db)
    //         .await
    //         .map_err(ErrorResponse::from)
    // }

    pub async fn find_by_id(uuid: &Uuid) -> Result<Self, ErrorResponse> {
        query_as!(Self, "select * from certs_ssh where id = $1", uuid)
            .fetch_one(Db::conn())
            .await
            .map_err(ErrorResponse::from)
    }

    // pub async fn find_all(db: DbPool) -> Result<Vec<Self>, ErrorResponse> {
    //     query_as!(Self, "select * from certs")
    //         .fetch_all(&db)
    //         .await
    //         .map_err(ErrorResponse::from)
    // }

    /// Creates a certificate entity with no `data` for getting the serial from the DB.
    pub async fn update_data(&self) -> Result<(), ErrorResponse> {
        query!(
            "update certs_ssh set data = $1 where serial = $2",
            self.data,
            self.serial
        )
        .execute(Db::conn())
        .await?;

        Ok(())
    }
}

impl From<&ClientSshEntity> for CertSshEntity {
    fn from(value: &ClientSshEntity) -> Self {
        let created = OffsetDateTime::now_utc();
        let expires = created.add(time::Duration::seconds(value.valid_secs as i64));
        Self {
            // Serial will be generated on the DB to have no inconsistencies
            serial: -1,
            id: Uuid::new_v4(),
            created,
            expires,
            client_id: Some(value.id),
            user_id: None,
            data: Vec::default(),
        }
    }
}

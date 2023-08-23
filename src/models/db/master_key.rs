use crate::config::Db;
use crate::models::api::error_response::ErrorResponse;
use sqlx::{query, query_as};
use time::OffsetDateTime;

#[derive(Debug, Clone, Default)]
pub struct MasterKeyEntity {
    pub initialized: Option<OffsetDateTime>,
    pub check_shard_1: Vec<u8>,
    pub check_shard_2: Vec<u8>,
    pub check_master: Vec<u8>,
    pub master_key: Vec<u8>,
    pub enc_key_active: Option<String>,
}

impl MasterKeyEntity {
    pub async fn build() -> Result<Self, ErrorResponse> {
        let rows = MasterKeyRow::find_all().await?;

        let mut slf = Self::default();

        for entry in rows {
            match entry.id.as_str() {
                "initialized" => {
                    let ts = entry.value.unwrap().parse::<i64>().unwrap();
                    let dt = OffsetDateTime::from_unix_timestamp(ts).unwrap();
                    slf.initialized = Some(dt);
                }
                "check_shard_1" => slf.check_shard_1 = hex::decode(entry.value.unwrap()).unwrap(),
                "check_shard_2" => slf.check_shard_2 = hex::decode(entry.value.unwrap()).unwrap(),
                "check_master" => slf.check_master = hex::decode(entry.value.unwrap()).unwrap(),
                "master_key" => slf.master_key = hex::decode(entry.value.unwrap()).unwrap(),
                "enc_key_active" => slf.enc_key_active = entry.value,
                _ => {}
            }
        }

        Ok(slf)
    }
}

#[derive(Debug, Clone, Default)]
pub struct MasterKeyRow {
    pub id: String,
    pub value: Option<String>,
}

impl MasterKeyRow {
    pub async fn find_all() -> Result<Vec<Self>, ErrorResponse> {
        query_as!(Self, "select * from master_key",)
            .fetch_all(Db::conn())
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn find_local_password() -> Result<String, ErrorResponse> {
        let slf = query_as!(Self, "select * from master_key where id = 'local_password'")
            .fetch_one(Db::conn())
            .await?;

        Ok(slf.value.expect("local password not set up correctly"))
    }

    pub async fn update_local_password(hash: &str) -> Result<(), ErrorResponse> {
        query!(
            "update master_key set value = $1 where id = 'local_password'",
            hash
        )
        .execute(Db::conn())
        .await?;

        Ok(())
    }
}

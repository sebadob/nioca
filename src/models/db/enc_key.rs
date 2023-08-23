use crate::certificates::encryption::decrypt;
use crate::config::Db;
use crate::models::api::error_response::ErrorResponse;
use sqlx::query_as;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct EncKeyEntity {
    pub id: Uuid,
    pub alg: String,
    pub value: Vec<u8>,
}

impl EncKeyEntity {
    pub async fn find(uuid: &Uuid, master_key: &[u8]) -> Result<Self, ErrorResponse> {
        let res = query_as!(Self, "select * from enc_keys where id = $1", uuid)
            .fetch_one(Db::conn())
            .await?;

        let dec = decrypt(res.value.as_slice(), master_key)?;

        Ok(Self {
            id: res.id,
            alg: res.alg,
            value: dec,
        })
    }
}

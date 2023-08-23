use crate::certificates::encryption::encrypt;
use crate::config::Db;
use crate::models::api::error_response::ErrorResponse;
use crate::models::db::enc_key::EncKeyEntity;
use crate::oidc::handler::OidcTokenSet;
use sqlx::{query, query_as};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct UserEntity {
    pub id: Uuid,
    pub email: String,
    pub enc_key_id: Option<Uuid>,
    pub token_set: Option<Vec<u8>>,
}

impl UserEntity {
    pub async fn insert(
        email: String,
        token_set: Option<&OidcTokenSet>,
        enc_key: &EncKeyEntity,
    ) -> Result<Self, ErrorResponse> {
        let id = Uuid::new_v4();
        let (token_set, enc_key_id) = if let Some(ts) = token_set {
            let bytes = bincode::serialize(ts).unwrap();
            let enc = encrypt(&bytes, &enc_key.value).unwrap();
            (Some(enc), Some(enc_key.id))
        } else {
            (None, None)
        };

        query!(
            "insert into users (id, email, enc_key_id, token_set) values ($1, $2, $3, $4)",
            id,
            email,
            enc_key_id,
            token_set,
        )
        .fetch_optional(Db::conn())
        .await?;

        Ok(Self {
            id,
            email,
            enc_key_id,
            token_set,
        })
    }

    // pub async fn find(db: DbPool, uuid: &Uuid) -> Result<Option<Self>, ErrorResponse> {
    //     let slf = query_as!(Self, "select * from users where id = $1", uuid)
    //         .fetch_optional(&*db)
    //         .await?;
    //
    //     Ok(slf)
    // }

    pub async fn find_by_email(email: &str) -> Result<Option<Self>, ErrorResponse> {
        let slf = query_as!(Self, "select * from users where email = $1", email)
            .fetch_optional(Db::conn())
            .await?;

        Ok(slf)
    }
}

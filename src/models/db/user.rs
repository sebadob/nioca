use crate::config::Db;
use crate::models::api::error_response::ErrorResponse;
use crate::oidc::principal::JwtIdClaims;
use sqlx::{query, query_as};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct UserEntity {
    pub id: Uuid,
    pub oidc_id: String,
    pub email: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
}

impl UserEntity {
    pub async fn insert(claims: &JwtIdClaims) -> Result<Self, ErrorResponse> {
        let slf = Self {
            id: Uuid::new_v4(),
            oidc_id: claims.sub.clone(),
            email: claims.email.clone(),
            given_name: claims.given_name.clone(),
            family_name: claims.family_name.clone(),
        };

        query!(
            r#"INSERT INTO
            users (id, oidc_id, email, given_name, family_name)
            VALUES ($1, $2, $3, $4, $5)"#,
            slf.id,
            slf.oidc_id,
            slf.email,
            slf.given_name,
            slf.family_name,
        )
        .fetch_optional(Db::conn())
        .await?;

        Ok(slf)
    }

    // pub async fn find(db: DbPool, uuid: &Uuid) -> Result<Option<Self>, ErrorResponse> {
    //     let slf = query_as!(Self, "select * from users where id = $1", uuid)
    //         .fetch_optional(&*db)
    //         .await?;
    //
    //     Ok(slf)
    // }

    // pub async fn find_by_email(email: &str) -> Result<Option<Self>, ErrorResponse> {
    //     let slf = query_as!(Self, "SELECT * FROM users WHERE email = $1", email)
    //         .fetch_optional(Db::conn())
    //         .await?;
    //
    //     Ok(slf)
    // }

    pub async fn find_all() -> Result<Vec<Self>, ErrorResponse> {
        let res = query_as!(Self, "SELECT * FROM users")
            .fetch_all(Db::conn())
            .await?;
        Ok(res)
    }

    pub async fn find_by_oidc_id(oidc_id: &str) -> Result<Option<Self>, ErrorResponse> {
        let slf = query_as!(Self, "SELECT * FROM users WHERE oidc_id = $1", oidc_id)
            .fetch_optional(Db::conn())
            .await?;

        Ok(slf)
    }

    pub async fn save(&self) -> Result<(), ErrorResponse> {
        query!(
            r#"UPDATE users
            SET email = $1, given_name = $2, family_name = $3
            WHERE id = $4"#,
            self.email,
            self.given_name,
            self.family_name,
            self.id,
        )
        .execute(Db::conn())
        .await?;

        Ok(())
    }

    pub async fn update_check(&self, claims: &JwtIdClaims) -> Result<(), ErrorResponse> {
        if self.email != claims.email
            || self.given_name != claims.given_name
            || self.family_name != claims.family_name
        {
            self.save().await?;
        }

        Ok(())
    }
}

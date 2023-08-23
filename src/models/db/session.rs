use crate::config::Db;
use crate::constants::{SESSION_TIMEOUT, SESSION_TIMEOUT_NEW};
use crate::models::api::error_response::ErrorResponse;
use crate::models::db::config_oidc::JwtClaimTyp;
use crate::models::db::enc_key::EncKeyEntity;
use crate::models::db::user::UserEntity;
use crate::oidc::handler::OidcTokenSet;
use crate::oidc::principal::JwtIdClaims;
use crate::oidc::validation::OIDC_CONFIG;
use crate::util::secure_random;
use sqlx::{query, query_as};
use std::ops::{Add, Sub};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SessionEntity {
    pub id: Uuid,
    pub local: bool,
    pub created: OffsetDateTime,
    pub expires: OffsetDateTime,
    pub xsrf: String,
    pub authenticated: bool,
    pub user_id: Option<Uuid>,
    pub email: Option<String>,
    pub roles: Option<String>,
    pub groups: Option<String>,
    pub is_admin: Option<bool>,
    pub is_user: Option<bool>,
}

impl SessionEntity {
    pub async fn new_local(// user_id: Option<Uuid>,
        // email: Option<String>,
        // roles: Option<Vec<String>>,
        // groups: Option<Vec<String>>,
    ) -> Result<Self, ErrorResponse> {
        let id = Uuid::new_v4();
        let xsrf = secure_random(48);
        let created = OffsetDateTime::now_utc();
        let expires = created.add(SESSION_TIMEOUT_NEW);

        // let slf = if user_id.is_some() {
        //     let rls = roles.map(|r| vec_to_csv(&r));
        //     let grps = groups.map(|g| vec_to_csv(&g));
        //
        //     Self {
        //         id,
        //         local: false,
        //         created,
        //         expires,
        //         xsrf,
        //         authenticated: false,
        //         user_id,
        //         email,
        //         roles: rls,
        //         groups: grps,
        //         is_admin: true,
        //         is_user: true,
        //     }
        // } else {
        let slf = Self {
            id,
            local: true,
            created,
            expires,
            xsrf,
            authenticated: false,
            user_id: None,
            email: None,
            roles: None,
            groups: None,
            is_admin: Some(true),
            is_user: Some(true),
        };
        // };

        slf.insert().await?;
        // query!(
        //         "insert into sessions (id, local, created, expires, xsrf, authenticated, email, roles, groups) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        //         slf.id, slf.local, slf.created, slf.expires, slf.xsrf, slf.authenticated, slf.email, slf.roles, slf.groups,
        //     )
        //     .execute(&*db)
        //     .await?;

        Ok(slf)
    }

    // Expands the session timeout by the default value
    pub async fn expand(&self) -> Result<(), ErrorResponse> {
        let exp = OffsetDateTime::now_utc().add(SESSION_TIMEOUT);
        query!(
            "update sessions set expires = $1 where id = $2",
            exp,
            self.id
        )
        .execute(Db::conn())
        .await?;
        Ok(())
    }

    pub async fn insert(&self) -> Result<(), ErrorResponse> {
        query!(
            "insert into sessions (id, local, created, expires, xsrf, authenticated, user_id, email, \
                roles, groups, is_admin, is_user) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            self.id,
            self.local,
            self.created,
            self.expires,
            self.xsrf,
            self.authenticated,
            self.user_id,
            self.email,
            self.roles,
            self.groups,
            self.is_admin,
            self.is_user,
        )
            .execute(Db::conn())
        .await?;
        Ok(())
    }

    // pub async fn find_all(db: DbPool) -> Result<Vec<Self>, ErrorResponse> {
    //     query_as!(Self, "select * from sessions")
    //         .fetch_all(&db)
    //         .await
    //         .map_err(ErrorResponse::from)
    // }

    pub async fn find(id: Uuid) -> Result<Self, ErrorResponse> {
        query_as!(Self, "select * from sessions where id = $1", id)
            .fetch_one(Db::conn())
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn from_id_claims(
        enc_key: &EncKeyEntity,
        claims: JwtIdClaims,
        ts: &OidcTokenSet,
    ) -> Result<Self, ErrorResponse> {
        let id = Uuid::new_v4();
        let xsrf = secure_random(48);
        let created = OffsetDateTime::now_utc();
        let expires = created.add(SESSION_TIMEOUT);

        let user = if let Some(user) = UserEntity::find_by_email(&claims.email).await? {
            user
        } else {
            UserEntity::insert(claims.email.clone(), Some(ts), enc_key).await?
        };
        let roles = claims.roles.join(",");
        let groups = claims.groups.map(|g| g.join(","));

        let (is_admin, is_user) = {
            let config = OIDC_CONFIG.read().await;
            let config = config.as_ref().unwrap();

            let is_admin = if let Some(claim) = &config.admin_claim {
                match claim.typ {
                    JwtClaimTyp::Roles => roles.contains(&claim.value),
                    JwtClaimTyp::Groups => {
                        groups.is_some() && groups.as_ref().unwrap().contains(&claim.value)
                    }
                }
            } else {
                true
            };
            let is_user = if let Some(claim) = &config.user_claim {
                match claim.typ {
                    JwtClaimTyp::Roles => roles.contains(&claim.value),
                    JwtClaimTyp::Groups => {
                        groups.is_some() && groups.as_ref().unwrap().contains(&claim.value)
                    }
                }
            } else {
                true
            };

            (is_admin, is_user)
        };

        let slf = Self {
            id,
            local: false,
            created,
            expires,
            xsrf,
            authenticated: true,
            user_id: Some(user.id),
            email: Some(user.email),
            roles: Some(roles),
            groups,
            is_admin: Some(is_admin),
            is_user: Some(is_user),
        };

        slf.insert().await?;

        Ok(slf)
    }

    // pub async fn delete(db: DbPool, id: Uuid) -> Result<(), ErrorResponse> {
    //     query!("delete from sessions where id = $1", id)
    //         .execute(&db)
    //         .await?;
    //     Ok(())
    // }

    /// Deletes all sessions that have expired more than 1 hour ago
    pub async fn delete_expired() -> Result<(), ErrorResponse> {
        let threshold = OffsetDateTime::now_utc().sub(time::Duration::hours(1));
        query!("delete from sessions where expires < $1", threshold)
            .execute(Db::conn())
            .await?;
        Ok(())
    }

    pub async fn invalidate(id: Uuid) -> Result<(), ErrorResponse> {
        let now = OffsetDateTime::now_utc().sub(time::Duration::seconds(10));
        query!("update sessions set expires = $1 where id = $2", now, id)
            .execute(Db::conn())
            .await?;
        Ok(())
    }

    // Expands the session timeout by the default value and sets it to authenticated
    pub async fn set_authenticated(&self) -> Result<(), ErrorResponse> {
        let exp = OffsetDateTime::now_utc().add(SESSION_TIMEOUT);
        query!(
            "update sessions set expires = $1, authenticated = true where id = $2",
            exp,
            self.id
        )
        .execute(Db::conn())
        .await?;
        Ok(())
    }
}

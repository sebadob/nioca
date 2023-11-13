use crate::config::Db;
use crate::constants::{SESSION_TIMEOUT, SESSION_TIMEOUT_NEW};
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::db::config_oidc::JwtClaimTyp;
use crate::models::db::user::UserEntity;
use crate::oidc::principal::JwtIdClaims;
use crate::oidc::validation::OIDC_CONFIG;
use crate::util::secure_random;
use ring::digest;
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
    pub xsrf: Vec<u8>,
    pub authenticated: bool,
    pub user_id: Option<Uuid>,
    pub email: Option<String>,
    pub roles: Option<String>,
    pub groups: Option<String>,
    pub is_admin: Option<bool>,
    pub is_user: Option<bool>,
}

impl SessionEntity {
    /// Creates a new local session and returns (Session, XSRF_Token)
    pub async fn new_local() -> Result<(Self, String), ErrorResponse> {
        let id = Uuid::new_v4();
        let xsrf_plain = secure_random(48);
        let xsrf = Self::hash_xsrf(xsrf_plain.as_bytes()).as_ref().to_vec();
        let created = OffsetDateTime::now_utc();
        let expires = created.add(SESSION_TIMEOUT_NEW);

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

        slf.insert().await?;

        Ok((slf, xsrf_plain))
    }

    // Expands the session timeout by the default value
    pub async fn expand(&self) -> Result<(), ErrorResponse> {
        let exp = OffsetDateTime::now_utc().add(SESSION_TIMEOUT);
        query!(
            "UPDATE sessions SET expires = $1 WHERE id = $2",
            exp,
            self.id
        )
        .execute(Db::conn())
        .await?;
        Ok(())
    }

    pub async fn insert(&self) -> Result<(), ErrorResponse> {
        query!(
            r#"INSERT INTO sessions
            (id, local, created, expires, xsrf, authenticated, user_id, email, roles, groups,
            is_admin, is_user)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
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

    pub async fn find(id: Uuid) -> Result<Self, ErrorResponse> {
        query_as!(Self, "SELECT * FROM sessions WHERE id = $1", id)
            .fetch_one(Db::conn())
            .await
            .map_err(ErrorResponse::from)
    }

    /// Creates a new session from SSO and returns (Session, XSRF_Token)
    pub async fn from_id_claims(claims: JwtIdClaims) -> Result<(Self, String), ErrorResponse> {
        let id = Uuid::new_v4();
        let xsrf_plain = secure_random(48);
        let xsrf = Self::hash_xsrf(xsrf_plain.as_bytes()).as_ref().to_vec();
        let created = OffsetDateTime::now_utc();
        let expires = created.add(SESSION_TIMEOUT);

        let user = if let Some(user) = UserEntity::find_by_oidc_id(&claims.sub).await? {
            user.update_check(&claims).await?;
            user
        } else {
            UserEntity::insert(&claims).await?
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

        Ok((slf, xsrf_plain))
    }

    /// Deletes all sessions that have expired more than 1 hour ago
    pub async fn delete_expired() -> Result<(), ErrorResponse> {
        let threshold = OffsetDateTime::now_utc().sub(time::Duration::hours(1));
        query!("DELETE FROM sessions WHERE expires < $1", threshold)
            .execute(Db::conn())
            .await?;
        Ok(())
    }

    pub async fn invalidate(id: Uuid) -> Result<(), ErrorResponse> {
        let now = OffsetDateTime::now_utc().sub(time::Duration::seconds(10));
        query!("UPDATE sessions SET expires = $1 WHERE id = $2", now, id)
            .execute(Db::conn())
            .await?;
        Ok(())
    }

    #[inline]
    pub fn hash_xsrf(xsrf_token: &[u8]) -> digest::Digest {
        digest::digest(&digest::SHA256, xsrf_token)
    }

    // Expands the session timeout by the default value and sets it to authenticated
    pub async fn set_authenticated(&self) -> Result<(), ErrorResponse> {
        let exp = OffsetDateTime::now_utc().add(SESSION_TIMEOUT);
        query!(
            "UPDATE sessions SET expires = $1, authenticated = true WHERE id = $2",
            exp,
            self.id
        )
        .execute(Db::conn())
        .await?;
        Ok(())
    }

    #[inline]
    pub fn validate_xsrf(&self, xsrf_token: &str) -> Result<(), ErrorResponse> {
        let hash = Self::hash_xsrf(xsrf_token.as_bytes());
        if self.xsrf == hash.as_ref() {
            Ok(())
        } else {
            Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "Invalid XSRF Token",
            ))
        }
    }
}

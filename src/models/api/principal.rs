use crate::config::Config;
use crate::constants::XSRF_HEADER;
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::db::session::SessionEntity;
use crate::util::get_session_cookie;
use axum::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::Method;
use axum_extra::extract::CookieJar;
use serde::Serialize;
use std::fmt::Display;
use std::str::FromStr;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use uuid::Uuid;

/// The AuthorizedUser making requests to the API
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Principal {
    pub local: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<String>,
    pub session_id: Uuid,
    pub expires_utc: i64,
    pub is_admin: Option<bool>,
    pub is_user: Option<bool>,
}

impl Principal {
    pub fn from_session(session: SessionEntity) -> Self {
        let mut is_user = false;
        if let Some(admin) = session.is_admin {
            if admin {
                is_user = true;
            }
        }
        if let Some(user) = session.is_user {
            if user {
                is_user = true;
            }
        }

        Self {
            local: session.local,
            user_id: session.user_id,
            email: session.email,
            roles: session.roles,
            groups: session.groups,
            session_id: session.id,
            expires_utc: session.expires.unix_timestamp(),
            is_admin: session.is_admin,
            is_user: Some(is_user),
        }
    }

    pub fn is_admin(&self) -> Result<(), ErrorResponse> {
        if self.local {
            return Ok(());
        } else if let Some(a) = self.is_admin {
            if a {
                return Ok(());
            }
        }

        Err(ErrorResponse::new(
            ErrorResponseType::Forbidden,
            "Admin access only".to_string(),
        ))
    }

    pub fn is_user(&self, user_id: &str) -> Result<(), ErrorResponse> {
        if self.local {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "No Access to this users resource".to_string(),
            ));
        }

        let user_id = Uuid::from_str(user_id)?;
        if Some(user_id) == self.user_id {
            return Ok(());
        }

        Err(ErrorResponse::new(
            ErrorResponseType::Forbidden,
            "Admin access only".to_string(),
        ))
    }
}

impl Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "User-Id: {:?}\nEmail: {}\nRoles: {:?}\nGroups: {:?}",
            self.user_id,
            self.email.as_ref().unwrap_or(&"N/A".to_string()),
            self.roles,
            self.groups,
        )
    }
}

/// Axum traits implementation to extract the Principal early in the request
#[async_trait]
impl<S> FromRequestParts<S> for Principal
where
    S: Send + Sync,
    Arc<RwLock<Config>>: FromRef<S>,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract the cookies
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| {
                ErrorResponse::new(ErrorResponseType::Unauthorized, "Session Cookie is missing")
            })?;

        let sid = get_session_cookie(&jar)?;
        let session = SessionEntity::find(sid).await?;

        // check expiry
        if session.expires < OffsetDateTime::now_utc() {
            return Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "Your session has expired".to_string(),
            ));
        }

        // check session state
        if !session.authenticated {
            return Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "Unauthenticated Session".to_string(),
            ));
        }

        // Extract the xsrf
        let xsrf = parts.headers.get(XSRF_HEADER).ok_or_else(|| {
            ErrorResponse::new(
                ErrorResponseType::InvalidToken,
                "XSRF Token is missing".to_string(),
            )
        })?;
        // check xsrf
        if parts.method != Method::GET {
            session.validate_xsrf(xsrf.to_str().unwrap_or("UNKNOWN"))?;
        }

        // expand the session lifetime
        session.expand().await?;

        Ok(Principal::from_session(session))
    }
}

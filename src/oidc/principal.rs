use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::oidc::validation::{validate_token, TokenCacheReq};
use crate::oidc::{extract_token_claims, validate_access_claims};
use axum::extract::FromRequestParts;
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::http::request::Parts;
use axum::{async_trait, TypedHeader};
use serde::Deserialize;
use std::fmt::Display;
use std::sync::Arc;

/// The AuthorizedUser making requests to the API
#[derive(Debug)]
pub struct PrincipalOidc {
    pub id: String,
    pub preferred_username: Option<String>,
    pub subject: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub scope: String,
}

impl PrincipalOidc {
    /// Creates a Principal from a raw Base64 encoded JWT token.
    pub async fn from_raw_token(token: &str) -> Result<Self, ErrorResponse> {
        let claims = extract_token_claims::<JwtAccessClaims>(token)?;
        validate_access_claims(&claims).await?;

        let roles = if let Some(r) = claims.roles {
            r
        } else {
            Vec::default()
        };
        let groups = if let Some(g) = claims.groups {
            g
        } else {
            Vec::default()
        };

        Ok(Self {
            id: claims.uid,
            preferred_username: claims.preferred_username,
            subject: claims.sub,
            roles,
            groups,
            scope: claims.scope,
        })
    }

    // #[allow(dead_code)]
    // pub fn has_role(&self, role: &str) -> Result<(), ErrorResponse> {
    //     // Important: Never use `contains` directly on the string in this case, since it can lead
    //     // to false positives
    //     let rls = self.roles.iter().map(|r| r.as_str()).collect::<Vec<&str>>();
    //     if rls.contains(&role) {
    //         return Ok(());
    //     }
    //
    //     Err(ErrorResponse::new(
    //         ErrorResponseType::Unauthorized,
    //         "Access not allowed".to_string(),
    //     ))
    // }
    //
    // #[allow(dead_code)]
    // pub fn has_group(&self, group: &str) -> Result<(), ErrorResponse> {
    //     // Important: Never use `contains` directly on the string in this case, since it can lead
    //     // to false positives
    //     let grps = self
    //         .groups
    //         .iter()
    //         .map(|g| g.as_str())
    //         .collect::<Vec<&str>>();
    //     if grps.contains(&group) {
    //         return Ok(());
    //     }
    //
    //     Err(ErrorResponse::new(
    //         ErrorResponseType::Unauthorized,
    //         "Access not allowed".to_string(),
    //     ))
    // }

    // pub fn has_any_role(&self, roles: Vec<&str>) -> Result<(), ErrorResponse> {
    //     // Important: Never use `contains` in this case, since it can lead to false positives
    //     let rls = self.roles.iter().map(|r| r.as_str()).collect::<Vec<&str>>();
    //     for r in roles {
    //         if rls.contains(&r) {
    //             return Ok(());
    //         }
    //     }
    //     Err(ErrorResponse::new(
    //         ErrorResponseType::Unauthorized,
    //         "Access not allowed".to_string(),
    //     ))
    // }

    // #[allow(dead_code)]
    // pub async fn is_admin(&self) -> bool {
    //     let config = OIDC_CONFIG.read().await;
    //     let config = config.as_ref().unwrap();
    //
    //     if let Some(claim) = &config.admin_claim {
    //         match claim.typ {
    //             JwtClaimTyp::Roles => self.has_role(&claim.value).is_ok(),
    //             JwtClaimTyp::Groups => self.has_group(&claim.value).is_ok(),
    //         }
    //     } else {
    //         true
    //     }
    // }
    //
    // #[allow(dead_code)]
    // pub async fn is_user(&self) -> bool {
    //     let config = OIDC_CONFIG.read().await;
    //     let config = config.as_ref().unwrap();
    //
    //     if let Some(claim) = &config.user_claim {
    //         match claim.typ {
    //             JwtClaimTyp::Roles => self.has_role(&claim.value).is_ok(),
    //             JwtClaimTyp::Groups => self.has_group(&claim.value).is_ok(),
    //         }
    //     } else {
    //         true
    //     }
    // }
}

impl Display for PrincipalOidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Id: {}\nSubject: {}\nUsername: {:?}\nRoles: {:?}\nGroups: {:?}\nScope: {}",
            self.id, self.subject, self.preferred_username, self.roles, self.groups, self.scope,
        )
    }
}

/// Axum trains implementation to extract the Principal early in the reqeust
#[async_trait]
impl<S> FromRequestParts<S> for PrincipalOidc
where
    S: Send + Sync,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    ErrorResponse::new(
                        ErrorResponseType::InvalidToken,
                        "The Bearer Token is missing",
                    )
                })?;

        // validate the token
        match parts.extensions.get::<Arc<flume::Sender<TokenCacheReq>>>() {
            None => {
                return Err(ErrorResponse::new(
                    ErrorResponseType::Internal,
                    "Missing internal Token validation data",
                ))
            }
            Some(channel) => validate_token(bearer.token().to_string(), channel).await?,
        }

        PrincipalOidc::from_raw_token(bearer.token()).await
    }
}

#[derive(Debug, Deserialize)]
pub struct JwtAccessClaims {
    pub typ: JwtType,
    pub sub: String,
    pub azp: String,
    pub aud: String,
    pub iss: String,
    pub scope: String,
    pub allowed_origins: Option<Vec<String>>,
    // user part
    pub uid: String,
    pub preferred_username: Option<String>,
    pub roles: Option<Vec<String>>,
    pub groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct JwtIdClaims {
    pub typ: JwtType,
    pub sub: String,
    pub azp: String,
    pub aud: String,
    pub iss: String,
    pub nonce: Option<String>,
    pub preferred_username: String,
    pub email: String,
    pub email_verified: Option<bool>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub roles: Vec<String>,
    pub groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct JwtRefreshClaims {
    pub azp: String,
    pub typ: JwtType,
    pub uid: String,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub enum JwtType {
    Bearer,
    Id,
    Refresh,
}

use crate::certificates::{SshKeyAlg, X509KeyAlg, X509KeyUsages, X509KeyUsagesExt};
use crate::constants::{
    RE_CA_NAME, RE_CLIENT_NAME, RE_DNS_SIMPLE, RE_HEX, RE_INIT_KEY, RE_JWT_CLAIM, RE_JWT_SCOPE,
    RE_LINUX_USER, RE_MASTER_SHARD_KEY, RE_SUBJECT_NAME, RE_SUBJECT_NAME_OPT, RE_XSRF,
};
use crate::models::db::client_ssh::SshCertType;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::str::FromStr;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::{Validate, ValidationError};

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
pub struct AddMasterShardRequest {
    #[validate(regex(path = "RE_MASTER_SHARD_KEY", code = "[a-zA-Z0-9]{48}"))]
    pub key: String,
    #[validate(regex(path = "RE_XSRF", code = "[a-zA-Z0-9]{48}"))]
    pub xsrf: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientSshRequest {
    #[validate(regex(path = "RE_CLIENT_NAME", code = "[a-zA-Z0-9.*]+"))]
    pub name: String,
    /// The expiry as a UTC timestamp
    pub expires: Option<i64>,
    pub enabled: bool,
    pub key_alg: SshKeyAlg,
    pub group_id: Uuid,
    pub typ: SshCertType,
    #[validate(custom(function = "validate_vec_principal"))]
    pub principals: Vec<String>,
    pub force_command: Option<String>,
    pub source_addresses: Option<Vec<String>>,
    pub permit_x11_forwarding: Option<bool>,
    pub permit_agent_forwarding: Option<bool>,
    pub permit_port_forwarding: Option<bool>,
    pub permit_pty: Option<bool>,
    pub permit_user_rc: Option<bool>,
    #[validate(range(min = 1))]
    pub valid_secs: i32,
    // #[validate(email)]
    // pub email: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientX509Request {
    #[validate(regex(path = "RE_CLIENT_NAME", code = "[a-zA-Z0-9.*]+"))]
    pub name: String,
    /// The expiry as a UTC timestamp
    pub expires: Option<i64>,
    pub key_alg: X509KeyAlg,
    pub enabled: bool,
    pub group_id: Option<Uuid>,
    #[validate(regex(path = "RE_SUBJECT_NAME", code = "[a-zA-Z0-9.*-]+"))]
    pub common_name: String,
    #[validate(regex(path = "RE_SUBJECT_NAME_OPT", code = "[a-zA-Z0-9-.*\\s]+"))]
    pub country: Option<String>,
    #[validate(regex(path = "RE_SUBJECT_NAME_OPT", code = "[a-zA-Z0-9-.*\\s]+"))]
    pub locality: Option<String>,
    #[validate(regex(path = "RE_SUBJECT_NAME_OPT", code = "[a-zA-Z0-9-.*\\s]+"))]
    pub organizational_unit: Option<String>,
    #[validate(regex(path = "RE_SUBJECT_NAME_OPT", code = "[a-zA-Z0-9-.*\\s]+"))]
    pub organization: Option<String>,
    #[validate(regex(path = "RE_SUBJECT_NAME_OPT", code = "[a-zA-Z0-9-.*\\s]+"))]
    pub state_or_province: Option<String>,
    #[validate(custom(function = "validate_vec_dns_simple"))]
    pub alt_names_dns: Vec<String>,
    #[validate(custom(function = "validate_vec_ip_simple"))]
    pub alt_names_ip: Vec<String>,
    pub key_usage: Vec<X509KeyUsages>,
    pub key_usage_ext: Vec<X509KeyUsagesExt>,
    #[validate(range(min = 1))]
    pub valid_hours: i32,
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSshKeyRequest {
    #[validate(regex(path = "RE_CA_NAME", code = "[a-zA-Z0-9\\-_.\\s]+"))]
    pub name: Option<String>,
    #[validate(regex(path = "RE_HEX", code = "[a-fA-F0-9]"))]
    pub key_enc_hex: String,
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct GenerateSshKeyRequest {
    #[validate(regex(path = "RE_CA_NAME", code = "[a-zA-Z0-9\\-_.\\s]+"))]
    pub name: Option<String>,
    pub alg: SshKeyAlg,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct GroupCreateRequest {
    #[validate(regex(path = "RE_CA_NAME", code = "[a-zA-Z0-9\\-_.\\s]+"))]
    pub name: String,
    pub ca_ssh: Uuid,
    pub ca_x509: Uuid,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct GroupUpdateRequest {
    pub id: Uuid,
    #[validate(regex(path = "RE_CA_NAME", code = "[a-zA-Z0-9\\-_.\\s]+"))]
    pub name: String,
    pub enabled: bool,
    pub ca_ssh: Uuid,
    pub ca_x509: Uuid,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InitRequest {
    pub local_password: String,
    pub root_pem: String,
    pub it_pem: String,
    #[validate(regex(path = "RE_HEX", code = "[a-fA-F0-9]"))]
    pub it_key: String,
    pub it_password: String,
    #[validate(regex(path = "RE_INIT_KEY", code = "[a-zA-Z0-9]{32}"))]
    pub init_key: String,
    #[validate(regex(path = "RE_XSRF", code = "[a-zA-Z0-9]{48}"))]
    pub xsrf_key: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub password: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigOidcEntityRequest {
    pub admin_claim: Option<JwtClaimRequest>,
    pub user_claim: Option<JwtClaimRequest>,
    #[validate(regex(path = "RE_JWT_CLAIM", code = "[a-z0-9-_/,]{2,32}"))]
    pub aud: String,
    #[validate(regex(path = "RE_JWT_CLAIM", code = "[a-z0-9-_/,]{2,32}"))]
    pub client_id: String,
    pub email_verified: bool,
    pub iss: String,
    #[validate(regex(path = "RE_JWT_SCOPE", code = "[a-z0-9-_/,\\s]{2,32}"))]
    pub scope: String,
    pub secret: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct JwtClaimRequest {
    pub typ: JwtClaimTypRequest,
    #[validate(regex(path = "RE_JWT_CLAIM", code = "[a-z0-9-_/,]{2,32}"))]
    pub value: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct PasswordChangeRequest {
    #[validate(length(min = 16, max = 128))]
    pub current_password: String,
    #[validate(length(min = 16, max = 128))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum JwtClaimTypRequest {
    Roles,
    Groups,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct UnsealRequest {
    #[validate(regex(path = "RE_XSRF", code = "[a-zA-Z0-9]{48}"))]
    pub xsrf: String,
}

// #[derive(Debug, Deserialize, Validate, ToSchema)]
// #[serde(rename_all = "camelCase")]
// pub struct X509Request {
//     pub root_pem: String,
//     pub it_pem: String,
//     #[validate(regex(path = "RE_HEX", code = "[a-fA-F0-9]"))]
//     pub it_key: String,
//     pub it_password: String,
//     #[validate(regex(path = "RE_INIT_KEY", code = "[a-zA-Z0-9]{32}"))]
//     pub init_key: String,
//     #[validate(regex(path = "RE_XSRF", code = "[a-zA-Z0-9]{48}"))]
//     pub xsrf_key: String,
// }

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct X509CaAddRequest {
    #[validate(regex(path = "RE_CA_NAME", code = "[a-zA-Z0-9\\-_.\\s]+"))]
    pub name: String,
    pub root_pem: String,
    pub it_pem: String,
    #[validate(regex(path = "RE_HEX", code = "[a-fA-F0-9]"))]
    pub it_key: String,
    pub it_password: String,
}

fn validate_vec_dns_simple(value: &[String]) -> Result<(), ValidationError> {
    let mut err = None;
    value.iter().for_each(|v| {
        if !RE_DNS_SIMPLE.is_match(v) {
            err = Some("[a-zA-Z0-9.-*]+");
        }
    });
    if let Some(e) = err {
        return Err(ValidationError::new(e));
    }
    Ok(())
}

fn validate_vec_ip_simple(value: &[String]) -> Result<(), ValidationError> {
    let mut err = None;
    value.iter().for_each(|v| {
        if Ipv4Addr::from_str(v).is_err() {
            err = Some("IPv4 Address");
        }
    });
    if let Some(e) = err {
        return Err(ValidationError::new(e));
    }
    Ok(())
}

fn validate_vec_principal(value: &[String]) -> Result<(), ValidationError> {
    let mut err = None;
    value.iter().for_each(|v| {
        if !RE_LINUX_USER.is_match(v) {
            err = Some("valid linux username: ^[a-z0-9-_@.]{2,30}$");
        }
    });
    if let Some(e) = err {
        return Err(ValidationError::new(e));
    }
    Ok(())
}

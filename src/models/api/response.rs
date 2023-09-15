use crate::certificates::{CertFormat, SshKeyAlg, X509KeyUsages, X509KeyUsagesExt};
use crate::constants::OIDC_CALLBACK_URI;
use crate::models::api::principal::Principal;
use crate::models::db::ca_cert_ssh::{CaCertSshEntity, SshKeyPairOpenssh};
use crate::models::db::client_ssh::{ClientSshEntity, SshCertType};
use crate::models::db::client_x509::ClientX509Entity;
use crate::models::db::config_oidc::{ConfigOidcEntity, JwtClaim};
use crate::models::db::groups::GroupEntity;
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CaCertSshResponse {
    pub id: Uuid,
    pub name: String,
    pub pub_key: String,
}

impl From<CaCertSshEntity> for CaCertSshResponse {
    fn from(value: CaCertSshEntity) -> Self {
        Self {
            id: value.id,
            name: value.name,
            pub_key: value.pub_key,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CasSshResponse {
    pub cas_ssh: Vec<CaCertSshResponse>,
}

// #[derive(Debug, Serialize, ToSchema)]
// #[serde(rename_all = "camelCase")]
// pub struct CaCertSshResponse {
//     pub cert_id: Uuid,
//     pub group_id: Uuid,
//     pub is_default: bool,
//     pub group_name: String,
//     pub enabled: bool,
//     pub pub_key: String,
// }
//
// impl From<CaCertSshEntity> for CaCertSshResponse {
//     fn from(value: CaCertSshEntity) -> Self {
//         Self {
//             cert_id: value.cert_id,
//             group_id: value.group_id,
//             is_default: value.is_default,
//             group_name: value.group_name,
//             enabled: value.enabled,
//             pub_key: value.pub_key,
//         }
//     }
// }

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CasX509Response {
    pub cas_x509: Vec<CertificateInspectResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct X509CertificatesInspectResponse {
    pub root: CertificateInspectResponse,
    pub intermediate: CertificateInspectResponse,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct X509CertificatesOptInspectResponse {
    pub root: Option<CertificateInspectResponse>,
    pub root_pem: Option<String>,
    pub intermediate: Option<CertificateInspectResponse>,
    pub intermediate_pem: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInspectResponse {
    pub id: Uuid,
    pub name: String,
    pub issuer: String,
    pub serial: u64,
    pub subject: String,
    // pub subject_pki: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternative_name: Option<X509ExtensionResponse>,
    pub validity: X509ValidityResponse,
    pub version: String,
    pub signature_alg: String,
    pub is_ca: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_usages: Option<X509ExtensionResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_usages_ext: Option<X509ExtensionResponse>,
}

impl CertificateInspectResponse {
    pub fn from_certificate(id: Uuid, name: String, value: X509Certificate) -> Self {
        let issuer = value.issuer.to_string();
        let serial = value.serial.bits();
        let subject = value.subject.to_string();
        // let subject_pki = value.subject_pki.to_owned().algorithm.algorithm.to_string()
        let alternative_name = if let Ok(Some(alt_name)) = value.subject_alternative_name() {
            let mut value = vec![];
            for n in &alt_name.value.general_names {
                value.push(n.to_string());
            }
            Some(X509ExtensionResponse {
                critical: alt_name.critical,
                value,
            })
        } else {
            None
        };
        let validity = X509ValidityResponse {
            not_before: value.validity.not_before.to_string(),
            not_after: value.validity.not_after.to_string(),
        };
        let version = value.version.to_string();
        let signature_alg = value.signature.algorithm.to_string();
        let is_ca = value.is_ca();
        let key_usages = if let Ok(Some(usage)) = value.key_usage() {
            Some(X509ExtensionResponse {
                critical: usage.critical,
                value: vec![usage.value.to_string()],
            })
        } else {
            None
        };
        let key_usages_ext = if let Ok(Some(ext)) = value.extended_key_usage() {
            // let mut enabled = vec![];
            // for ena in ext.value.
            info!("extended: {:?}", ext);
            Some(X509ExtensionResponse {
                critical: ext.critical,
                value: vec![],
            })
        } else {
            None
        };

        Self {
            id,
            name,
            issuer,
            serial,
            subject,
            alternative_name,
            validity,
            version,
            signature_alg,
            is_ca,
            key_usages,
            key_usages_ext,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertX509Response {
    pub cert: String,
    pub cert_fingerprint: String,
    pub cert_chain: String,
    pub key: String,
    pub cert_format: CertFormat,
    /// not after as a unix timestamp in seconds in UTC format
    pub not_after: i64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientSshResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
    pub enabled: bool,
    pub key_alg: SshKeyAlg,
    pub group_id: Uuid,
    pub typ: SshCertType,
    pub principals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit_x11_forwarding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit_agent_forwarding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit_port_forwarding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit_pty: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit_user_rc: Option<bool>,
    pub valid_secs: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_cert: Option<i32>,
    // pub email: String,
}

impl From<ClientSshEntity> for ClientSshResponse {
    fn from(value: ClientSshEntity) -> Self {
        let key_alg = SshKeyAlg::from_str(&value.key_alg);
        let typ = SshCertType::from_str(&value.typ);
        let principals = value
            .principals
            .split(',')
            .map(String::from)
            .collect::<Vec<String>>();
        let source_addresses = value
            .source_addresses
            .map(|a| a.split(',').map(String::from).collect::<Vec<String>>());

        Self {
            id: value.id,
            name: value.name,
            expires: value.expires.map(|ts| ts.unix_timestamp()),
            enabled: value.enabled,
            key_alg,
            group_id: value.group_id,
            typ,
            principals,
            force_command: value.force_command,
            source_addresses,
            permit_x11_forwarding: value.permit_x11_forwarding,
            permit_agent_forwarding: value.permit_agent_forwarding,
            permit_port_forwarding: value.permit_port_forwarding,
            permit_pty: value.permit_pty,
            permit_user_rc: value.permit_user_rc,
            valid_secs: value.valid_secs,
            latest_cert: value.latest_cert,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientX509Response {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
    pub enabled: bool,
    pub group_id: Uuid,
    pub key_alg: String,
    pub common_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organizational_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_or_province: Option<String>,
    pub alt_names_dns: Vec<String>,
    pub alt_names_ip: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_usage: Option<Vec<X509KeyUsages>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_usage_ext: Option<Vec<X509KeyUsagesExt>>,
    pub valid_hours: i32,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_cert: Option<i32>,
}

impl From<ClientX509Entity> for ClientX509Response {
    fn from(value: ClientX509Entity) -> Self {
        let key_usage = if let Some(mut bytes) = value.key_usage {
            let mut res = vec![];
            for b in bytes.drain(..) {
                res.push(X509KeyUsages::from_value(b));
            }
            Some(res)
        } else {
            None
        };
        let key_usage_ext = if let Some(mut bytes) = value.key_usage_ext {
            let mut res = vec![];
            for b in bytes.drain(..) {
                res.push(X509KeyUsagesExt::from_value(b));
            }
            Some(res)
        } else {
            None
        };
        let alt_names_dns = value
            .alt_names_dns
            .split(',')
            .map(|n| n.trim().to_string())
            .collect::<Vec<String>>();
        let alt_names_ip = value
            .alt_names_ip
            .split(',')
            .map(|n| n.trim().to_string())
            .collect::<Vec<String>>();

        Self {
            id: value.id,
            name: value.name,
            expires: value.expires.map(|ts| ts.unix_timestamp()),
            enabled: value.enabled,
            group_id: value.group_id,
            key_alg: value.key_alg,
            common_name: value.common_name,
            country: value.country,
            locality: value.locality,
            organizational_unit: value.organizational_unit,
            organization: value.organization,
            state_or_province: value.state_or_province,
            alt_names_dns,
            alt_names_ip,
            key_usage,
            key_usage_ext,
            valid_hours: value.valid_hours,
            email: value.email,
            latest_cert: value.latest_cert,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClientX509CertResponse {
    pub cert: String,
    pub chain: String,
    pub key: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSecretResponse {
    pub secret: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigOidcEntityResponse {
    pub admin_claim: Option<JwtClaim>,
    pub user_claim: Option<JwtClaim>,
    pub aud: String,
    pub client_id: String,
    pub email_verified: bool,
    pub iss: String,
    pub redirect_uri: String,
    pub scope: String,
    pub secret: String,
}

impl From<ConfigOidcEntity> for ConfigOidcEntityResponse {
    fn from(value: ConfigOidcEntity) -> Self {
        Self {
            admin_claim: value.admin_claim,
            user_claim: value.user_claim,
            aud: value.aud,
            client_id: value.client_id,
            email_verified: value.email_verified,
            iss: value.iss,
            redirect_uri: OIDC_CALLBACK_URI.clone(),
            scope: value.scope,
            secret: value.secret,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupResponse {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub ca_ssh: Option<Uuid>,
    pub ca_x509: Option<Uuid>,
}

impl From<GroupEntity> for GroupResponse {
    fn from(value: GroupEntity) -> Self {
        Self {
            id: value.id,
            name: value.name,
            enabled: value.enabled,
            ca_ssh: value.ca_ssh,
            ca_x509: value.ca_x509,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthCheckResponse {
    pub principal: Principal,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xsrf: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshCertificateResponse {
    pub user_ca_pub: String,
    pub host_key_pair: SshKeyPairOpenssh,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct X509ExtensionResponse {
    pub critical: bool,
    pub value: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct X509ValidityResponse {
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InitResponse {
    pub master_shard_1: String,
    pub master_shard_2: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub xsrf: String,
    pub expires: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SealedStatus {
    pub is_initialized: bool,
    pub is_sealed: bool,
    pub master_shard_1: bool,
    pub master_shard_2: bool,
    pub is_ready: bool,
    pub key_add_rate_limit: u32,
}

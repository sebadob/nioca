use std::env;

use utoipa::openapi::Server;
use utoipa::{openapi, OpenApi};

use crate::certificates;
use crate::constants::PUB_URL_WITH_SCHEME;
use crate::models::api::error_response;
use crate::models::api::request;
use crate::models::api::response;
use crate::routes::clients_ssh;
use crate::routes::clients_x509;
use crate::routes::oidc;
use crate::routes::sealed;
use crate::routes::unsealed;
use crate::routes::users;
use crate::service;
use crate::VERSION;

/// The OpenAPI Documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        clients_ssh::get_clients,
        clients_ssh::post_client,
        clients_ssh::get_client,
        clients_ssh::put_client,
        clients_ssh::get_client_secret,
        clients_x509::get_clients,
        clients_x509::post_client,
        clients_x509::get_client,
        clients_x509::put_client,
        clients_x509::get_client_secret,
        clients_x509::post_build_client_cert,
        oidc::get_oidc_exists,
        oidc::get_config_oidc,
        oidc::put_config_oidc,
        users::get_users,
        users::get_user_group_access,
        users::post_user_group_access,
        sealed::post_init,
        sealed::post_init_check,
        sealed::post_master_shard,
        sealed::get_status,
        sealed::post_unseal,
        sealed::get_xsrf,
        unsealed::post_login,
        unsealed::get_login_check,
        unsealed::post_session,
        unsealed::get_status,
    ),
    components(
        schemas(
            certificates::CertFormat,
            certificates::SshKeyAlg,
            certificates::X509KeyAlg,
            certificates::X509KeyUsages,
            certificates::X509KeyUsagesExt,
            error_response::ErrorResponse,
            error_response::ErrorResponseType,
            request::AddMasterShardRequest,
            request::ClientSshRequest,
            request::InitRequest,
            request::LoginRequest,
            request::ConfigOidcEntityRequest,
            request::JwtClaimRequest,
            request::JwtClaimTypRequest,
            request::UnsealRequest,
            response::CasSshResponse,
            response::CasX509Response,
            response::X509CertificatesInspectResponse,
            response::CertificateInspectResponse,
            response::CertX509Response,
            response::ClientSshResponse,
            response::ClientX509Response,
            response::ClientSecretResponse,
            response::X509ExtensionResponse,
            response::X509ValidityResponse,
            response::InitResponse,
            response::SessionResponse,
            response::SealedStatus,
            response::SshCertificateResponse,
            service::x509::CheckedCerts,
        ),
    ),
    tags(
        (name = "sealed", description = "Routes available in sealed status"),
        (name = "unsealed", description = "Generic routes in unsealed status"),
        (name = "ca", description = "X509 / SSH Certificate Authorities"),
        (name = "clients", description = "Client specific routes"),
        (name = "common", description = "Routes available in both states"),
        (name = "oidc", description = "OIDC config"),
    ),
)]
pub struct ApiDoc;

impl ApiDoc {
    pub fn build() -> openapi::OpenApi {
        // pub fn build(app_state: &web::Data<AppState>) -> openapi::OpenApi {
        let mut doc = Self::openapi();

        doc.info = openapi::Info::new("Nioca Certificate Authority", &format!("v{}", VERSION));

        // let desc = r#""#;
        // doc.info.description = Some(desc.to_string());

        // let mut contact = Contact::new();
        // contact.name = Some("".to_string());
        // contact.url = Some("".to_string());
        // contact.email = Some("".to_string());
        // doc.info.contact = Some(contact);

        let pub_port = env::var("PORT_HTTPS_PUB").unwrap_or_else(|_| "8443".to_string());
        let url = if &pub_port != "443" {
            format!("{}:{}/api", *PUB_URL_WITH_SCHEME, pub_port)
        } else {
            format!("{}/api", *PUB_URL_WITH_SCHEME)
        };
        doc.servers = Some(vec![Server::new(url)]);

        doc
    }
}

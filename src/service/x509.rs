use crate::certificates::encryption::{decrypt, kdf_danger_static};
use crate::certificates::x509::cert_from_key_pem;
use crate::certificates::x509::verification::{
    validate_x509, x509_der_from_bytes, x509_pem_from_bytes,
};
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::api::response::{CertificateInitInspectResponse, CertificateInspectResponse};
use crate::util::fingerprint;
use time::OffsetDateTime;
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;
use x509_parser::nom::AsBytes;

#[derive(Debug, ToSchema)]
pub struct CheckedCerts {
    pub root_exp: OffsetDateTime,
    pub root_cert_pem: String,
    pub root_fingerprint: String,
    pub nioca_exp: OffsetDateTime,
    pub nioca_cert_pem: String,
    pub nioca_fingerprint: String,
    pub nioca_key_plain: String,
}

pub async fn x509_ca_validate(
    // state: &ConfigSealed,
    root_pem: &str,
    it_pem: &str,
    it_key: &str,
    it_password: &str,
) -> Result<(CheckedCerts, CertificateInitInspectResponse), ErrorResponse> {
    // try to serialize the certificates

    // root certificate
    let root_fingerprint = fingerprint(root_pem.trim().as_bytes());
    let root_cert_pem = x509_pem_from_bytes(root_pem.as_bytes()).map_err(|err| {
        ErrorResponse::new(
            ErrorResponseType::BadRequest,
            format!("Bad Root PEM: {}", err.message),
        )
    })?;
    let root_cert = x509_der_from_bytes(root_cert_pem.contents.as_bytes())?;
    if !root_cert.is_ca() {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "The given root certificate is not a CA".to_string(),
        ));
    }
    // root certificates are always self-signed
    root_cert.verify_signature(None).map_err(|err| {
        let e = ErrorResponse::from(err);
        ErrorResponse::new(
            ErrorResponseType::BadRequest,
            format!("Root Certificate - {}", e.message),
        )
    })?;
    // validate additional parts of the certificate
    validate_x509(&root_cert).map_err(|_| {
        ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "The given certificate is invalid".to_string(),
        )
    })?;

    // intermediate certificate
    let it_fingerprint = fingerprint(it_pem.trim().as_bytes());
    let it_cert_pem = x509_pem_from_bytes(it_pem.as_bytes()).map_err(|err| {
        ErrorResponse::new(
            ErrorResponseType::BadRequest,
            format!("Bad Intermediate PEM: {}", err.message),
        )
    })?;
    let it_cert = x509_der_from_bytes(it_cert_pem.contents.as_bytes())?;
    if !it_cert.is_ca() {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "The given intermediate certificate is not a CA".to_string(),
        ));
    }
    // verify the signature with the roots public key
    it_cert
        .verify_signature(Some(root_cert.public_key()))
        .map_err(|err| {
            let e = ErrorResponse::from(err);
            ErrorResponse::new(
                ErrorResponseType::BadRequest,
                format!("Intermediate Certificate - {}", e.message),
            )
        })?;
    // validate additional parts of the certificate
    validate_x509(&it_cert).map_err(|_| {
        ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "The given certificate is invalid".to_string(),
        )
    })?;

    // try to decode the private key
    let key_bytes = match hex::decode(it_key.trim()) {
        Ok(b) => b,
        Err(err) => {
            error!("{}", err);
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "Cannot decode the intermediate key from HEX format".to_string(),
            ));
        }
    };
    // try to decrypt it with the given password
    let secret = kdf_danger_static(it_password.as_bytes()).await?;
    let key_plain = match decrypt(&key_bytes, secret.as_ref()) {
        Ok(k) => k,
        Err(err) => {
            error!("{}", err.message);
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "Cannot decrypt the Intermediate Private Key".to_string(),
            ));
        }
    };
    let ca_key_plain = match String::from_utf8(key_plain) {
        Ok(k) => k,
        Err(err) => {
            error!("{}", err);
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "Cannot parse the Intermediate Private Key to String".to_string(),
            ));
        }
    };
    // try to rebuild the full intermediate certificate
    let _it_cert_full = cert_from_key_pem(&ca_key_plain, &it_pem).await?;

    // everything is valid
    let checked_certs = CheckedCerts {
        root_exp: root_cert.validity.not_after.to_datetime(),
        root_cert_pem: root_pem.trim().to_string(),
        root_fingerprint,
        nioca_exp: it_cert.validity.not_after.to_datetime(),
        nioca_cert_pem: it_pem.trim().to_string(),
        nioca_fingerprint: it_fingerprint,
        nioca_key_plain: ca_key_plain,
    };

    // build the API response
    let name = "default".to_string();
    let resp = CertificateInitInspectResponse {
        root: CertificateInspectResponse::from_certificate(
            Uuid::default(),
            name.clone(),
            root_cert,
        ),
        intermediate: CertificateInspectResponse::from_certificate(Uuid::default(), name, it_cert),
    };

    Ok((checked_certs, resp))
}

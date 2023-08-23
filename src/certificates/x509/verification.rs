use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use tracing::error;
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::Pem;
use x509_parser::validate::{Validator, VecLogger, X509StructureValidator};

pub fn validate_x509(x509: &X509Certificate) -> Result<(), ErrorResponse> {
    // validate the general structure
    let mut it_logger = VecLogger::default();
    let is_valid = X509StructureValidator.validate(x509, &mut it_logger);
    for warning in it_logger.warnings() {
        error!("x509 validation warning: {}", warning);
    }
    for error in it_logger.errors() {
        error!("x509 validation error: {}", error);
    }
    if !is_valid || !it_logger.errors().is_empty() {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "The given certificate is invalid".to_string(),
        ));
    }

    // validate nbf and exp
    if !x509.validity.is_valid() {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "The given certificate has expired or is not yet valid".to_string(),
        ));
    }

    Ok(())
}

pub fn x509_pem_from_bytes(input: &[u8]) -> Result<Pem, ErrorResponse> {
    match x509_parser::pem::parse_x509_pem(input) {
        Ok((_, pem)) => Ok(pem),
        Err(err) => Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            format!("Cannot parse the input to a valid PEM: {}", err),
        )),
    }
}

pub fn x509_der_from_bytes(input: &[u8]) -> Result<X509Certificate, ErrorResponse> {
    match x509_parser::parse_x509_certificate(input) {
        Ok((_, cert)) => Ok(cert),
        Err(err) => Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            format!("Cannot parse the input to a valid DER: {}", err),
        )),
    }
}

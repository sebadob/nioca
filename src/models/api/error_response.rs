use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::DecodeError;
use bincode::ErrorKind;
use chacha20poly1305::Error;
use hex::FromHexError;
use rcgen::RcgenError;
use serde::Serialize;
use std::string::FromUtf8Error;
use std::time::SystemTimeError;
use tracing::error;
use utoipa::ToSchema;
use validator::ValidationErrors;
use x509_parser::error::X509Error;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub typ: ErrorResponseType,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, ToSchema, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ErrorResponseType {
    BadRequest,
    Connection,
    Database,
    DatabaseIo,
    Forbidden,
    Internal,
    InvalidToken,
    NotFound,
    Unauthorized,
    ServiceUnavailable,
    TooManyRequests,
}

impl ErrorResponse {
    pub fn new(t: ErrorResponseType, msg: impl Into<String>) -> Self {
        ErrorResponse {
            typ: t,
            message: msg.into(),
        }
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = match self.typ {
            ErrorResponseType::BadRequest => StatusCode::BAD_REQUEST,
            ErrorResponseType::Connection => StatusCode::SERVICE_UNAVAILABLE,
            ErrorResponseType::Forbidden => StatusCode::FORBIDDEN,
            ErrorResponseType::Unauthorized | ErrorResponseType::InvalidToken => {
                StatusCode::UNAUTHORIZED
            }
            ErrorResponseType::NotFound => StatusCode::NOT_FOUND,
            ErrorResponseType::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, Json(self)).into_response()
    }
}

/// Converts a [sqlx::Error](sqlx::Error) to [ErrorResponse](ErrorResponse)
impl From<sqlx::Error> for ErrorResponse {
    fn from(err: sqlx::Error) -> Self {
        let (error, msg) = match err {
            sqlx::Error::Configuration(e) => (ErrorResponseType::Database, e.to_string()),
            sqlx::Error::Database(e) => (ErrorResponseType::Database, e.to_string()),
            sqlx::Error::Io(e) => (ErrorResponseType::DatabaseIo, e.to_string()),
            sqlx::Error::RowNotFound => (ErrorResponseType::NotFound, "Row not found".to_string()),
            sqlx::Error::TypeNotFound { type_name } => (
                ErrorResponseType::NotFound,
                format!("Type not found: {}", type_name),
            ),
            sqlx::Error::ColumnNotFound(s) => (
                ErrorResponseType::NotFound,
                format!("Column not found: {}", s),
            ),
            sqlx::Error::PoolTimedOut => (
                ErrorResponseType::Internal,
                "Network error, please try again".to_string(),
            ),
            sqlx::Error::PoolClosed => (
                ErrorResponseType::Internal,
                "Network error, please try again".to_string(),
            ),
            e => {
                error!("Database Error: {:?}", e);
                (
                    ErrorResponseType::Internal,
                    "Internal error, please try again".to_string(),
                )
            }
        };

        Self {
            typ: error,
            message: msg,
        }
    }
}

impl From<reqwest::Error> for ErrorResponse {
    fn from(err: reqwest::Error) -> Self {
        let typ = if let Some(status) = err.status() {
            match status.as_u16() {
                x if x == 400 => ErrorResponseType::BadRequest,
                x if x == 401 => ErrorResponseType::Unauthorized,
                x if x == 404 => ErrorResponseType::NotFound,
                _ => ErrorResponseType::Internal,
            }
        } else {
            ErrorResponseType::Internal
        };

        ErrorResponse::new(typ, err.to_string())
    }
}

impl From<ValidationErrors> for ErrorResponse {
    fn from(err: ValidationErrors) -> Self {
        ErrorResponse::new(ErrorResponseType::BadRequest, err.to_string())
    }
}

impl From<tokio::task::JoinError> for ErrorResponse {
    fn from(_: tokio::task::JoinError) -> Self {
        Self {
            typ: ErrorResponseType::Internal,
            message: "Thread Join Error".to_string(),
        }
    }
}

impl From<chacha20poly1305::Error> for ErrorResponse {
    fn from(_: Error) -> Self {
        Self {
            typ: ErrorResponseType::Internal,
            message: "Internal Encryption Error".to_string(),
        }
    }
}

impl From<X509Error> for ErrorResponse {
    fn from(value: X509Error) -> Self {
        let err = match value {
            X509Error::Generic => "Generic",
            X509Error::InvalidVersion => "InvalidVersion",
            X509Error::InvalidSerial => "InvalidSerial",
            X509Error::InvalidAlgorithmIdentifier => "InvalidAlgorithmIdentifier",
            X509Error::InvalidX509Name => "InvalidX509Name",
            X509Error::InvalidDate => "InvalidDate",
            X509Error::InvalidSPKI => "InvalidSPKI",
            X509Error::InvalidSubjectUID => "InvalidSubjectUID",
            X509Error::InvalidIssuerUID => "InvalidIssuerUID",
            X509Error::InvalidExtensions => "InvalidExtensions",
            X509Error::InvalidAttributes => "InvalidAttributes",
            X509Error::DuplicateExtensions => "DuplicateExtensions",
            X509Error::DuplicateAttributes => "DuplicateAttributes",
            X509Error::InvalidSignatureValue => "InvalidSignatureValue",
            X509Error::InvalidTbsCertificate => "InvalidTbsCertificate",
            X509Error::InvalidUserCertificate => "InvalidUserCertificate",
            X509Error::InvalidCertificate => "InvalidCertificate",
            X509Error::SignatureVerificationError => "SignatureVerificationError",
            X509Error::SignatureUnsupportedAlgorithm => "SignatureUnsupportedAlgorithm",
            X509Error::InvalidNumber => "InvalidNumber",
            _ => "Internal Error",
        };
        let message = format!("X509 Error: {}", err);
        Self {
            typ: ErrorResponseType::BadRequest,
            message,
        }
    }
}

impl From<anyhow::Error> for ErrorResponse {
    fn from(value: anyhow::Error) -> Self {
        Self {
            typ: ErrorResponseType::BadRequest,
            message: value.to_string(),
        }
    }
}

impl From<uuid::Error> for ErrorResponse {
    fn from(err: uuid::Error) -> Self {
        error!("uuid::Error: {}", err);
        Self {
            typ: ErrorResponseType::BadRequest,
            message: "Cannot parse input to a valid UUID".to_string(),
        }
    }
}

impl From<FromUtf8Error> for ErrorResponse {
    fn from(err: FromUtf8Error) -> Self {
        error!("FromUtf8Error: {}", err);
        Self {
            typ: ErrorResponseType::Internal,
            message: "Internal Deserialization Error".to_string(),
        }
    }
}

impl From<RcgenError> for ErrorResponse {
    fn from(value: RcgenError) -> Self {
        error!("From<RcgenError>: {}", value);
        Self {
            typ: ErrorResponseType::Internal,
            message: "Internal certificate generation error".to_string(),
        }
    }
}

impl From<der::Error> for ErrorResponse {
    fn from(value: der::Error) -> Self {
        error!("From<der::Error>: {}", value);
        Self {
            typ: ErrorResponseType::Internal,
            message: "Internal PEM / DER serialization error".to_string(),
        }
    }
}

impl From<base64::DecodeError> for ErrorResponse {
    fn from(value: DecodeError) -> Self {
        error!("From<base64::DecodeError>: {}", value);
        Self {
            typ: ErrorResponseType::Internal,
            message: "Internal base64 decode error".to_string(),
        }
    }
}

impl From<Box<bincode::ErrorKind>> for ErrorResponse {
    fn from(value: Box<ErrorKind>) -> Self {
        error!("Bincode Error: {}", value);
        Self {
            typ: ErrorResponseType::Internal,
            message: "Internal Serialization Error".to_string(),
        }
    }
}

impl From<ssh_key::Error> for ErrorResponse {
    fn from(value: ssh_key::Error) -> Self {
        error!("From<Box<ssh_key::Error>>: {:?}", value);
        Self {
            typ: ErrorResponseType::BadRequest,
            message: "Bad SSH Key".to_string(),
        }
    }
}

impl From<FromHexError> for ErrorResponse {
    fn from(value: FromHexError) -> Self {
        let msg = match value {
            FromHexError::InvalidHexCharacter { .. } => "FromHexError::InvalidHexCharacter",
            FromHexError::OddLength => "FromHexError::OddLength",
            FromHexError::InvalidStringLength => "FromHexError::InvalidStringLength",
        };

        Self {
            typ: ErrorResponseType::BadRequest,
            message: format!("Hex Decoding Error: {}", msg),
        }
    }
}

impl From<SystemTimeError> for ErrorResponse {
    fn from(value: SystemTimeError) -> Self {
        error!("From<SystemTimeError>: {:?}", value);
        Self {
            typ: ErrorResponseType::Internal,
            message: "Internal Error with SystemTime, please check the logs".to_string(),
        }
    }
}

use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use rcgen::{ExtendedKeyUsagePurpose, KeyUsagePurpose};
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg};
use utoipa::ToSchema;

pub mod encryption;
pub mod ssh;
pub mod x509;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "UPPERCASE")]
pub enum CertType {
    X509,
    Ssh,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, clap::ValueEnum, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum CertFormat {
    Pem,
    Der,
    PKCS12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, clap::ValueEnum, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum SshKeyAlg {
    // Rsa,
    RsaSha256,
    RsaSha512,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
}

impl SshKeyAlg {
    pub fn as_str(&self) -> &str {
        match self {
            // Self::Rsa => "RSA",
            Self::RsaSha256 => "RSA_SHA256",
            Self::RsaSha512 => "RSA_SHA512",
            Self::EcdsaP256 => "ECDSA_P256",
            Self::EcdsaP384 => "ECDSA_P384",
            Self::Ed25519 => "ED25519",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            // "RSA" => Self::Rsa,
            "RSA_SHA256" => Self::RsaSha256,
            "RSA_SHA512" => Self::RsaSha512,
            "ECDSA_P256" => Self::EcdsaP256,
            "ECDSA_P384" => Self::EcdsaP384,
            "ED25519" => Self::Ed25519,
            _ => unreachable!(),
        }
    }

    pub fn from_alg(alg: Algorithm) -> Result<Self, ErrorResponse> {
        let err = || {
            Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "Supported SSH Key Algorithms: Ed25519, RsaSha256, RsaSha512, EcdsaP256, EcdsaP384"
                    .to_string(),
            ))
        };
        let a = match alg {
            Algorithm::Ed25519 => Self::Ed25519,
            Algorithm::Ecdsa { curve } => match curve {
                EcdsaCurve::NistP256 => Self::EcdsaP256,
                EcdsaCurve::NistP384 => Self::EcdsaP384,
                EcdsaCurve::NistP521 => return err(),
            },
            Algorithm::Rsa { hash } => {
                if hash.is_none() {
                    return err();
                }
                match hash.unwrap() {
                    HashAlg::Sha256 => Self::RsaSha256,
                    HashAlg::Sha512 => Self::RsaSha512,
                    _ => return err(),
                }
            }
            _ => return err(),
        };

        Ok(a)
    }

    pub fn as_alg(&self) -> Algorithm {
        match self {
            // SshKeyAlg::Rsa => Algorithm::Rsa { hash: None },
            SshKeyAlg::RsaSha256 => Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            SshKeyAlg::RsaSha512 => Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            SshKeyAlg::EcdsaP256 => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            SshKeyAlg::EcdsaP384 => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            SshKeyAlg::Ed25519 => Algorithm::Ed25519,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, clap::ValueEnum, ToSchema)]
#[allow(clippy::upper_case_acronyms)]
pub enum X509KeyAlg {
    RSA,
    ECDSA,
    EdDSA,
}

impl X509KeyAlg {
    pub fn as_str(&self) -> &str {
        match self {
            X509KeyAlg::RSA => "RSA",
            X509KeyAlg::ECDSA => "ECDSA",
            X509KeyAlg::EdDSA => "EdDSA",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "RSA" => Self::RSA,
            "ECDSA" => Self::ECDSA,
            "EdDSA" => Self::EdDSA,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, clap::ValueEnum, ToSchema)]
pub enum X509KeyUsages {
    DigitalSignature,
    ContentCommitment,
    CrlSign,
    DataEncipherment,
    DecipherOnly,
    EncipherOnly,
    KeyAgreement,
    KeyCertSign,
    KeyEncipherment,
}

impl X509KeyUsages {
    pub fn from_value(value: u8) -> Self {
        match value {
            0 => Self::DigitalSignature,
            2 => Self::KeyEncipherment,
            3 => Self::DataEncipherment,
            4 => Self::KeyAgreement,
            5 => Self::KeyCertSign,
            6 => Self::CrlSign,
            7 => Self::EncipherOnly,
            8 => Self::DecipherOnly,
            11 => Self::ContentCommitment,
            _ => unreachable!(),
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            X509KeyUsages::DigitalSignature => 0,
            X509KeyUsages::KeyEncipherment => 2,
            X509KeyUsages::DataEncipherment => 3,
            X509KeyUsages::KeyAgreement => 4,
            X509KeyUsages::KeyCertSign => 5,
            X509KeyUsages::CrlSign => 6,
            X509KeyUsages::EncipherOnly => 7,
            X509KeyUsages::DecipherOnly => 8,
            X509KeyUsages::ContentCommitment => 11,
        }
    }
}

impl From<X509KeyUsages> for KeyUsagePurpose {
    fn from(value: X509KeyUsages) -> Self {
        match value {
            X509KeyUsages::DigitalSignature => KeyUsagePurpose::DigitalSignature,
            X509KeyUsages::ContentCommitment => KeyUsagePurpose::ContentCommitment,
            X509KeyUsages::CrlSign => KeyUsagePurpose::CrlSign,
            X509KeyUsages::DataEncipherment => KeyUsagePurpose::DataEncipherment,
            X509KeyUsages::DecipherOnly => KeyUsagePurpose::DecipherOnly,
            X509KeyUsages::EncipherOnly => KeyUsagePurpose::EncipherOnly,
            X509KeyUsages::KeyAgreement => KeyUsagePurpose::KeyAgreement,
            X509KeyUsages::KeyCertSign => KeyUsagePurpose::KeyCertSign,
            X509KeyUsages::KeyEncipherment => KeyUsagePurpose::KeyEncipherment,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, clap::ValueEnum, ToSchema)]
pub enum X509KeyUsagesExt {
    Any,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    OcspSigning,
    ServerAuth,
    TimeStamping,
}

impl X509KeyUsagesExt {
    pub fn from_value(value: u8) -> Self {
        match value {
            0 => Self::Any,
            1 => Self::ClientAuth,
            2 => Self::CodeSigning,
            3 => Self::EmailProtection,
            4 => Self::OcspSigning,
            5 => Self::ServerAuth,
            6 => Self::TimeStamping,
            _ => unreachable!(),
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            X509KeyUsagesExt::Any => 0,
            X509KeyUsagesExt::ClientAuth => 1,
            X509KeyUsagesExt::CodeSigning => 2,
            X509KeyUsagesExt::EmailProtection => 3,
            X509KeyUsagesExt::OcspSigning => 4,
            X509KeyUsagesExt::ServerAuth => 5,
            X509KeyUsagesExt::TimeStamping => 6,
        }
    }
}

impl From<X509KeyUsagesExt> for ExtendedKeyUsagePurpose {
    fn from(value: X509KeyUsagesExt) -> Self {
        match value {
            X509KeyUsagesExt::Any => ExtendedKeyUsagePurpose::Any,
            X509KeyUsagesExt::ClientAuth => ExtendedKeyUsagePurpose::ClientAuth,
            X509KeyUsagesExt::CodeSigning => ExtendedKeyUsagePurpose::CodeSigning,
            X509KeyUsagesExt::EmailProtection => ExtendedKeyUsagePurpose::EmailProtection,
            X509KeyUsagesExt::OcspSigning => ExtendedKeyUsagePurpose::OcspSigning,
            X509KeyUsagesExt::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
            X509KeyUsagesExt::TimeStamping => ExtendedKeyUsagePurpose::TimeStamping,
        }
    }
}

pub async fn set_file_ro(path: &str) -> anyhow::Result<()> {
    #[cfg(target_family = "unix")]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;
        use tokio::fs;

        fs::File::open(path)
            .await?
            .set_permissions(Permissions::from_mode(0o600))
            .await?;
    }
    Ok(())
}

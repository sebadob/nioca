use rcgen::{Certificate, CertificateParams};

pub mod bootstrap;
pub mod end_entity;
pub mod intermediate;
pub mod root;
pub mod singing;
pub mod verification;

pub async fn cert_from_key_der(
    private_der: &[u8],
    cert_der: &[u8],
) -> Result<Certificate, anyhow::Error> {
    // build key pair from the private key
    let key_pair = match rcgen::KeyPair::from_der(private_der) {
        Ok(kp) => kp,
        Err(_) => {
            return Err(anyhow::Error::msg(
                "Error building the KeyPair. Either wrong password or a corrupted file.",
            ));
        }
    };

    // extract params from the originally created cert
    // note: only the for the signing operation needed values are extracted, all others will be default
    let params = CertificateParams::from_ca_cert_der(cert_der, key_pair).unwrap();

    // re-build the certificate
    let cert = rcgen::Certificate::from_params(params).unwrap();

    Ok(cert)
}

pub fn cert_from_key_pem(key: &str, cert_pem: &str) -> Result<Certificate, anyhow::Error> {
    // build key pair from the private key
    let key_pair = match rcgen::KeyPair::from_pem(key) {
        Ok(kp) => kp,
        Err(_) => {
            return Err(anyhow::Error::msg(
                "Error building the KeyPair. Either wrong password or a corrupted file.",
            ));
        }
    };

    // extract params from the originally created cert
    // note: only the for the signing operation needed values are extracted, all others will be default
    let params = CertificateParams::from_ca_cert_pem(cert_pem, key_pair).unwrap();

    // re-build the certificate
    let cert = rcgen::Certificate::from_params(params).unwrap();

    Ok(cert)
}

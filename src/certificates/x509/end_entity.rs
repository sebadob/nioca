use crate::certificates::x509::bootstrap::{
    check_out_dir, OUT_DIR_END_ENTITY, OUT_DIR_INTERMEDIATE, SERIAL_PATH,
};
use crate::certificates::x509::singing::{
    gen_ecdsa_key_pair, gen_ed25519_key_pair, gen_rsa_key_pair,
};
use crate::certificates::{set_file_ro, X509KeyAlg};
use crate::cli::X509CliOptions;
use crate::constants::DEV_MODE;
use crate::util::{csv_to_vec, fingerprint};
use base64::{engine::general_purpose, Engine as _};
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyIdMethod, KeyUsagePurpose, SanType,
};
use std::env;
use std::net::IpAddr;
use std::ops::{Add, Sub};
use std::str::FromStr;
use time::Duration;
use time::OffsetDateTime;
use tokio::fs;
use tracing::{error, info, warn};

// pub async fn end_entity_cert(
//     state: AppStateExtract,
//     req: X509Request,
// ) -> Result<(), anyhow::Error> {
//     // let key_pair = gen_ed25519_key_pair()?;
//     let key_pair = gen_ecdsa_key_pair()?;
//     // let key_pair = gen_rsa_key_pair(2048)?;
//
//     let mut params = CertificateParams::default();
//     // params.alg = &rcgen::PKCS_ED25519;
//     params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
//     // params.alg = &rcgen::PKCS_RSA_SHA256;
//     params.not_before = OffsetDateTime::now_utc().sub(Duration::minutes(10));
//     params.not_after = OffsetDateTime::now_utc().add(Duration::days(90));
//     params.serial_number = None;
//     params.subject_alt_names = vec![];
//
//     let mut sub = DistinguishedName::new();
//     let cn = format!("{} Intermediate", opt.common_name);
//     sub.push(DnType::CommonName, cn);
//     if let Some(country) = opt.country.as_ref() {
//         sub.push(DnType::CountryName, country);
//     }
//     if let Some(loc) = opt.locality.as_ref() {
//         sub.push(DnType::LocalityName, loc);
//     }
//     if let Some(ou) = opt.organizational_unit.as_ref() {
//         sub.push(DnType::OrganizationalUnitName, ou);
//     }
//     if let Some(org) = opt.organization.as_ref() {
//         sub.push(DnType::OrganizationName, org);
//     }
//     if let Some(st) = opt.state_province_name.as_ref() {
//         sub.push(DnType::StateOrProvinceName, st);
//     }
//     params.distinguished_name = sub;
//
//     params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
//     params.key_usages = vec![
//         KeyUsagePurpose::CrlSign,
//         KeyUsagePurpose::KeyCertSign,
//         KeyUsagePurpose::DigitalSignature,
//     ];
//     params.extended_key_usages = vec![];
//     params.name_constraints = None;
//     params.custom_extensions = vec![];
//     params.key_pair = Some(key_pair);
//     params.use_authority_key_identifier_extension = true;
//     params.key_identifier_method = KeyIdMethod::Sha256;
//
//     let cert = rcgen::Certificate::from_params(params)?;
//     let pem_serialized = cert.serialize_pem_with_signer(&root_ca)?;
//     let der_serialized = ::pem::parse(&pem_serialized).unwrap().contents;
//     let hash = ring::digest::digest(&ring::digest::SHA256, &der_serialized);
//     let fingerprint: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
//     let fingerprint_full = format!("sha256:{}", fingerprint);
//
//     fs::write(
//         format!("{}/intermediate.fingerprint", OUT_DIR_INTERMEDIATE),
//         fingerprint_full,
//     )
//     .await?;
//     fs::write(
//         format!("{}/intermediate.pem", OUT_DIR_INTERMEDIATE),
//         pem_serialized,
//     )
//     .await?;
//     fs::write(
//         format!("{}/intermediate.der", OUT_DIR_INTERMEDIATE),
//         der_serialized,
//     )
//     .await?;
//
//     // encrypt the key before saving it
//     let private_der = cert.serialize_private_key_der();
//     let private_enc = encrypt(private_der.as_slice(), secret).unwrap();
//     fs::write(
//         format!("{}/intermediate.key", OUT_DIR_INTERMEDIATE),
//         &private_enc,
//     )
//     .await?;
//
//     // save it as hex for convenience
//     let private_enc_hex = hex::encode(private_enc);
//     fs::write(
//         format!("{}/intermediate.key.hex", OUT_DIR_INTERMEDIATE),
//         private_enc_hex,
//     )
//     .await?;
//
//     println!("Building intermediate certificate successful\n");
//
//     Ok(())
// }

pub async fn nioca_server_cert(
    ca_cert: &Certificate,
    ca_chain: &str,
) -> Result<(String, String), anyhow::Error> {
    // pub async fn nioca_server_cert(ca_cert: &Certificate) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    // let key_pair = gen_ed25519_key_pair()?;
    let key_pair = gen_ecdsa_key_pair()?;
    // let key_pair = gen_rsa_key_pair(2048)?;

    let mut params = CertificateParams::default();
    // params.alg = &rcgen::PKCS_ED25519;
    params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
    // params.alg = &rcgen::PKCS_RSA_SHA256;
    params.key_pair = Some(key_pair);

    params.not_before = OffsetDateTime::now_utc().sub(Duration::minutes(10));
    params.not_after = OffsetDateTime::now_utc().add(Duration::days(375));
    let max_not_after = ca_cert.get_params().not_after.sub(Duration::minutes(1));
    if params.not_after > max_not_after {
        params.not_after = max_not_after;
        // TODO send out email notification in this case
        warn!("Cannot issue the certificate for the full duration because of a not long enough valid intermediate certificate");
    }
    params.serial_number = None;

    let cn = env::var("NIOCA_CERT_CN").expect("NIOCA_CERT_CN is missing");
    let dns_names = match env::var("NIOCA_CERT_ALT_NAMES_DNS") {
        Ok(s) => csv_to_vec(&s).into_iter().map(SanType::DnsName).collect(),
        Err(_) => Vec::default(),
    };
    let ips = match env::var("NIOCA_CERT_ALT_NAMES_IP") {
        Ok(s) => {
            let ips = csv_to_vec(&s);
            let mut v = Vec::with_capacity(ips.len());
            for ip in ips {
                match IpAddr::from_str(&ip) {
                    Ok(ip) => v.push(SanType::IpAddress(ip)),
                    Err(err) => {
                        error!("Skipping IP from NIOCA_CERT_ALT_NAMES_IP {}: {}", ip, err);
                    }
                }
            }
            v
        }
        Err(_) => Vec::default(),
    };
    params.subject_alt_names = Vec::with_capacity(1 + dns_names.len() + ips.len());
    params.subject_alt_names.push(SanType::DnsName(cn.clone()));
    for san_type in dns_names {
        params.subject_alt_names.push(san_type);
    }
    for san_type in ips {
        params.subject_alt_names.push(san_type);
    }

    let mut sub = DistinguishedName::new();
    sub.push(DnType::CommonName, cn);
    if let Ok(country) = env::var("NIOCA_CERT_C") {
        sub.push(DnType::CountryName, country);
    }
    if let Ok(loc) = env::var("NIOCA_CERT_L") {
        sub.push(DnType::LocalityName, loc);
    }
    if let Ok(ou) = env::var("NIOCA_CERT_OU") {
        sub.push(DnType::OrganizationalUnitName, ou);
    }
    if let Ok(org) = env::var("NIOCA_CERT_O") {
        sub.push(DnType::OrganizationName, org);
    }
    if let Ok(st) = env::var("NIOCA_CERT_ST") {
        sub.push(DnType::StateOrProvinceName, st);
    }
    params.distinguished_name = sub;

    params.is_ca = IsCa::ExplicitNoCa;

    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.name_constraints = None;
    params.custom_extensions = vec![];
    params.use_authority_key_identifier_extension = true;
    params.key_identifier_method = KeyIdMethod::Sha256;

    // create an sign the certificate
    let cert = Certificate::from_params(params)?;
    let pem_serialized = cert.serialize_pem_with_signer(ca_cert)?;
    let cert_chain = format!("{}{}", pem_serialized, ca_chain);
    // let der_serialized = ::pem::parse(&pem_serialized).unwrap().contents;
    // let der_serialized = cert.serialize_der_with_signer(&ca_cert)?;

    if *DEV_MODE {
        info!("\n{}", cert_chain);
    }

    // hash the cert fingerprint
    let fingerprint_full = fingerprint(pem_serialized.as_bytes());
    info!("Fingerprint Nioca WebServer: {}", fingerprint_full);

    // extract the private key
    // let private_der = cert.serialize_private_key_der();
    let private_pem = cert.serialize_private_key_pem();

    info!("Building Nioca WebServer Certificate successful");

    Ok((cert_chain, private_pem))
}

pub async fn end_entity_cert_cli(
    opt: &X509CliOptions,
    intermediate_ca: &Certificate,
) -> Result<(), anyhow::Error> {
    println!("Building end entity certificate");

    let out_dir_intermediate = format!("{}{}", opt.out_dir, OUT_DIR_INTERMEDIATE);
    let out_dir_end_entity = format!("{}{}", opt.out_dir, OUT_DIR_END_ENTITY);
    check_out_dir(&out_dir_end_entity, opt, true).await?;
    check_any_usages(opt);
    let serial = get_serial(opt).await?;

    let mut params = CertificateParams::default();

    let key_pair = match opt.key_alg {
        X509KeyAlg::RSA => {
            params.alg = &rcgen::PKCS_RSA_SHA256;
            gen_rsa_key_pair(2048)?
        }
        X509KeyAlg::ECDSA => {
            params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
            gen_ecdsa_key_pair()?
        }
        X509KeyAlg::EdDSA => {
            params.alg = &rcgen::PKCS_ED25519;
            gen_ed25519_key_pair()?
        }
    };
    params.key_pair = Some(key_pair);

    // make it valid "before 10 minutes" to avoid clock skew issues
    params.not_before = OffsetDateTime::now_utc().sub(Duration::minutes(10));
    params.not_after = OffsetDateTime::now_utc().add(Duration::days(opt.valid as i64));
    params.serial_number = Some(serial.into());

    let mut alt_names = vec![];
    for name in opt.alt_name_rfc.clone() {
        alt_names.push(SanType::Rfc822Name(name));
    }
    for ip in opt.alt_name_ip.clone() {
        alt_names.push(SanType::IpAddress(ip));
    }
    for uri in opt.alt_name_uri.clone() {
        alt_names.push(SanType::URI(uri));
    }
    for dns in opt.alt_name_dns.clone() {
        alt_names.push(SanType::DnsName(dns));
    }
    params.subject_alt_names = alt_names;

    let mut sub = DistinguishedName::new();
    sub.push(DnType::CommonName, &opt.common_name);
    if let Some(country) = opt.country.as_ref() {
        sub.push(DnType::CountryName, country);
    }
    if let Some(loc) = opt.locality.as_ref() {
        sub.push(DnType::LocalityName, loc);
    }
    if let Some(ou) = opt.organizational_unit.as_ref() {
        sub.push(DnType::OrganizationalUnitName, ou);
    }
    if let Some(org) = opt.organization.as_ref() {
        sub.push(DnType::OrganizationName, org);
    }
    if let Some(st) = opt.state_province_name.as_ref() {
        sub.push(DnType::StateOrProvinceName, st);
    }
    params.distinguished_name = sub;

    params.is_ca = IsCa::ExplicitNoCa;

    let mut key_usages = vec![];
    for u in opt.key_usage.clone() {
        key_usages.push(KeyUsagePurpose::from(u));
    }
    params.key_usages = key_usages;

    let mut extended_key_usages = vec![];
    for ext in opt.key_usage_ext.clone() {
        extended_key_usages.push(ExtendedKeyUsagePurpose::from(ext));
    }
    params.extended_key_usages = extended_key_usages;

    params.name_constraints = None;
    params.custom_extensions = vec![];
    params.use_authority_key_identifier_extension = true;
    params.key_identifier_method = KeyIdMethod::Sha256;

    let cert = rcgen::Certificate::from_params(params)?;
    let pem_serialized = cert.serialize_pem_with_signer(intermediate_ca)?;

    let path_chain = format!("{}/ca-chain.pem", out_dir_intermediate);
    let chain = fs::read_to_string(&path_chain).await?;
    let cert_chain = format!("{}{}", pem_serialized, chain);
    let chain_b64 = general_purpose::STANDARD.encode(cert_chain.as_bytes());
    // the second encoding makes it possible to just copy & paste the output into a k8s secret
    let chain_b64_twice = general_purpose::STANDARD.encode(chain_b64.as_bytes());

    // let der_serialized = cert.serialize_der_with_signer(intermediate_ca)?;
    let pem = ::pem::parse(&pem_serialized).unwrap();
    let der_serialized = pem.contents();
    let fingerprint_full = fingerprint(der_serialized);

    fs::write(
        format!("{}/{}/cert.fingerprint", out_dir_end_entity, serial),
        fingerprint_full,
    )
    .await?;
    let path_cert_pem = format!("{}/{}/cert.pem", out_dir_end_entity, serial);
    fs::write(&path_cert_pem, pem_serialized).await?;
    fs::write(
        format!("{}/{}/cert.der", out_dir_end_entity, serial),
        der_serialized,
    )
    .await?;
    fs::write(
        format!("{}/{}/cert-chain.pem", out_dir_end_entity, serial),
        cert_chain,
    )
    .await?;
    fs::write(
        format!("{}/{}/cert-chain.pem.b64", out_dir_end_entity, serial),
        chain_b64,
    )
    .await?;
    fs::write(
        format!("{}/{}/cert-chain.pem.b64-twice", out_dir_end_entity, serial),
        chain_b64_twice,
    )
    .await?;

    // end user certificates are not encrypted
    let private_pem = cert.serialize_private_key_pem();
    let key_b64 = general_purpose::STANDARD.encode(private_pem.as_bytes());
    // the second encoding makes it possible to just copy & paste the output into a k8s secret
    let key_b64_twice = general_purpose::STANDARD.encode(key_b64.as_bytes());

    let p = format!("{}/{}/key.pem", out_dir_end_entity, serial);
    fs::write(&p, &private_pem).await?;
    set_file_ro(&p).await?;

    let private_der = cert.serialize_private_key_der();
    let p = format!("{}/{}/key.der", out_dir_end_entity, serial);
    fs::write(&p, &private_der).await?;
    set_file_ro(&p).await?;

    let p = format!("{}/{}/key.pem.b64", out_dir_end_entity, serial);
    fs::write(&p, key_b64).await?;
    set_file_ro(&p).await?;

    let p = format!("{}/{}/key.pem.b64-twice", out_dir_end_entity, serial);
    fs::write(&p, key_b64_twice).await?;
    set_file_ro(&p).await?;

    // save it as hex for convenience
    let private_enc_hex = hex::encode(private_der);
    let p = format!("{}/{}/key.der.hex", out_dir_end_entity, serial);
    fs::write(&p, private_enc_hex).await?;
    set_file_ro(&p).await?;

    println!("Building end entity successful\n\n");

    let msg = format!(
        "You can inspect and validate the certificate with \
    external / trusted tools to your liking, for instance:\nInspect: \
    openssl x509 -in {} -text -noout\nValidate: \
    openssl verify --CAfile {} {}",
        path_cert_pem, path_chain, path_cert_pem
    );
    println!("{}", msg);

    Ok(())
}

fn has_any_usages(opt: &X509CliOptions) -> bool {
    !opt.key_usage.is_empty() || !opt.key_usage_ext.is_empty()
}

fn check_any_usages(opt: &X509CliOptions) {
    if !has_any_usages(opt) {
        println!(
            "Caution: The final certificates does not allow any usages. It will not be usable"
        );
    }
}

async fn get_serial(opt: &X509CliOptions) -> Result<u64, anyhow::Error> {
    let serial_path = format!("{}{}", opt.out_dir, SERIAL_PATH);
    let serial = match fs::read_to_string(&serial_path).await {
        Ok(s) => s.parse::<u64>().unwrap_or(0) + 1,
        Err(_) => 1u64,
    };
    println!("Serial for end entity: {}", serial);

    fs::create_dir(format!("{}{}/{}", opt.out_dir, OUT_DIR_END_ENTITY, serial)).await?;
    fs::write(&serial_path, serial.to_string()).await?;
    Ok(serial)
}

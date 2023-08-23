// use crate::certificates::bootstrap::{check_out_dir, OUT_DIR_END_ENTITY, SERIAL_PATH};
// use crate::certificates::singing::{gen_ecdsa_key_pair, gen_rsa_key_pair};
// use crate::certificates::X509KeyAlg;
// use crate::cli::BootstrapOptions;
// use rcgen::{
//     Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
//     KeyIdMethod, KeyUsagePurpose, SanType,
// };
// use std::env;
// use std::ops::{Add, Sub};
// use time::Duration;
// use time::OffsetDateTime;
// use tokio::fs;
// use tracing::info;
//
// // pub async fn end_entity_cert(
// //     state: AppStateExtract,
// //     req: X509Request,
// // ) -> Result<(), anyhow::Error> {
// //     // let key_pair = gen_ed25519_key_pair()?;
// //     let key_pair = gen_ecdsa_key_pair()?;
// //     // let key_pair = gen_rsa_key_pair(2048)?;
// //
// //     let mut params = CertificateParams::default();
// //     // params.alg = &rcgen::PKCS_ED25519;
// //     params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
// //     // params.alg = &rcgen::PKCS_RSA_SHA256;
// //     params.not_before = OffsetDateTime::now_utc().sub(Duration::minutes(10));
// //     params.not_after = OffsetDateTime::now_utc().add(Duration::days(90));
// //     params.serial_number = None;
// //     params.subject_alt_names = vec![];
// //
// //     let mut sub = DistinguishedName::new();
// //     let cn = format!("{} Intermediate", opt.common_name);
// //     sub.push(DnType::CommonName, cn);
// //     if let Some(country) = opt.country.as_ref() {
// //         sub.push(DnType::CountryName, country);
// //     }
// //     if let Some(loc) = opt.locality.as_ref() {
// //         sub.push(DnType::LocalityName, loc);
// //     }
// //     if let Some(ou) = opt.organizational_unit.as_ref() {
// //         sub.push(DnType::OrganizationalUnitName, ou);
// //     }
// //     if let Some(org) = opt.organization.as_ref() {
// //         sub.push(DnType::OrganizationName, org);
// //     }
// //     if let Some(st) = opt.state_province_name.as_ref() {
// //         sub.push(DnType::StateOrProvinceName, st);
// //     }
// //     params.distinguished_name = sub;
// //
// //     params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
// //     params.key_usages = vec![
// //         KeyUsagePurpose::CrlSign,
// //         KeyUsagePurpose::KeyCertSign,
// //         KeyUsagePurpose::DigitalSignature,
// //     ];
// //     params.extended_key_usages = vec![];
// //     params.name_constraints = None;
// //     params.custom_extensions = vec![];
// //     params.key_pair = Some(key_pair);
// //     params.use_authority_key_identifier_extension = true;
// //     params.key_identifier_method = KeyIdMethod::Sha256;
// //
// //     let cert = rcgen::Certificate::from_params(params)?;
// //     let pem_serialized = cert.serialize_pem_with_signer(&root_ca)?;
// //     let der_serialized = ::pem::parse(&pem_serialized).unwrap().contents;
// //     let hash = ring::digest::digest(&ring::digest::SHA256, &der_serialized);
// //     let fingerprint: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
// //     let fingerprint_full = format!("sha256:{}", fingerprint);
// //
// //     fs::write(
// //         format!("{}/intermediate.fingerprint", OUT_DIR_INTERMEDIATE),
// //         fingerprint_full,
// //     )
// //     .await?;
// //     fs::write(
// //         format!("{}/intermediate.pem", OUT_DIR_INTERMEDIATE),
// //         pem_serialized,
// //     )
// //     .await?;
// //     fs::write(
// //         format!("{}/intermediate.der", OUT_DIR_INTERMEDIATE),
// //         der_serialized,
// //     )
// //     .await?;
// //
// //     // encrypt the key before saving it
// //     let private_der = cert.serialize_private_key_der();
// //     let private_enc = encrypt(private_der.as_slice(), secret).unwrap();
// //     fs::write(
// //         format!("{}/intermediate.key", OUT_DIR_INTERMEDIATE),
// //         &private_enc,
// //     )
// //     .await?;
// //
// //     // save it as hex for convenience
// //     let private_enc_hex = hex::encode(private_enc);
// //     fs::write(
// //         format!("{}/intermediate.key.hex", OUT_DIR_INTERMEDIATE),
// //         private_enc_hex,
// //     )
// //     .await?;
// //
// //     println!("Building intermediate certificate successful\n");
// //
// //     Ok(())
// // }
//
// pub async fn nioca_server_cert(
//     ca_cert: &Certificate,
//     ca_chain: &str,
// ) -> Result<(String, String), anyhow::Error> {
//     // pub async fn nioca_server_cert(ca_cert: &Certificate) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
//     // let key_pair = gen_ed25519_key_pair()?;
//     let key_pair = gen_ecdsa_key_pair()?;
//     // let key_pair = gen_rsa_key_pair(2048)?;
//
//     let mut params = CertificateParams::default();
//     // params.alg = &rcgen::PKCS_ED25519;
//     params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
//     // params.alg = &rcgen::PKCS_RSA_SHA256;
//
//     params.not_before = OffsetDateTime::now_utc().sub(Duration::minutes(10));
//     params.not_after = OffsetDateTime::now_utc().add(Duration::days(375));
//     params.serial_number = None;
//
//     let cn = env::var("NIOCA_CERT_CN").expect("NIOCA_CERT_CN is missing");
//     params.subject_alt_names = vec![SanType::DnsName(cn.clone())];
//
//     let mut sub = DistinguishedName::new();
//     sub.push(DnType::CommonName, cn);
//     if let Ok(country) = env::var("NIOCA_CERT_C") {
//         sub.push(DnType::CountryName, country);
//     }
//     if let Ok(loc) = env::var("NIOCA_CERT_L") {
//         sub.push(DnType::LocalityName, loc);
//     }
//     if let Ok(ou) = env::var("NIOCA_CERT_OU") {
//         sub.push(DnType::OrganizationalUnitName, ou);
//     }
//     if let Ok(org) = env::var("NIOCA_CERT_O") {
//         sub.push(DnType::OrganizationName, org);
//     }
//     if let Ok(st) = env::var("NIOCA_CERT_ST") {
//         sub.push(DnType::StateOrProvinceName, st);
//     }
//     params.distinguished_name = sub;
//
//     params.is_ca = IsCa::ExplicitNoCa;
//
//     params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
//     params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
//     params.name_constraints = None;
//     params.custom_extensions = vec![];
//     params.key_pair = Some(key_pair);
//     params.use_authority_key_identifier_extension = true;
//     params.key_identifier_method = KeyIdMethod::Sha256;
//
//     // create an sign the certificate
//     let cert = rcgen::Certificate::from_params(params)?;
//     let pem_serialized = cert.serialize_pem_with_signer(&ca_cert)?;
//     let cert_chain = format!("{}{}", pem_serialized, ca_chain);
//     let der_serialized = cert.serialize_der_with_signer(&ca_cert)?;
//     info!("\n{}", pem_serialized);
//     info!("\n{}", cert_chain);
//
//     // hash the cert fingerprint
//     let digest = ring::digest::digest(&ring::digest::SHA256, &der_serialized);
//     let fingerprint: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
//     let fingerprint_full = format!("sha256:{}", fingerprint);
//     info!("Fingerprint Nioca WebServer: {}", fingerprint_full);
//
//     // extract the private key
//     // let private_der = cert.serialize_private_key_der();
//     let private_pem = cert.serialize_private_key_pem();
//
//     info!("Building Nioca WebServer Certificate successful");
//
//     Ok((cert_chain, private_pem))
// }
//
// pub async fn end_entity_cert_cli(
//     opt: &BootstrapOptions,
//     intermediate_ca: &Certificate,
// ) -> Result<(), anyhow::Error> {
//     println!("Building end entity certificate");
//
//     check_out_dir(OUT_DIR_END_ENTITY, opt, true).await?;
//     check_any_usages(opt);
//     let serial = get_serial().await?;
//
//     let mut params = CertificateParams::default();
//
//     let key_pair = match opt.key_alg {
//         X509KeyAlg::Rsa => {
//             params.alg = &rcgen::PKCS_RSA_SHA256;
//             gen_rsa_key_pair(2048)?
//         }
//         X509KeyAlg::Ecdsa => {
//             params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
//             gen_ecdsa_key_pair()?
//         }
//     };
//     params.key_pair = Some(key_pair);
//
//     // make it valid "before 10 minutes" to avoid clock skew issues
//     params.not_before = OffsetDateTime::now_utc().sub(Duration::minutes(10));
//     params.not_after = OffsetDateTime::now_utc().add(Duration::days(opt.valid as i64));
//     params.serial_number = Some(serial);
//
//     let mut alt_names = vec![];
//     for name in opt.alt_name_rfc.clone() {
//         alt_names.push(SanType::Rfc822Name(name));
//     }
//     for ip in opt.alt_name_ip.clone() {
//         alt_names.push(SanType::IpAddress(ip));
//     }
//     for uri in opt.alt_name_uri.clone() {
//         alt_names.push(SanType::URI(uri));
//     }
//     for dns in opt.alt_name_dns.clone() {
//         alt_names.push(SanType::DnsName(dns));
//     }
//     params.subject_alt_names = alt_names;
//
//     let mut sub = DistinguishedName::new();
//     sub.push(DnType::CommonName, &opt.common_name);
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
//     params.is_ca = IsCa::ExplicitNoCa;
//
//     let mut key_usages = vec![];
//     for u in opt.key_usage.clone() {
//         key_usages.push(KeyUsagePurpose::from(u));
//     }
//     params.key_usages = key_usages;
//
//     let mut extended_key_usages = vec![];
//     for ext in opt.key_usage_ext.clone() {
//         extended_key_usages.push(ExtendedKeyUsagePurpose::from(ext));
//     }
//     params.extended_key_usages = extended_key_usages;
//
//     params.name_constraints = None;
//     params.custom_extensions = vec![];
//     params.use_authority_key_identifier_extension = true;
//     params.key_identifier_method = KeyIdMethod::Sha256;
//
//     let cert = rcgen::Certificate::from_params(params)?;
//     let pem_serialized = cert.serialize_pem_with_signer(intermediate_ca)?;
//     let der_serialized = ::pem::parse(&pem_serialized).unwrap();
//     let der_pem_contents = der_serialized.contents();
//     let hash = ring::digest::digest(&ring::digest::SHA256, der_pem_contents);
//     let fingerprint: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
//     let fingerprint_full = format!("sha256:{}", fingerprint);
//
//     fs::write(
//         format!("{}/{}/cert.fingerprint", OUT_DIR_END_ENTITY, serial),
//         fingerprint_full,
//     )
//     .await?;
//     fs::write(
//         format!("{}/{}/cert.pem", OUT_DIR_END_ENTITY, serial),
//         pem_serialized,
//     )
//     .await?;
//     fs::write(
//         format!("{}/{}/cert.der", OUT_DIR_END_ENTITY, serial),
//         der_pem_contents,
//     )
//     .await?;
//
//     // end user certificates are not encrypted
//     let private_pem = cert.serialize_private_key_pem();
//     fs::write(
//         format!("{}/{}/key.pem", OUT_DIR_END_ENTITY, serial),
//         &private_pem,
//     )
//     .await?;
//     let private_der = cert.serialize_private_key_der();
//     fs::write(
//         format!("{}/{}/key.der", OUT_DIR_END_ENTITY, serial),
//         &private_der,
//     )
//     .await?;
//
//     // save it as hex for convenience
//     let private_enc_hex = hex::encode(private_der);
//     fs::write(
//         format!("{}/{}/key.der.hex", OUT_DIR_END_ENTITY, serial),
//         private_enc_hex,
//     )
//     .await?;
//
//     println!("Building end entity successful\n");
//
//     Ok(())
// }
//
// fn has_any_usages(opt: &BootstrapOptions) -> bool {
//     !opt.key_usage.is_empty() || !opt.key_usage_ext.is_empty()
// }
//
// fn check_any_usages(opt: &BootstrapOptions) {
//     if !has_any_usages(opt) {
//         println!(
//             "Caution: The final certificates does not allow for any usages. It will not be usable"
//         );
//     }
// }
//
// async fn get_serial() -> Result<u64, anyhow::Error> {
//     let serial = match fs::read_to_string(SERIAL_PATH).await {
//         Ok(s) => s.parse::<u64>().unwrap_or(0) + 1,
//         Err(_) => 1u64,
//     };
//     info!("Serial for end entity: {}", serial);
//
//     fs::create_dir(format!("{}/{}", OUT_DIR_END_ENTITY, serial)).await?;
//     fs::write(SERIAL_PATH, serial.to_string()).await?;
//     Ok(serial)
// }

// use crate::certificates::bootstrap::{check_out_dir, OUT_DIR_INTERMEDIATE, OUT_DIR_ROOT};
// use crate::certificates::encryption::{decrypt, encrypt, prompt_password};
// use crate::certificates::singing::{gen_ecdsa_key_pair, gen_rsa_key_pair};
// use crate::certificates::{cert_from_key_der, X509KeyAlg};
// use crate::cli::BootstrapOptions;
// use crate::util::get_rand_between;
// use rcgen::{
//     BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyIdMethod,
//     KeyUsagePurpose,
// };
// use ring::digest;
// use std::ops::{Add, Sub};
// use time::Duration;
// use time::OffsetDateTime;
// use tokio::fs;
//
// pub async fn build_intermediate_ca(
//     opt: &BootstrapOptions,
//     root_ca: &Certificate,
// ) -> Result<(), anyhow::Error> {
//     println!("Building intermediate certificate");
//
//     check_out_dir(OUT_DIR_INTERMEDIATE, opt, false).await?;
//
//     println!("Enter a new password for the Intermediate CA private key.\nThis should be different from the Root CA.");
//     let pwd = prompt_password("Password: ")?;
//     let pwd_confirm = prompt_password("Confirm Password: ")?;
//     if pwd != pwd_confirm {
//         return Err(anyhow::Error::msg("Passwords do not match"));
//     }
//
//     let digest = digest::digest(&digest::SHA256, pwd.as_bytes());
//     let secret = digest.as_ref();
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
//     // let key_pair = gen_ed25519_key_pair()?;
//     // params.alg = &rcgen::PKCS_ED25519;
//
//     // set the valid from to some random earlier time to not potentially leak information about
//     // the creation date and therefore make guessing random number generation harder
//     let nbf_sub = Duration::minutes(get_rand_between(1, 525600) as i64);
//     params.not_before = OffsetDateTime::now_utc().sub(nbf_sub);
//     params.not_after = OffsetDateTime::now_utc().add(Duration::days(opt.valid_intermediate as i64));
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
//     params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
//     params.key_usages = vec![
//         KeyUsagePurpose::CrlSign,
//         KeyUsagePurpose::KeyCertSign,
//         KeyUsagePurpose::DigitalSignature,
//     ];
//     params.extended_key_usages = vec![];
//     params.name_constraints = None;
//     params.custom_extensions = vec![];
//     params.use_authority_key_identifier_extension = true;
//     params.key_identifier_method = KeyIdMethod::Sha256;
//
//     let cert = rcgen::Certificate::from_params(params)?;
//     let pem_serialized = cert.serialize_pem_with_signer(root_ca)?;
//     let der_serialized = ::pem::parse(&pem_serialized).unwrap();
//     let der_pem_contents = der_serialized.contents();
//     let hash = ring::digest::digest(&ring::digest::SHA256, der_pem_contents);
//     let fingerprint: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
//     let fingerprint_full = format!("sha256:{}", fingerprint);
//
//     fs::write(
//         format!("{}/intermediate.fingerprint", OUT_DIR_INTERMEDIATE),
//         fingerprint_full,
//     )
//     .await?;
//     fs::write(
//         format!("{}/intermediate.cert.pem", OUT_DIR_INTERMEDIATE),
//         &pem_serialized,
//     )
//     .await?;
//     fs::write(
//         format!("{}/intermediate.cert.der", OUT_DIR_INTERMEDIATE),
//         der_pem_contents,
//     )
//     .await?;
//
//     // since some applications need the full chain, create such a file too
//     let root_pem = fs::read_to_string(format!("{}/root.cert.pem", OUT_DIR_ROOT)).await?;
//     let ca_chain = format!("{}{}", root_pem, pem_serialized);
//     fs::write(format!("{}/ca-chain.pem", OUT_DIR_INTERMEDIATE), ca_chain).await?;
//
//     // encrypt the key before saving it
//     let private_pem = cert.serialize_private_key_pem();
//     let private_pem_enc = encrypt(private_pem.as_bytes(), secret).unwrap();
//     fs::write(
//         format!("{}/intermediate.key.pem", OUT_DIR_INTERMEDIATE),
//         &private_pem_enc,
//     )
//     .await?;
//     let private_der = cert.serialize_private_key_der();
//     let private_der_enc = encrypt(private_der.as_slice(), secret).unwrap();
//     fs::write(
//         format!("{}/intermediate.key.der", OUT_DIR_INTERMEDIATE),
//         &private_der_enc,
//     )
//     .await?;
//
//     // save it as hex for convenience
//     let private_pem_enc_hex = hex::encode(private_pem_enc);
//     fs::write(
//         format!("{}/intermediate.key.pem.hex", OUT_DIR_INTERMEDIATE),
//         private_pem_enc_hex,
//     )
//     .await?;
//     let private_der_enc_hex = hex::encode(private_der_enc);
//     fs::write(
//         format!("{}/intermediate.key.der.hex", OUT_DIR_INTERMEDIATE),
//         &private_der_enc_hex,
//     )
//     .await?;
//
//     println!("Building intermediate certificate successful\n");
//
//     Ok(())
// }
//
// pub async fn intermediate_ca_from_folder() -> Result<Certificate, anyhow::Error> {
//     println!("Reading encrypted intermediate certificate from filesystem");
//
//     let pwd = prompt_password("Intermediate CA password: ")?;
//
//     let digest = digest::digest(&digest::SHA256, pwd.as_bytes());
//     let secret = digest.as_ref();
//
//     let path_key = format!("{}/intermediate.key.der", OUT_DIR_INTERMEDIATE);
//     let ca_key_enc = match fs::read(&path_key).await {
//         Ok(file) => file,
//         Err(_) => {
//             return Err(anyhow::Error::msg(format!(
//                 "Could not read Intermediate CA Key file from path '{}'\nBuild the Intermediate CA first!",
//                 path_key
//             )));
//         }
//     };
//     let ca_key_der = match decrypt(&ca_key_enc, secret) {
//         Ok(der) => der,
//         // if we get an error here, the file is either corrupt or not encrypted at all
//         Err(_) => ca_key_enc,
//     };
//
//     let path_cert = format!("{}/intermediate.cert.der", OUT_DIR_INTERMEDIATE);
//     let ca_cert_der = match fs::read(&path_cert).await {
//         Ok(file) => file,
//         Err(_) => {
//             return Err(anyhow::Error::msg(format!(
//                 "Could not read Intermediate CA cert file from path '{}'",
//                 path_cert
//             )));
//         }
//     };
//
//     let cert = cert_from_key_der(&ca_key_der, ca_cert_der.as_slice()).await?;
//
//     println!("Reading encrypted intermediate certificate from filesystem successful\n");
//     Ok(cert)
// }

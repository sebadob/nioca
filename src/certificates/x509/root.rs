use crate::certificates::encryption::{decrypt, encrypt, kdf_danger_static, prompt_password};
use crate::certificates::x509::bootstrap::{check_out_dir, OUT_DIR_ROOT};
use crate::certificates::x509::cert_from_key_der;
use crate::certificates::x509::singing::{
    gen_ecdsa_key_pair, gen_ed25519_key_pair, gen_rsa_key_pair,
};
use crate::certificates::X509KeyAlg;
use crate::cli::X509CliOptions;
use crate::util::{fingerprint, get_rand_between};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    GeneralSubtree, IsCa, KeyIdMethod, KeyUsagePurpose, NameConstraints,
};
use std::ops::{Add, Sub};
use time::Duration;
use time::OffsetDateTime;
use tokio::fs;

pub async fn build_root_ca(opt: &X509CliOptions) -> Result<(), anyhow::Error> {
    println!("Building root certificate");

    let out_dir_root = format!("{}{}", opt.out_dir, OUT_DIR_ROOT);
    check_out_dir(&out_dir_root, opt, false).await?;

    // Read in passwords
    println!("Enter a new Root CA password.");
    let pwd = prompt_password("Password: ")?;
    let pwd_confirm = prompt_password("Confirm Password: ")?;
    if pwd != pwd_confirm {
        return Err(anyhow::Error::msg("Passwords do not match"));
    }
    if pwd.len() < 16 {
        return Err(anyhow::Error::msg(
            "The password should be at least 16 characters long",
        ));
    }

    // build secret key
    let secret = kdf_danger_static(pwd.as_bytes()).await?;

    let mut params = CertificateParams::default();

    let key_pair = match opt.key_alg {
        X509KeyAlg::RSA => {
            params.alg = &rcgen::PKCS_RSA_SHA256;
            gen_rsa_key_pair(4096)?
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

    // let key_pair = gen_ed25519_key_pair()?;
    // params.alg = &rcgen::PKCS_ED25519;

    // set the valid from to some random earlier time to not potentially leak information about
    // the creation date and therefore make guessing random number generation harder
    let nbf_sub = Duration::minutes(get_rand_between(525600, 1051200) as i64);
    params.not_before = OffsetDateTime::now_utc().sub(nbf_sub);
    params.not_after = OffsetDateTime::now_utc().add(Duration::days(opt.valid_root as i64));
    params.serial_number = None;
    // params.serial_number = Some(1);
    params.subject_alt_names = vec![];
    // params.subject_alt_names = vec![SanType::Rfc822Name(opt.issuer.clone())];

    let mut sub = DistinguishedName::new();
    let cn = format!("{} Root", opt.common_name);
    sub.push(DnType::CommonName, cn);
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

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.extended_key_usages = vec![];

    let mut permitted_subtrees = vec![];
    for dns in &opt.name_constraint_dns {
        permitted_subtrees.push(GeneralSubtree::DnsName(dns.clone()));
    }
    for subnet in &opt.name_constraint_ip {
        match CidrSubnet::from_str(subnet) {
            Ok(s) => permitted_subtrees.push(GeneralSubtree::IpAddress(s)),
            Err(_) => {
                panic!("Cannot parse {} to a CidrSubnet", subnet);
            }
        }
    }
    if !permitted_subtrees.is_empty() {
        let nc = NameConstraints {
            permitted_subtrees,
            excluded_subtrees: vec![],
        };
        params.name_constraints = Some(nc);
    }

    params.custom_extensions = vec![];
    params.use_authority_key_identifier_extension = true;
    params.key_identifier_method = KeyIdMethod::Sha256;

    let cert = Certificate::from_params(params)?;
    let pem_serialized = cert.serialize_pem_with_signer(&cert)?;
    let pem = ::pem::parse(&pem_serialized).unwrap();
    let der_serialized = pem.contents();
    let fingerprint_full = fingerprint(der_serialized);

    fs::write(
        format!("{}/root.fingerprint", out_dir_root),
        fingerprint_full,
    )
    .await?;
    fs::write(
        format!("{}/root.cert.pem", out_dir_root),
        pem_serialized.clone(),
    )
    .await?;
    fs::write(format!("{}/root.cert.der", out_dir_root), der_serialized).await?;

    // encrypt the key before saving it
    let private_pem = cert.serialize_private_key_pem();
    let private_pem_enc = encrypt(private_pem.as_bytes(), &secret).unwrap();
    let private_pem_enc_path = format!("{}/root.key.pem", out_dir_root);
    fs::write(&private_pem_enc_path, &private_pem_enc).await?;

    let private_der = cert.serialize_private_key_der();
    let private_der_enc = encrypt(private_der.as_slice(), &secret).unwrap();
    let private_der_enc_path = format!("{}/root.key.der", out_dir_root);
    fs::write(&private_der_enc_path, &private_der_enc).await?;

    // save it as hex for convenience
    let private_pem_enc_hex = hex::encode(private_pem_enc);
    let private_pem_enc_hex_path = format!("{}/root.key.pem.hex", out_dir_root);
    fs::write(&private_pem_enc_hex_path, private_pem_enc_hex).await?;

    let private_der_enc_hex = hex::encode(private_der_enc);
    let private_der_enc_hex_path = format!("{}/root.key.der.hex", out_dir_root);
    fs::write(&private_der_enc_hex_path, private_der_enc_hex).await?;

    println!("Building root certificate successful\n");

    Ok(())
}

pub async fn root_ca_from_folder(opt: &X509CliOptions) -> Result<Certificate, anyhow::Error> {
    println!("Reading encrypted root certificate from filesystem");

    let pwd = prompt_password("Root CA password: ")?;

    // let digest = digest::digest(&digest::SHA256, pwd.as_bytes());
    // let secret = digest.as_ref();
    let secret = kdf_danger_static(pwd.as_bytes()).await?;

    let out_dir_root = format!("{}{}", opt.out_dir, OUT_DIR_ROOT);
    let path_key = format!("{}/root.key.der", out_dir_root);
    let ca_key_enc = match fs::read(&path_key).await {
        Ok(file) => file,
        Err(_) => {
            return Err(anyhow::Error::msg(format!(
                "Could not read CA Key file from path '{}'\nBuild the Root CA first!",
                path_key
            )));
        }
    };
    let ca_key_der = match decrypt(&ca_key_enc, &secret) {
        Ok(der) => der,
        // if we get an error here, the file is either corrupt or not encrypted at all
        Err(_) => ca_key_enc,
    };

    let path_cert = format!("{}/root.cert.der", out_dir_root);
    let ca_cert_der = match fs::read(&path_cert).await {
        Ok(file) => file,
        Err(_) => {
            return Err(anyhow::Error::msg(format!(
                "Could not read CA cert file from path '{}'",
                path_cert
            )));
        }
    };

    let signing_cert = cert_from_key_der(&ca_key_der, ca_cert_der.as_slice()).await?;

    println!("Reading encrypted root certificate from filesystem successful\n");
    Ok(signing_cert)
}

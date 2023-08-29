use crate::certificates::set_file_ro;
use crate::certificates::ssh::bootstrap::{get_serial, OUT_DIR_USER};
use crate::cli::SshOptions;
use anyhow::Error;
use der::pem::LineEnding;
use rand_core::OsRng;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::PrivateKey;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;

pub async fn build_user(opt: &SshOptions, ca_key: &PrivateKey) -> Result<(), Error> {
    println!("Building ssh user certificate");

    let key = PrivateKey::random(&mut OsRng, opt.get_alg())?;
    let key_openssh = key.to_openssh(LineEnding::LF).unwrap();

    // build the certificate
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let valid_after = now - 120;
    let valid_before = now + (60 * opt.valid);

    let mut cert_builder =
        Builder::new_with_random_nonce(&mut OsRng, key.public_key(), valid_after, valid_before)?;

    let next_serial = get_serial(opt, OUT_DIR_USER).await?;
    cert_builder.serial(next_serial)?;
    cert_builder.key_id("nioca-root")?;
    cert_builder.cert_type(CertType::User)?;

    opt.principal.iter().for_each(|p| {
        cert_builder.valid_principal(p).unwrap();
    });

    if let Some(cmd) = &opt.force_command {
        cert_builder
            .critical_option("force-command", cmd.clone())
            .unwrap();
    }

    if let Some(sources) = &opt.source_address {
        let ips = sources.join(",");
        cert_builder.critical_option("source-address", ips).unwrap();
    }

    if !opt.disable_x11_forwarding {
        cert_builder.extension("permit-X11-forwarding", "").unwrap();
    }
    if !opt.disable_agent_forwarding {
        cert_builder
            .extension("permit-agent-forwarding", "")
            .unwrap();
    }
    if !opt.disable_port_forwarding {
        cert_builder
            .extension("permit-port-forwarding", "")
            .unwrap();
    }
    if !opt.disable_pty {
        cert_builder.extension("permit-pty", "").unwrap();
    }
    if !opt.disable_user_rc {
        cert_builder.extension("permit-user-rc", "").unwrap();
    }

    cert_builder.comment("nioca-ca")?;

    let cert = cert_builder.sign(ca_key)?;

    let cert_openssh = cert.to_openssh().unwrap();
    println!("Host Certificate:\n{}", cert_openssh);

    // file paths
    let path_key = format!("{}{}/nioca_user_key", opt.out_dir, OUT_DIR_USER);
    let path_cert = format!("{}{}/nioca_user_key.pub", opt.out_dir, OUT_DIR_USER);

    // save to disk
    fs::write(&path_key, &key_openssh).await?;
    set_file_ro(&path_key).await?;
    fs::write(&path_cert, &cert_openssh).await?;

    println!("Building ssh user certificate successful\n");
    println!(
        "You can check the contents of the certificate with 'ssh-keygen -L -f {}'",
        path_cert
    );

    Ok(())
}

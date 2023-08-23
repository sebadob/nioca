use crate::certificates::x509::end_entity::end_entity_cert_cli;
use crate::certificates::x509::intermediate::{build_intermediate_ca, intermediate_ca_from_folder};
use crate::certificates::x509::root::{build_root_ca, root_ca_from_folder};
use crate::cli::{X509CliOptions, X509Stage};
use tokio::fs;

pub const OUT_DIR_BASE: &str = "ca/x509";
pub const OUT_DIR_ROOT: &str = "ca/x509/root";
pub const OUT_DIR_INTERMEDIATE: &str = "ca/x509/intermediate";
pub const OUT_DIR_END_ENTITY: &str = "ca/x509/end_entity";
pub const SERIAL_PATH: &str = "ca/x509/end_entity/serial";

pub async fn bootstrap_x509(mut opt: X509CliOptions) -> Result<(), anyhow::Error> {
    if !opt.out_dir.ends_with('/') {
        opt.out_dir = format!("{}/", opt.out_dir);
    }

    if opt.stage == X509Stage::Root || opt.stage == X509Stage::Full {
        if opt.clean {
            // removing a non-existing dir anyway will fail -> ignore it
            let path = format!("{}{}", opt.out_dir, OUT_DIR_BASE);
            let _ = fs::remove_dir_all(&path).await;
            fs::create_dir_all(&path).await?;
        }

        build_root_ca(&opt).await?;
    }

    if opt.stage == X509Stage::Intermediate || opt.stage == X509Stage::Full {
        // do read the ca private in from file again to make sure everything works out fine
        let signing_cert = root_ca_from_folder(&opt).await?;

        // build intermediate
        build_intermediate_ca(&opt, &signing_cert).await?;
    }

    // This should only be needed for the very first bootstrap or disaster recovery
    if opt.stage == X509Stage::EndEntity || opt.stage == X509Stage::Full {
        // do read the ca private in from file again to make sure everything works out fine
        let intermediate_cert = intermediate_ca_from_folder(&opt).await?;

        // build intermediate
        end_entity_cert_cli(&opt, &intermediate_cert).await?;
    }

    Ok(())
}

pub async fn check_out_dir(
    path: &str,
    opt: &X509CliOptions,
    overwrite: bool,
) -> Result<(), anyhow::Error> {
    let p = format!("{}{}", opt.out_dir, OUT_DIR_BASE);
    if fs::read_dir(&p).await.is_err() {
        fs::create_dir_all(&p).await?;
    }

    match fs::read_dir(path).await {
        Ok(_) => {
            if overwrite {
                Ok(())
            } else if opt.clean {
                let _ = fs::remove_dir_all(path).await;
                fs::create_dir_all(path).await?;
                Ok(())
            } else {
                let msg = format!(
                    "Output dir '{}' already exists - exiting to not override existing data",
                    path
                );
                Err(anyhow::Error::msg(msg))
            }
        }
        Err(_) => {
            // if the directory does not exist, create it and go on
            fs::create_dir_all(path).await?;
            Ok(())
        }
    }
}

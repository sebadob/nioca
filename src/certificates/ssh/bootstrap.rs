use crate::certificates::encryption::{decrypt, kdf_danger_static, prompt_password};
use crate::certificates::ssh::host::build_host;
use crate::certificates::ssh::root::build_root_ca;
use crate::certificates::ssh::user::build_user;
use crate::cli::{SshOptions, SshStage};
use ssh_key::PrivateKey;
use tokio::fs;

pub const OUT_DIR_BASE: &str = "ca/ssh";
pub const OUT_DIR_ROOT: &str = "ca/ssh/root";
pub const OUT_DIR_HOST: &str = "ca/ssh/hosts";
pub const OUT_DIR_USER: &str = "ca/ssh/users";

pub async fn bootstrap_ssh(mut opt: SshOptions) -> Result<(), anyhow::Error> {
    if !opt.out_dir.ends_with('/') {
        opt.out_dir = format!("{}/", opt.out_dir);
    }

    if opt.stage == SshStage::Root {
        if opt.clean {
            // removing a non-existing dir anyway will fail -> ignore it
            let path = format!("{}{}", opt.out_dir, OUT_DIR_BASE);
            let _ = fs::remove_dir_all(&path).await;
            fs::create_dir_all(&path).await?;
        }

        build_root_ca(&opt).await?;
    }

    if opt.stage == SshStage::Host {
        let signing_cert = ca_key_from_folder(&opt).await?;
        build_host(&opt, &signing_cert).await?;
    }

    if opt.stage == SshStage::User {
        let signing_cert = ca_key_from_folder(&opt).await?;
        build_user(&opt, &signing_cert).await?;
    }

    Ok(())
}

pub async fn ca_key_from_folder(opt: &SshOptions) -> Result<PrivateKey, anyhow::Error> {
    println!("Reading encrypted root ssh private key from filesystem");

    let pwd = prompt_password("Root CA password: ")?;

    // let digest = digest::digest(&digest::SHA256, pwd.as_bytes());
    // let secret = digest.as_ref();
    let secret = kdf_danger_static(pwd.as_bytes()).await?;

    // let out_dir_root = format!("{}{}", opt.out_dir, OUT_DIR_ROOT);
    let path_key = format!("{}{}/key.enc", opt.out_dir, OUT_DIR_ROOT);
    // let path_key = format!("{}/root.key.der", out_dir_root);
    let ca_key_enc = match fs::read(&path_key).await {
        Ok(file) => file,
        Err(_) => {
            return Err(anyhow::Error::msg(format!(
                "Could not read SSH Key file from path '{}'\nBuild the SSH Root CA first!",
                path_key
            )));
        }
    };
    let ca_key_bytes = match decrypt(&ca_key_enc, &secret) {
        Ok(der) => der,
        // if we get an error here, the file is either corrupt or not encrypted at all
        Err(_) => ca_key_enc,
    };

    let key = match PrivateKey::from_openssh(ca_key_bytes) {
        Ok(k) => k,
        Err(_) => {
            return Err(anyhow::Error::msg(
                "Bad private SSH key format or wrong password",
            ));
        }
    };

    println!("Reading encrypted root ssh private key from filesystem successful\n");
    Ok(key)
}

pub async fn check_out_dir(
    path: &str,
    opt: &SshOptions,
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

pub(crate) async fn get_serial(opt: &SshOptions, sub_path: &str) -> Result<u64, anyhow::Error> {
    let serial_path = format!("{}{}/serial", opt.out_dir, sub_path);
    let serial = match fs::read_to_string(&serial_path).await {
        Ok(s) => s.parse::<u64>().unwrap_or(0) + 1,
        Err(_) => 1u64,
    };
    println!("New certificate serial: {}", serial);

    fs::create_dir_all(format!("{}{}/{}", opt.out_dir, sub_path, serial)).await?;
    fs::write(&serial_path, serial.to_string()).await?;
    Ok(serial)
}

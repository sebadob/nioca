use crate::certificates::encryption::{encrypt, kdf_danger_static, EncAlg};
use crate::config::{ConfigSealed, Db, EncKeys};
use crate::constants::{DEV_MODE, INSTANCE_UUID, UNSEAL_RATE_LIMIT};
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::api::request::{AddMasterShardRequest, InitRequest, UnsealRequest};
use crate::models::api::response::{CertificateInitInspectResponse, InitResponse, SealedStatus};
use crate::models::db::ca_cert_x509::{CaCertX509Nioca, CaCertX509Root, CaCertX509Type};
use crate::models::db::enc_key::EncKeyEntity;
use crate::models::db::master_key::MasterKeyEntity;
use crate::models::db::sealed::SealedEntity;
use crate::routes::AppStateSealedExtract;
use crate::service;
use crate::service::password_hasher::HashPassword;
use crate::service::x509::CheckedCerts;
use crate::util::secure_random;
use ring::digest;
use sqlx::query;
use std::env;
use std::ops::Add;
use std::str::FromStr;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{debug, error, info};
use uuid::Uuid;
use x509_parser::nom::AsBytes;

/// Initialized the database with the given init values.
pub async fn init(
    state: AppStateSealedExtract,
    req: InitRequest,
) -> Result<InitResponse, ErrorResponse> {
    // block the config for the whole operation
    let config = state.write().await.clone();

    // check validity of the input data
    let (checked_certs, _) = init_values_check(&config, &req).await?;

    // create keys and secrets
    let master_shard_1 = secure_random(48);
    let master_shard_1_check = kdf_danger_static(master_shard_1.as_bytes()).await?;

    let master_shard_2 = secure_random(48);
    let master_shard_2_check = kdf_danger_static(master_shard_2.as_bytes()).await?;

    let master_full = format!("{}{}", master_shard_1, master_shard_2);
    let master_key_hash = kdf_danger_static(master_full.as_bytes()).await?;
    let master_key_check = kdf_danger_static(master_key_hash.as_bytes()).await?;

    let enc_key_str = secure_random(128);
    let enc_key_hash = digest::digest(&digest::SHA256, enc_key_str.as_bytes());
    let enc_key_bytes = enc_key_hash.as_ref();
    let enc_key_encrypted = encrypt(enc_key_bytes, &master_key_hash).unwrap();
    let enc_key_id = Uuid::new_v4();
    let enc_key_alg = EncAlg::ChaCha20Poly1305;

    let nioca_key_enc = encrypt(checked_certs.nioca_key_plain.as_bytes(), enc_key_bytes)?;
    let nioca_key_enc_hex = hex::encode(nioca_key_enc);

    // encrypt PEM fingerprints
    let root_fingerprint = encrypt(checked_certs.root_fingerprint.as_bytes(), enc_key_bytes)?;
    let nioca_fingerprint = encrypt(checked_certs.nioca_fingerprint.as_bytes(), enc_key_bytes)?;

    let now_ts = OffsetDateTime::now_utc().unix_timestamp().to_string();

    // create a password hash
    let local_password_hash =
        HashPassword::hash_password(&req.local_password, &master_full).await?;

    // generate a UUID for the new default certificate
    let uuid = Uuid::new_v4();

    // The whole initialization should be a big single transaction
    let mut txn = Db::txn().await?;

    query!(
        "INSERT INTO master_key (id, value) VALUES ('check_shard_1', $1)",
        hex::encode(&master_shard_1_check)
    )
    .execute(&mut *txn)
    .await?;

    query!(
        "INSERT INTO master_key (id, value) VALUES ('check_shard_2', $1)",
        hex::encode(&master_shard_2_check)
    )
    .execute(&mut *txn)
    .await?;

    query!(
        "INSERT INTO master_key (id, value) VALUES ('check_master', $1)",
        hex::encode(&master_key_check)
    )
    .execute(&mut *txn)
    .await?;

    query!(
        "INSERT INTO master_key (id, value) VALUES ('enc_key_active', $1)",
        enc_key_id.to_string()
    )
    .execute(&mut *txn)
    .await?;

    query!(
        "INSERT INTO master_key (id, value) VALUES ('initialized', $1)",
        now_ts
    )
    .execute(&mut *txn)
    .await?;

    query!(
        "INSERT INTO master_key (id, value) VALUES ('local_password', $1)",
        local_password_hash
    )
    .execute(&mut *txn)
    .await?;

    query!(
        "INSERT INTO master_key (id, value) VALUES ('default_x509', $1)",
        uuid.to_string(),
    )
    .execute(&mut *txn)
    .await?;

    query!(
        "INSERT INTO enc_keys (id, alg, value) VALUES ($1, $2, $3)",
        enc_key_id,
        enc_key_alg.to_string(),
        enc_key_encrypted,
    )
    .execute(&mut *txn)
    .await?;

    query!(
        "INSERT INTO ca_certs_x509 (id, typ, name, expires, data, fingerprint, enc_key_id) VALUES ($1, $2, 'default', $3, $4, $5, $6)",
        &uuid,
        CaCertX509Type::Root.as_str(),
        checked_certs.root_exp,
        checked_certs.root_cert_pem,
        root_fingerprint,
        enc_key_id,
    )
        .execute(&mut *txn)
    .await?;

    query!(
        "INSERT INTO ca_certs_x509 (id, typ, name, expires, data, fingerprint, enc_key_id) VALUES ($1, $2, 'default', $3, $4, $5, $6)",
        &uuid,
        CaCertX509Type::Certificate.as_str(),
        checked_certs.nioca_exp,
        checked_certs.nioca_cert_pem,
        nioca_fingerprint,
        enc_key_id,
    )
        .execute(&mut *txn)
    .await?;

    query!(
        "INSERT INTO ca_certs_x509 (id, typ, name, data, enc_key_id) VALUES ($1, $2, 'default', $3, $4)",
        &uuid,
        CaCertX509Type::Key.as_str(),
        nioca_key_enc_hex,
        enc_key_id
    )
    .execute(&mut *txn)
    .await?;

    query!(
        "UPDATE groups SET ca_x509 = $1 WHERE name = 'default'",
        &uuid,
    )
    .execute(&mut *txn)
    .await?;

    // commit
    txn.commit().await?;

    // set the state to initialized
    state.write().await.init_key = None;

    // create a new xsrf token
    state.write().await.xsrf_key = secure_random(48);

    Ok(InitResponse {
        master_shard_1,
        master_shard_2,
    })
}

/// Checks the given Nioca init values for correctness, validity and consistency.
pub async fn init_values_check(
    state: &ConfigSealed,
    req: &InitRequest,
) -> Result<(CheckedCerts, CertificateInitInspectResponse), ErrorResponse> {
    // check init key
    if state.init_key.as_ref().unwrap() != &req.init_key {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Bad Init Key".to_string(),
        ));
    }

    // check xsrf key
    if state.xsrf_key != req.xsrf_key {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Bad XSRF Key".to_string(),
        ));
    }

    // make sure the password is not too short
    let pwd_len = req.local_password.len();
    if !(16..=128).contains(&pwd_len) {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "The local password should be between 16 and 128 characters long".to_string(),
        ));
    }

    service::x509::x509_ca_validate(&req.root_pem, &req.it_pem, &req.it_key, &req.it_pem).await
}

/// Checks a given master shard key against the check hashes from the database and saves the shard
/// upon success.
pub async fn add_unseal_shard(
    state: AppStateSealedExtract,
    req: AddMasterShardRequest,
) -> Result<SealedStatus, ErrorResponse> {
    // lock the config for the whole checking process
    let mut config = state.write().await;

    // very hard rate limiting for the unsealing operation
    let now = OffsetDateTime::now_utc();
    if config.next_unseal_nbf > now {
        return Err(ErrorResponse::new(
            ErrorResponseType::TooManyRequests,
            format!("Next key add request not before: {}", now.unix_timestamp()),
        ));
    }

    // check xsrf key
    if config.xsrf_key != req.xsrf {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Bad XSRF Key".to_string(),
        ));
    }

    let hash = kdf_danger_static(req.key.as_bytes()).await?;

    let master_key = MasterKeyEntity::build().await?;

    let mut is_match = false;
    if config.enc_keys.master_shard_1.is_none() && master_key.check_shard_1.as_bytes() == hash {
        config.enc_keys.master_shard_1 = Some(req.key.clone());
        is_match = true;
    } else if config.enc_keys.master_shard_2.is_none()
        && master_key.check_shard_2.as_bytes() == hash
    {
        config.enc_keys.master_shard_2 = Some(req.key.clone());
        is_match = true;
    }

    // set new rate limit timeout
    config.next_unseal_nbf =
        OffsetDateTime::now_utc().add(time::Duration::seconds(*UNSEAL_RATE_LIMIT as i64));

    // create new xsrf key
    config.xsrf_key = secure_random(48);

    if is_match {
        // if we found a key, lookup the database if other instances need unsealing
        let root_cert = CaCertX509Root::find_default(&config.enc_keys, true).await?;
        push_shard_to_remotes(req.key, root_cert.cert_pem.as_bytes()).await?;

        let status = SealedStatus {
            is_initialized: true,
            is_sealed: true,
            master_shard_1: config.enc_keys.master_shard_1.is_some(),
            master_shard_2: config.enc_keys.master_shard_2.is_some(),
            is_ready: config.enc_keys.master_shard_1.is_some()
                && config.enc_keys.master_shard_2.is_some(),
            key_add_rate_limit: *UNSEAL_RATE_LIMIT,
        };

        Ok(status)
    } else {
        Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Incorrect Key Shard".to_string(),
        ))
    }
}

/// Unseals Nioca
pub async fn unseal(state: AppStateSealedExtract, req: UnsealRequest) -> Result<(), ErrorResponse> {
    // lock the config for the whole checking process
    let config = state.write().await;

    // check xsrf key
    if config.xsrf_key != req.xsrf {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Bad XSRF Key".to_string(),
        ));
    }

    // check if shards keys are present
    if config.enc_keys.master_shard_1.is_none() || config.enc_keys.master_shard_2.is_none() {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Nioca is not ready to be unsealed. Master Keys are missing".to_string(),
        ));
    }

    // build the master key
    let master_shard_1 = config.enc_keys.master_shard_1.as_ref().unwrap();
    let master_shard_2 = config.enc_keys.master_shard_2.as_ref().unwrap();
    let master_full = format!("{}{}", master_shard_1, master_shard_2);
    let master_key_hash = kdf_danger_static(master_full.as_bytes()).await?;
    // this is our master key for decryption end enc keys
    let master_key_bytes = master_key_hash.as_ref();
    assert_eq!(master_key_hash.len(), 32);

    // check for correctness against the hash from the db
    let mk_entity = MasterKeyEntity::build().await?;
    let master_key_hash_hash = kdf_danger_static(master_key_bytes).await?;
    if mk_entity.check_master != master_key_hash_hash {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "Master Key Checksum failed".to_string(),
        ));
    }

    // the reconstructed master key is correct -> ready to unseal

    // get encryption key and decrypt with master
    let enc_key_id = mk_entity
        .enc_key_active
        .expect("enc_key_active is non when it should never be");
    let enc_uuid = Uuid::from_str(&enc_key_id).expect("Rebuilding UUID for enc kid");
    let enc_key = EncKeyEntity::find(&enc_uuid, master_key_bytes).await?;

    let enc_keys = EncKeys {
        master_shard_1: None,
        master_shard_2: None,
        master_key: master_key_hash,
        pepper: master_full,
        enc_key: enc_key.clone(),
    };

    // find the certificates and decrypt the private key, just to make sure that everything is fine
    let _root_cert = CaCertX509Root::find_default(&enc_keys, false).await?;
    let _nioca_cert = CaCertX509Nioca::find_default(&enc_keys).await?;

    // if we got until here successfully, everything is ready
    // Send the enc keys over the channel for the new server process
    config
        .tx_enc_keys
        .send_async(enc_keys)
        .await
        .expect("Send EncKeys from sealed server");

    // When running in DEV_MODE, log these values into the console to have them for the .env file with
    // auto unsealing
    if *DEV_MODE {
        info!("######################################################");
        info!(">>> master_shard_1: {}", master_shard_1);
        info!(">>> master_shard_2: {}", master_shard_2);
        info!(">>> enc_key_uuid: {}", enc_uuid);
        info!(">>> enc_key_value: {}", hex::encode(enc_key.value));
        info!("######################################################");
    }

    // start the exit handler with a short timeout, so we can actually send out the answer
    let tx_exit = config.tx_exit.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        tx_exit
            .send_async(())
            .await
            .expect("Sending exit signal for sealed server");
    });

    Ok(())
}

/// Does a lookup to the database to find existing remote instances waiting for an unseal and pushes
/// the master shard keys to them from an alread unsealed instance.
pub async fn push_shard_to_remotes(key: String, root_pem: &[u8]) -> Result<(), ErrorResponse> {
    debug!("Running push_shard_to_remotes");

    // if auto unsealing is not configured, just skip this step
    if env::var("INTERVAL_AUTO_UNSEAL").is_err() {
        return Ok(());
    }

    let sealed = SealedEntity::find_all().await?;

    for s in sealed {
        if s.id == *INSTANCE_UUID {
            continue;
        }

        if !s.direct_access {
            info!(
                "Skipping auto-unseal of instance {} - no direct access configured",
                s.id
            );
            continue;
        }

        let cert = reqwest::Certificate::from_pem(root_pem)
            .expect("Building root certificate for remote auto-unseal");
        let client = reqwest::ClientBuilder::new()
            .add_root_certificate(cert)
            .connect_timeout(Duration::from_secs(10))
            .https_only(true)
            .user_agent(format!("Nioca Auto-Unseal {}", *INSTANCE_UUID))
            .build()
            .expect("Building reqwest client for auto-unsealing");

        // get the instances xsrf token
        let xsrf = match client
            .get(format!("{}/unseal/xsrf", s.url))
            .header("accept", "application/json")
            .send()
            .await
        {
            Ok(res) => match res.text().await {
                Ok(xsrf) => xsrf,
                Err(err) => {
                    error!("Auto-Unseal GET xsrf body -> text: {}", err);
                    continue;
                }
            },
            Err(err) => {
                error!("Auto-Unseal GET xsrf error: {}", err);
                continue;
            }
        };

        // send the key shard
        let req = AddMasterShardRequest {
            key: key.clone(),
            xsrf,
        };
        match client
            .post(format!("{}/unseal/xsrf", s.url))
            .json(&req)
            .send()
            .await
        {
            Ok(_) => {
                info!(
                    "Sent Master Shard key for Auto-Unseal to instance {} successfully",
                    s.id
                );
            }
            Err(err) => {
                error!("Auto-Unseal GET xsrf error: {}", err);
                continue;
            }
        };
    }

    Ok(())
}

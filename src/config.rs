use crate::certificates::x509::cert_from_key_pem;
use crate::constants::{PUB_URL_FULL, TOKEN_CACHE_LIFESPAN};
use crate::models::api::error_response::ErrorResponse;
use crate::models::db::ca_cert_x509::{CaCertX509Nioca, CaCertX509Root};
use crate::models::db::config_oidc::ConfigOidcEntity;
use crate::models::db::enc_key::EncKeyEntity;
use crate::models::db::master_key::MasterKeyEntity;
use crate::models::db::sealed::SealedEntity;
use crate::oidc::validation;
use crate::oidc::validation::{OidcConfig, TokenCacheReq};
use crate::util::secure_random;
use anyhow::Context;
use rcgen::Certificate;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Postgres, Transaction};
use std::env;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

pub type AppState = Arc<RwLock<Config>>;
pub type AppStateSealed = Arc<RwLock<ConfigSealed>>;
pub type DbPool = sqlx::Pool<Postgres>;

pub static DB: OnceLock<DbPool> = OnceLock::new();

pub struct Db();

impl Db {
    pub async fn init() -> anyhow::Result<()> {
        let db_host = env::var("DB_HOST").expect("DB_HOST is not set");
        let db_port = env::var("DB_PORT")
            .unwrap_or_else(|_| "5432".to_string())
            .parse::<u16>()
            .expect("Cannot parse DB_PORT to u16");
        let db_user = env::var("DB_USER").expect("DB_USER is not set");
        let db_password = env::var("DB_PASSWORD").expect("DB_PASSWORD is not set");

        let db_timeout = Duration::from_secs(30);
        let db_max_conn = env::var("DATABASE_MAX_CONN")
            .unwrap_or_else(|_| String::from("2"))
            .parse::<u32>()
            .expect("Error parsing DATABASE_MAX_CONN to u32");

        let connection_options = PgConnectOptions::new()
            .host(&db_host)
            .port(db_port)
            .username(&db_user)
            .password(&db_password)
            .database("nioca");

        let db = PgPoolOptions::new()
            .max_connections(db_max_conn)
            .acquire_timeout(db_timeout)
            .connect_with(connection_options)
            .await
            .context("failed to connect to DATABASE_URL")?;

        info!("Database Connection Pool created successfully");

        // Postgres 15 denies to create anything in the public schema for any user but postgres.
        // However, the _sqlx_migrations will be saved on public and if did not find a way around it
        // at this time. To grant access to public again for our nioca user:
        // GRANT CREATE ON SCHEMA public TO nioca;
        sqlx::migrate!().run(&db).await?;

        DB.set(db).unwrap();

        Ok(())
    }

    pub fn conn<'a>() -> &'a DbPool {
        DB.get().unwrap()
    }

    pub async fn txn<'a>() -> Result<Transaction<'a, Postgres>, ErrorResponse> {
        let txn = DB.get().unwrap().begin().await?;
        Ok(txn)
    }
}

/// Application config
pub struct Config {
    pub enc_keys: EncKeys,
    pub root_cert: CaCertX509Root,
    pub nioca_cert: CaCertX509Nioca,
    pub ca_chain_pem: String,
    pub nioca_signing_cert: Certificate,
    pub tx_token_cache: Option<flume::Sender<TokenCacheReq>>,
}

impl Config {
    pub async fn new(enc_keys: EncKeys) -> Result<AppState, ErrorResponse> {
        // when we get here, Nioca is unsealed -> unregister the await
        if let Err(err) = SealedEntity::delete().await {
            error!(
                "Error deleting this instance from unseal await: {}",
                err.message
            );
        }

        let root_cert = CaCertX509Root::find_default(&enc_keys, false).await?;
        let nioca_cert = CaCertX509Nioca::find_default(&enc_keys).await?;
        let nioca_signing_cert = cert_from_key_pem(&nioca_cert.key, &nioca_cert.cert_pem).await?;
        let ca_chain_pem = format!("{}\n{}", nioca_cert.cert_pem, root_cert.cert_pem);

        let tx_token_cache = match ConfigOidcEntity::find(&enc_keys).await {
            Ok(c) => {
                debug!("Found ConfigOidcEntity - spawning Token Cache");
                let config = OidcConfig::from_db_entity(c).await?;
                let tx = validation::init(config, TOKEN_CACHE_LIFESPAN).await?;
                Some(tx)
            }
            Err(_) => None,
        };

        let config = Self {
            enc_keys,
            root_cert,
            nioca_cert,
            ca_chain_pem,
            nioca_signing_cert,
            tx_token_cache,
        };

        Ok(AppState::new(RwLock::new(config)))
    }
}

/// Application config for the sealed state
#[derive(Debug, Clone)]
pub struct ConfigSealed {
    pub tx_enc_keys: flume::Sender<EncKeys>,
    pub tx_exit: flume::Sender<()>,
    pub enc_keys: EncKeys,
    pub master_key_entity: MasterKeyEntity,
    pub next_unseal_nbf: OffsetDateTime,
    pub init_key: Option<String>,
    pub xsrf_key: String,
}

impl ConfigSealed {
    pub async fn new(
        tx_enc_keys: flume::Sender<EncKeys>,
        tx_exit: flume::Sender<()>,
    ) -> Result<AppStateSealed, anyhow::Error> {
        // register this instance in the DB -> awaiting unsealing
        if let Err(err) = SealedEntity::add().await {
            error!(
                "Error registering this instance for unseal await: {}",
                err.message
            );
        }

        let enc_keys = EncKeys::default();
        let master_key = MasterKeyEntity::build().await.expect("Building MasterKey");
        let init_key = if master_key.initialized.is_none() {
            let key = env::var("INIT_KEY")
                .expect("INIT_KEY must be given for a non-initialized instance");
            info!(
                "Visit the UI {}/unseal.html and enter the Nioca init key for the first time setup: {}",
                *PUB_URL_FULL, key
            );
            Some(key)
        } else {
            None
        };
        let xsrf_key = secure_random(48);

        let config = Self {
            tx_enc_keys,
            tx_exit,
            enc_keys,
            master_key_entity: master_key,
            next_unseal_nbf: OffsetDateTime::now_utc(),
            init_key,
            xsrf_key,
        };
        let app_state_sealed = Arc::new(RwLock::new(config));

        Ok(app_state_sealed)
    }
}

#[derive(Debug, Clone, Default)]
pub struct EncKeys {
    pub master_shard_1: Option<String>,
    pub master_shard_2: Option<String>,
    pub master_key: Vec<u8>,
    pub pepper: String,
    pub enc_key: EncKeyEntity,
}

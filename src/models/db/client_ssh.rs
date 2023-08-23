use crate::certificates::encryption::{decrypt, encrypt};
use crate::certificates::SshKeyAlg;
use crate::config::{Db, EncKeys};
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::api::request::ClientSshRequest;
use crate::models::api::response::SshCertificateResponse;
use crate::models::db::ca_cert_ssh::{CaCertSshEntity, SshKeyPairOpenssh};
use crate::models::db::cert_ssh::CertSshEntity;
use crate::models::db::enc_key::EncKeyEntity;
use crate::models::db::groups::GroupEntity;
use crate::routes::AppStateExtract;
use crate::util::secure_random;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{query, query_as};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::{LineEnding, PrivateKey};
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use tracing::{debug, info};
use utoipa::ToSchema;
use uuid::Uuid;
use x509_parser::nom::AsBytes;

#[derive(Debug, Clone)]
pub struct ClientSshEntity {
    pub id: Uuid,
    pub name: String,
    pub expires: Option<OffsetDateTime>,
    pub enabled: bool,
    pub api_key: Vec<u8>,
    pub enc_key_id: Uuid,
    pub key_alg: String,
    pub group_id: Uuid,
    pub typ: String,
    pub principals: String,
    pub force_command: Option<String>,
    pub source_addresses: Option<String>,
    pub permit_x11_forwarding: Option<bool>,
    pub permit_agent_forwarding: Option<bool>,
    pub permit_port_forwarding: Option<bool>,
    pub permit_pty: Option<bool>,
    pub permit_user_rc: Option<bool>,
    pub valid_secs: i32,
    pub latest_cert: Option<i32>,
}

// CRUD
impl ClientSshEntity {
    pub async fn create(
        client: ClientSshRequest,
        enc_key: &EncKeyEntity,
    ) -> Result<Self, ErrorResponse> {
        let uuid = Uuid::new_v4();
        let expires = Self::expires_from_req(client.expires)?;
        let principals = client.principals.join(",");
        let source_addresses = client.source_addresses.map(|a| a.join(","));
        let api_key_enc = encrypt(secure_random(48).as_bytes(), enc_key.value.as_bytes())?;
        let enc_key_id = enc_key.id;

        let db = Db::conn();

        query!(
            r#"
            INSERT INTO clients_ssh (id, name, expires, enabled, api_key, enc_key_id, key_alg,
            group_id, typ, principals, force_command, source_addresses, permit_x11_forwarding,
            permit_agent_forwarding, permit_port_forwarding, permit_pty, permit_user_rc, valid_secs)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
            "#,
            uuid,
            client.name,
            expires,
            client.enabled,
            api_key_enc,
            enc_key_id,
            client.key_alg.as_str(),
            client.group_id,
            client.typ.as_str(),
            principals,
            client.force_command,
            source_addresses,
            client.permit_x11_forwarding,
            client.permit_agent_forwarding,
            client.permit_port_forwarding,
            client.permit_pty,
            client.permit_user_rc,
            client.valid_secs,
        )
        .execute(db)
        .await?;

        // a second query instead of insert return to be able to switch to sqlite easily too
        let res = query_as!(Self, "SELECT * FROM clients_ssh WHERE id = $1", uuid)
            .fetch_one(db)
            .await?;

        Ok(res)
    }

    pub async fn delete(uuid: &Uuid) -> Result<(), ErrorResponse> {
        // Delete the client itself
        query!("DELETE FROM clients_ssh WHERE id = $1", uuid)
            .execute(Db::conn())
            .await?;

        Ok(())
    }

    pub async fn update(uuid: &Uuid, client: ClientSshRequest) -> Result<Self, ErrorResponse> {
        let expires = ClientSshEntity::expires_from_req(client.expires)?;
        let principals = client.principals.join(",");
        let source_addresses = client.source_addresses.map(|a| a.join(","));

        let db = Db::conn();

        query!(
            r#"
            UPDATE clients_ssh
            SET name = $1, expires = $2, enabled = $3, key_alg = $4, group_id = $5, typ = $6, principals = $7,
            force_command = $8, source_addresses = $9, permit_x11_forwarding = $10, permit_agent_forwarding = $11,
            permit_port_forwarding = $12, permit_pty = $13, permit_user_rc = $14, valid_secs = $15
            WHERE id = $16
            "#,
            client.name,
            expires,
            client.enabled,
            client.key_alg.as_str(),
            client.group_id,
            client.typ.as_str(),
            principals,
            client.force_command,
            source_addresses,
            client.permit_x11_forwarding,
            client.permit_agent_forwarding,
            client.permit_port_forwarding,
            client.permit_pty,
            client.permit_user_rc,
            client.valid_secs,
            uuid,
        )
            .execute(db)
            .await?;

        // a second query instead of insert return to be able to switch to sqlite easily too
        let res = query_as!(Self, "SELECT * FROM clients_ssh WHERE id = $1", uuid)
            .fetch_one(db)
            .await?;

        Ok(res)
    }

    pub async fn find(uuid: &Uuid) -> Result<Self, ErrorResponse> {
        query_as!(Self, "SELECT * FROM clients_ssh WHERE id = $1", uuid)
            .fetch_one(Db::conn())
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn find_all() -> Result<Vec<Self>, ErrorResponse> {
        query_as!(Self, "SELECT * FROM clients_ssh")
            .fetch_all(Db::conn())
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn find_secret(uuid: &Uuid, enc_keys: &EncKeys) -> Result<String, ErrorResponse> {
        let slf = Self::find(uuid).await?;
        slf.decrypt_api_key(enc_keys).await
    }

    pub async fn decrypt_api_key(&self, enc_keys: &EncKeys) -> Result<String, ErrorResponse> {
        // If the enc_key is not the currently active one, fetch the old one and re-encrypt with the
        // active key
        let api_key_plain_bytes = if self.enc_key_id != enc_keys.enc_key.id {
            let enc_key = EncKeyEntity::find(&self.id, &enc_keys.master_key).await?;
            let api_key_bytes = decrypt(&self.api_key, &enc_key.value)?;

            // re-encrypt with the new key and save it
            let api_key_new = encrypt(&api_key_bytes, &enc_keys.enc_key.value)?;
            query!(
                "UPDATE clients_ssh SET api_key = $1, enc_key_id = $2 WHERE id = $3",
                api_key_new,
                enc_keys.enc_key.id,
                self.id
            )
            .execute(Db::conn())
            .await?;

            api_key_bytes
        } else {
            decrypt(&self.api_key, &enc_keys.enc_key.value)?
        };

        let api_key_plain = String::from_utf8(api_key_plain_bytes)?;
        Ok(api_key_plain)
    }

    pub async fn new_secret(uuid: &Uuid, enc_keys: &EncKeys) -> Result<String, ErrorResponse> {
        let secret = secure_random(48);
        let api_key_new = encrypt(secret.as_bytes(), &enc_keys.enc_key.value)?;
        query!(
            "UPDATE clients_ssh SET api_key = $1, enc_key_id = $2 WHERE id = $3",
            api_key_new,
            enc_keys.enc_key.id,
            uuid,
        )
        .execute(Db::conn())
        .await?;

        Ok(secret)
    }

    pub async fn set_last_cert(client: &Uuid, cert: i32) -> Result<(), ErrorResponse> {
        query!(
            "UPDATE clients_ssh SET latest_cert = $1 WHERE id = $2",
            cert,
            client,
        )
        .execute(Db::conn())
        .await?;

        Ok(())
    }
}

impl ClientSshEntity {
    /// Creates a new SSH certificate for this client and saves the information in the DB
    pub async fn build_cert(
        &self,
        state: &AppStateExtract,
        group: &GroupEntity,
    ) -> Result<SshCertificateResponse, ErrorResponse> {
        debug!("Building new SSH Certificate for client {}", self.id);

        let key_alg = SshKeyAlg::from_str(&self.key_alg);
        let key = PrivateKey::random(&mut OsRng, key_alg.as_alg())?;
        let key_openssh = key.to_openssh(LineEnding::LF).unwrap();

        // build the certificate
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let valid_after = now - 120;
        let valid_before = now + self.valid_secs as u64;

        let mut cert_builder =
            Builder::new_with_random_nonce(&mut OsRng, key.public_key(), valid_after, valid_before);

        let key_id = format!("nioca-{}", group.name);
        cert_builder.key_id(key_id)?;
        let cert_type = SshCertType::from_str(&self.typ);
        cert_builder.cert_type(cert_type.as_cert_type())?;

        self.principals.split(',').for_each(|p| {
            cert_builder.valid_principal(p).unwrap();
        });

        // All extensions and critical options are only validated for user certificates.
        // OpenSSH does NOT validate / force them for host certificates!
        if cert_type == SshCertType::User {
            // force_command and source_address currently throw errors - will be added later
            // if let Some(cmd) = &self.force_command {
            //     cert_builder
            //         .critical_option("force-command", cmd.clone())
            //         .unwrap();
            // }
            // if let Some(sources) = &self.source_addresses {
            //     let ips = sources.join(",");
            //     cert_builder.critical_option("source-address", ips).unwrap();
            // }

            if let Some(value) = self.permit_x11_forwarding {
                if value {
                    cert_builder.extension("permit-X11-forwarding", "").unwrap();
                }
            }
            if let Some(value) = self.permit_agent_forwarding {
                if value {
                    cert_builder
                        .extension("permit-agent-forwarding", "")
                        .unwrap();
                }
            }
            if let Some(value) = self.permit_port_forwarding {
                if value {
                    cert_builder
                        .extension("permit-port-forwarding", "")
                        .unwrap();
                }
            }
            if let Some(value) = self.permit_pty {
                if value {
                    cert_builder.extension("permit-pty", "").unwrap();
                }
            }
            if let Some(value) = self.permit_user_rc {
                if value {
                    cert_builder.extension("permit-user-rc", "").unwrap();
                }
            }
        }

        let comment = format!("nioca-{}", self.name);
        cert_builder.comment(comment)?;

        // generate a certificate without data to get a serial from the DB
        let entity = CertSshEntity::from(self);
        let mut cert_entity = entity.insert().await?;
        assert!(cert_entity.serial > 0);
        cert_builder.serial(cert_entity.serial as u64)?;

        let ca = CaCertSshEntity::find_by_group(&self.group_id).await?;
        let ca_key = {
            let enc_keys = &state.read().await.enc_keys;
            ca.get_private_key(enc_keys).await?
        };
        let cert = cert_builder.sign(&ca_key)?;
        let cert_openssh = cert.to_openssh().unwrap();

        let kp = SshKeyPairOpenssh {
            id: key_openssh.to_string(),
            id_pub: cert_openssh,
            alg: key_alg,
            typ: Some(cert_type),
        };

        let cert_bytes = kp.id_pub.as_bytes().to_vec();
        cert_entity.data = cert_bytes;
        cert_entity.update_data().await?;
        ClientSshEntity::set_last_cert(&self.id, cert_entity.serial).await?;

        info!(
            "New SSH Certificate generated for client {} - {}",
            self.id, self.name
        );

        let resp = SshCertificateResponse {
            user_ca_pub: ca.pub_key,
            host_key_pair: kp,
        };

        Ok(resp)
    }

    fn expires_from_req(ts: Option<i64>) -> Result<Option<OffsetDateTime>, ErrorResponse> {
        if let Some(ts) = ts {
            match OffsetDateTime::from_unix_timestamp(ts) {
                Ok(dt) => Ok(Some(dt)),
                Err(err) => Err(ErrorResponse::new(
                    ErrorResponseType::BadRequest,
                    format!("Cannot parse the 'expires' timestamp: {}", err),
                )),
            }
        } else {
            Ok(None)
        }
    }

    pub async fn validate_active_enabled(
        &self,
        state: &AppStateExtract,
        api_key: &str,
    ) -> Result<GroupEntity, ErrorResponse> {
        if !self.enabled {
            return Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "Client is disabled".to_string(),
            ));
        }

        if let Some(exp) = self.expires.as_ref() {
            if exp < &OffsetDateTime::now_utc() {
                debug!("Client expiry: {:?}", self.expires);
                debug!("NOW: {:?}", Some(OffsetDateTime::now_utc()));
                return Err(ErrorResponse::new(
                    ErrorResponseType::Unauthorized,
                    "Client has expired".to_string(),
                ));
            }
        }

        let group = GroupEntity::find_by_id(&self.group_id).await?;
        if !group.enabled {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                // TODO remove the group name here to not possibly leak group names?
                // format!("Group '{}' is disabled", group.name),
                "Group is disabled".to_string(),
            ));
        }

        let enc_keys = state.read().await.enc_keys.clone();
        let client_key = self.decrypt_api_key(&enc_keys).await?;

        if api_key != client_key {
            return Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "Bad Credentials".to_string(),
            ));
        }

        Ok(group)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum SshCertType {
    Host,
    User,
}

impl SshCertType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Host => "host",
            Self::User => "user",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "host" => Self::Host,
            "user" => Self::User,
            _ => unreachable!(),
        }
    }

    pub fn as_cert_type(&self) -> CertType {
        match self {
            SshCertType::Host => CertType::Host,
            SshCertType::User => CertType::User,
        }
    }
}

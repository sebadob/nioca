use crate::certificates::encryption::{decrypt, encrypt};
use crate::certificates::{SshKeyAlg, X509KeyAlg, X509KeyUsages, X509KeyUsagesExt};
use crate::config::{Db, EncKeys};
use crate::models::api::error_response::ErrorResponse;
use crate::models::api::request::UsersGroupAccessRequest;
use crate::models::db::enc_key::EncKeyEntity;
use serde::{Deserialize, Serialize};
use sqlx::{query, query_as};
use std::default::Default;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersGroupAccessEntity {
    pub user_id: Uuid,
    pub group_id: Uuid,
    pub enc_key_id: Uuid,
    pub group_access: Vec<u8>,
}

impl UsersGroupAccessEntity {
    pub async fn find_group_access(
        &self,
        enc_keys: &EncKeys,
    ) -> Result<UsersGroupAccess, ErrorResponse> {
        let group_access = if self.enc_key_id != enc_keys.enc_key.id {
            // we should decrypt with the old and re-encrypt with the currently active key
            let key = EncKeyEntity::find(&self.enc_key_id, &enc_keys.master_key).await?;
            let dec = decrypt(&self.group_access, &key.value)?;

            // re-encrypt with the currently active key and update the DB
            let enc = encrypt(&dec, &enc_keys.enc_key.value)?;
            query!(
                r#"UPDATE users_group_access
                SET enc_key_id = $1, group_access = $2
                WHERE user_id = $3 AND group_id = $4"#,
                enc_keys.enc_key.id,
                enc,
                self.user_id,
                self.group_id,
            )
            .execute(Db::conn())
            .await?;

            bincode::deserialize::<UsersGroupAccess>(&dec)?
        } else {
            let dec = decrypt(&self.group_access, &enc_keys.enc_key.value)?;
            bincode::deserialize::<UsersGroupAccess>(&dec)?
        };

        Ok(group_access)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGroupAccessSsh {
    pub enabled: bool,
    pub key_alg: SshKeyAlg,
    pub principals: Vec<String>,
    pub force_command: Option<String>,
    pub permit_x11_forwarding: Option<bool>,
    pub permit_agent_forwarding: Option<bool>,
    pub permit_port_forwarding: Option<bool>,
    pub permit_pty: Option<bool>,
    pub permit_user_rc: Option<bool>,
    pub valid_secs: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGroupAccessX509 {
    pub enabled: bool,
    pub key_alg: X509KeyAlg,
    pub key_usage: Vec<X509KeyUsages>,
    pub key_usage_ext: Vec<X509KeyUsagesExt>,
    pub valid_hours: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersGroupAccess {
    pub user_id: Uuid,
    pub group_id: Uuid,
    pub secret_create: bool,
    pub secret_read: bool,
    pub secret_update: bool,
    pub secret_delete: bool,
    pub access_ssh: UserGroupAccessSsh,
    pub access_x509: UserGroupAccessX509,
}

impl UsersGroupAccess {
    pub async fn create(
        user_id: Uuid,
        group_id: Uuid,
        enc_key: &EncKeyEntity,
    ) -> Result<(), ErrorResponse> {
        let group_access = UsersGroupAccess {
            user_id,
            group_id,
            ..Default::default()
        };
        let access_bytes = bincode::serialize(&group_access).unwrap();
        let access_enc = encrypt(access_bytes.as_slice(), enc_key.value.as_slice())?;
        let enc_key_id = enc_key.id;

        query!(
            r#"INSERT INTO
            users_group_access (user_id, group_id, enc_key_id, group_access)
            VALUES ($1, $2, $3, $4)"#,
            group_access.user_id,
            group_access.group_id,
            enc_key_id,
            access_enc,
        )
        .execute(Db::conn())
        .await?;

        Ok(())
    }

    // pub async fn find_for_group(user_id: Uuid, group_id: Uuid) -> Result<Self, ErrorResponse> {
    //     // TODO
    //     Ok(())
    // }

    // pub async fn find_groups(user_id: Uuid) -> Result<Vec<Uuid>, ErrorResponse> {
    //     // TODO
    //     Ok(())
    // }

    pub async fn find_all_user(
        enc_keys: &EncKeys,
        user_id: &Uuid,
    ) -> Result<Vec<Self>, ErrorResponse> {
        let entities = query_as!(
            UsersGroupAccessEntity,
            "SELECT * FROM users_group_access WHERE user_id = $1",
            user_id
        )
        .fetch_all(Db::conn())
        .await?;

        let mut res = Vec::with_capacity(entities.len());
        for entity in entities {
            res.push(entity.find_group_access(enc_keys).await?);
        }

        Ok(res)
    }

    pub async fn update(
        enc_key: &EncKeyEntity,
        user_id: Uuid,
        group_id: Uuid,
        group_access: &UsersGroupAccess,
    ) -> Result<(), ErrorResponse> {
        let access_bytes = bincode::serialize(group_access).unwrap();
        let access_enc = encrypt(access_bytes.as_slice(), enc_key.value.as_slice())?;
        let enc_key_id = enc_key.id;

        query!(
            r#"UPDATE users_group_access
            SET enc_key_id = $1, group_access = $2
            WHERE user_id = $3 AND group_id = $4"#,
            enc_key_id,
            access_enc,
            user_id,
            group_id,
        )
        .execute(Db::conn())
        .await?;

        Ok(())
    }

    pub async fn delete(user_id: Uuid, group_id: Uuid) -> Result<(), ErrorResponse> {
        query!(
            "DELETE FROM users_group_access WHERE user_id = $1 AND group_id = $2",
            user_id,
            group_id
        )
        .execute(Db::conn())
        .await?;
        Ok(())
    }
}

impl Default for UsersGroupAccess {
    fn default() -> Self {
        Self {
            user_id: Default::default(),
            group_id: Default::default(),
            secret_create: false,
            secret_read: false,
            secret_update: false,
            secret_delete: false,
            access_ssh: UserGroupAccessSsh {
                enabled: false,
                key_alg: SshKeyAlg::Ed25519,
                principals: vec!["nobody".to_string()],
                force_command: None,
                permit_x11_forwarding: Some(false),
                permit_agent_forwarding: Some(false),
                permit_port_forwarding: Some(false),
                permit_pty: Some(true),
                permit_user_rc: Some(true),
                valid_secs: 3600,
            },
            access_x509: UserGroupAccessX509 {
                enabled: false,
                key_alg: X509KeyAlg::ECDSA,
                key_usage: vec![
                    X509KeyUsages::DigitalSignature,
                    X509KeyUsages::ContentCommitment,
                ],
                key_usage_ext: vec![
                    X509KeyUsagesExt::ClientAuth,
                    X509KeyUsagesExt::CodeSigning,
                    X509KeyUsagesExt::EmailProtection,
                ],
                valid_hours: 720,
            },
        }
    }
}

impl TryFrom<UsersGroupAccessRequest> for UsersGroupAccess {
    type Error = ErrorResponse;

    fn try_from(value: UsersGroupAccessRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            user_id: Uuid::from_str(&value.user_id)?,
            group_id: Uuid::from_str(&value.group_id)?,
            secret_create: value.secret_create,
            secret_read: value.secret_read,
            secret_update: value.secret_update,
            secret_delete: value.secret_delete,
            access_ssh: UserGroupAccessSsh {
                enabled: value.access_ssh.enabled,
                key_alg: value.access_ssh.key_alg,
                principals: value.access_ssh.principals,
                force_command: value.access_ssh.force_command,
                permit_x11_forwarding: value.access_ssh.permit_x11_forwarding,
                permit_agent_forwarding: value.access_ssh.permit_agent_forwarding,
                permit_port_forwarding: value.access_ssh.permit_port_forwarding,
                permit_pty: value.access_ssh.permit_pty,
                permit_user_rc: value.access_ssh.permit_user_rc,
                valid_secs: value.access_ssh.valid_secs,
            },
            access_x509: UserGroupAccessX509 {
                enabled: value.access_x509.enabled,
                key_alg: value.access_x509.key_alg,
                key_usage: value.access_x509.key_usage,
                key_usage_ext: value.access_x509.key_usage_ext,
                valid_hours: value.access_x509.valid_hours,
            },
        })
    }
}

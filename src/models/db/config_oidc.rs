use crate::certificates::encryption::{decrypt, encrypt};
use crate::config::{Db, EncKeys};
use crate::models::api::error_response::ErrorResponse;
use crate::models::api::request::{ConfigOidcEntityRequest, JwtClaimTypRequest};
use crate::models::db::enc_key::EncKeyEntity;
use crate::models::db::key_value_enc::KeyValueEncEntity;
use serde::{Deserialize, Serialize};
use sqlx::{query, query_as};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigOidcEntity {
    pub admin_claim: Option<JwtClaim>,
    pub user_claim: Option<JwtClaim>,
    pub aud: String,
    pub client_id: String,
    pub email_verified: bool,
    pub iss: String,
    pub scope: String,
    pub secret: String,
}

// CRUD
impl ConfigOidcEntity {
    pub async fn find(enc_keys: &EncKeys) -> Result<Self, ErrorResponse> {
        let enc_entity = query_as!(KeyValueEncEntity, "select * from config where key = 'oidc'")
            .fetch_one(Db::conn())
            .await?;

        let slf = if enc_entity.enc_key_id != enc_keys.enc_key.id {
            // re-encrypt the config and save it
            let k = EncKeyEntity::find(&enc_entity.enc_key_id, &enc_keys.master_key).await?;
            let dec = decrypt(&enc_entity.value, &k.value)?;
            let slf = bincode::deserialize::<Self>(&dec)?;
            slf.save(enc_keys).await?;
            slf
        } else {
            let dec = decrypt(&enc_entity.value, &enc_keys.enc_key.value)?;
            bincode::deserialize::<Self>(&dec)?
        };

        Ok(slf)
    }

    pub async fn save(&self, enc_keys: &EncKeys) -> Result<(), ErrorResponse> {
        let bytes = bincode::serialize(self).unwrap();
        let enc = encrypt(&bytes, &enc_keys.enc_key.value)?;

        query!(
            "insert into config (key, enc_key_id, value) values('oidc', $1, $2)\
             on conflict (key) do \
             update set enc_key_id = $1, value = $2",
            enc_keys.enc_key.id,
            enc
        )
        .execute(Db::conn())
        .await?;

        Ok(())
    }
}

impl From<ConfigOidcEntityRequest> for ConfigOidcEntity {
    fn from(value: ConfigOidcEntityRequest) -> Self {
        let admin_claim = if let Some(c) = value.admin_claim {
            let typ = match c.typ {
                JwtClaimTypRequest::Roles => JwtClaimTyp::Roles,
                JwtClaimTypRequest::Groups => JwtClaimTyp::Groups,
            };
            Some(JwtClaim {
                typ,
                value: c.value,
            })
        } else {
            None
        };

        let user_claim = if let Some(c) = value.user_claim {
            let typ = match c.typ {
                JwtClaimTypRequest::Roles => JwtClaimTyp::Roles,
                JwtClaimTypRequest::Groups => JwtClaimTyp::Groups,
            };
            Some(JwtClaim {
                typ,
                value: c.value,
            })
        } else {
            None
        };

        Self {
            admin_claim,
            user_claim,
            aud: value.aud,
            client_id: value.client_id,
            email_verified: value.email_verified,
            iss: value.iss,
            scope: value.scope,
            secret: value.secret,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaim {
    pub typ: JwtClaimTyp,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JwtClaimTyp {
    Roles,
    Groups,
}

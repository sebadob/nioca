use crate::certificates::encryption::{decrypt_by_kid, encrypt};
use crate::certificates::x509::cert_from_key_pem;
use crate::config::{Db, EncKeys};
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::util::{fingerprint, pem_to_der};
use der::Document;
use rcgen::Certificate;
use sqlx::{query, query_as, Postgres, Transaction};
use time::OffsetDateTime;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct CaCertX509Entity {
    pub id: Uuid,
    pub typ: CaCertX509Type,
    pub name: String,
    pub expires: Option<OffsetDateTime>,
    pub data: String,
    pub fingerprint: Option<Vec<u8>>,
    pub enc_key_id: Uuid,
}

impl CaCertX509Entity {
    pub async fn insert(&self, txn: &mut Transaction<'_, Postgres>) -> Result<(), ErrorResponse> {
        query!(
            r#"INSERT INTO ca_certs_x509 (id, typ, name, expires, data, fingerprint, enc_key_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            self.id,
            self.typ.as_str(),
            self.name,
            self.expires,
            self.data,
            self.fingerprint,
            self.enc_key_id,
        )
        .execute(&mut **txn)
        .await?;
        Ok(())
    }

    pub async fn find_all_by_type(typ: CaCertX509Type) -> Result<Vec<Self>, ErrorResponse> {
        let res = query_as!(
            Self,
            "SELECT * FROM ca_certs_x509 WHERE typ = $1",
            typ.as_str()
        )
        .fetch_all(Db::conn())
        .await?;
        Ok(res)
    }

    pub async fn find_all_certs() -> Result<Vec<Self>, ErrorResponse> {
        let res = query_as!(
            Self,
            "SELECT * FROM ca_certs_x509 WHERE typ = $1 OR typ = $2",
            CaCertX509Type::Root.as_str(),
            CaCertX509Type::Certificate.as_str(),
        )
        .fetch_all(Db::conn())
        .await?;
        Ok(res)
    }

    pub async fn find_default(typ: CaCertX509Type) -> Result<Self, ErrorResponse> {
        let slf = query_as!(
            Self,
            r#"SELECT * FROM ca_certs_x509
            WHERE typ = $1
            AND id = (SELECT uuid(ca_x509) FROM groups WHERE name = 'default')"#,
            typ.as_str(),
        )
        .fetch_one(Db::conn())
        .await?;
        Ok(slf)
    }

    pub async fn find_by_id(id: &Uuid, typ: CaCertX509Type) -> Result<Self, ErrorResponse> {
        let slf = query_as!(
            Self,
            "SELECT * FROM ca_certs_x509 WHERE id = $1 AND typ = $2",
            id,
            typ.as_str(),
        )
        .fetch_one(Db::conn())
        .await?;
        Ok(slf)
    }

    pub async fn find_all_by_id(id: &Uuid) -> Result<Vec<Self>, ErrorResponse> {
        let slf = query_as!(Self, "SELECT * FROM ca_certs_x509 WHERE id = $1", id,)
            .fetch_all(Db::conn())
            .await?;
        Ok(slf)
    }

    pub async fn delete_by_id(id: &Uuid) -> Result<(), ErrorResponse> {
        query!("DELETE FROM ca_certs_x509 WHERE id = $1", id)
            .execute(Db::conn())
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, sqlx::Type)]
#[sqlx(type_name = "typ")]
#[sqlx(rename_all = "lowercase")]
pub enum CaCertX509Type {
    Unknown,
    Root,
    Certificate,
    Key,
}

impl Default for CaCertX509Type {
    fn default() -> Self {
        Self::Unknown
    }
}

impl From<String> for CaCertX509Type {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

impl From<&str> for CaCertX509Type {
    fn from(value: &str) -> Self {
        match value {
            "root" => Self::Root,
            "certificate" => Self::Certificate,
            "key" => Self::Key,
            "unknown" => Self::Unknown,
            _ => unreachable!(),
        }
    }
}

impl CaCertX509Type {
    pub fn as_str<'a>(&self) -> &'a str {
        match self {
            CaCertX509Type::Root => "root",
            CaCertX509Type::Certificate => "certificate",
            CaCertX509Type::Key => "key",
            CaCertX509Type::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaCertX509Root {
    pub expires: OffsetDateTime,
    pub cert_pem: String,
    pub cert_der: Document,
    pub fingerprint: String,
}

impl CaCertX509Root {
    pub async fn add_new(
        enc_keys: &EncKeys,
        id: Uuid,
        name: String,
        cert_pem: String,
        fingerprint: &str,
        exp: OffsetDateTime,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(), ErrorResponse> {
        let fingerprint = encrypt(fingerprint.as_bytes(), enc_keys.enc_key.value.as_slice())?;
        let entity_cert = CaCertX509Entity {
            id,
            typ: CaCertX509Type::Root,
            name: name.clone(),
            expires: Some(exp),
            data: cert_pem,
            fingerprint: Some(fingerprint),
            enc_key_id: enc_keys.enc_key.id,
        };
        entity_cert.insert(txn).await?;

        Ok(())
    }

    pub async fn find_default(
        enc_keys: &EncKeys,
        is_sealed: bool,
    ) -> Result<CaCertX509Root, ErrorResponse> {
        let cert_entity = CaCertX509Entity::find_default(CaCertX509Type::Root).await?;
        Self::build(cert_entity, enc_keys, is_sealed).await
    }

    #[allow(dead_code)]
    pub async fn find(
        id: &Uuid,
        enc_keys: &EncKeys,
        is_sealed: bool,
    ) -> Result<CaCertX509Root, ErrorResponse> {
        let cert_entity = CaCertX509Entity::find_by_id(id, CaCertX509Type::Root).await?;
        Self::build(cert_entity, enc_keys, is_sealed).await
    }

    pub async fn build(
        cert: CaCertX509Entity,
        enc_keys: &EncKeys,
        is_sealed: bool,
    ) -> Result<CaCertX509Root, ErrorResponse> {
        let fingerprint_str = if is_sealed {
            String::default()
        } else {
            let (bytes, bytes_new) =
                decrypt_by_kid(&cert.fingerprint.unwrap(), &cert.enc_key_id, enc_keys).await?;
            if let Some(bytes_new) = bytes_new {
                query!(
                    "UPDATE ca_certs_x509 SET fingerprint = $1, enc_key_id = $2 WHERE id = $3 AND typ = $4",
                    bytes_new,
                    enc_keys.enc_key.id,
                    cert.id,
                    CaCertX509Type::Root.as_str(),
                )
                    .execute(Db::conn())
                .await?;
            }
            let fingerprint_str = String::from_utf8(bytes)?;
            info!("Root PEM fingerprint: {}", fingerprint_str);

            // validate the fingerprint
            let finger = fingerprint(cert.data.as_bytes());
            // let finger = fingerprint(cert.data.as_bytes());
            if fingerprint_str == finger {
                info!("Fingerprint for Root PEM matches");
            } else {
                info!("\n\ncert.data:\n{}\n\n", cert.data);
                panic!(
                    "Fingerprint mismatch for CaCertRoot: {} != {}",
                    fingerprint_str, finger
                );
            }

            fingerprint_str
        };

        let cert_der = pem_to_der(&cert.data)?;

        Ok(CaCertX509Root {
            expires: cert.expires.unwrap(),
            cert_pem: cert.data,
            cert_der,
            fingerprint: fingerprint_str,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CaCertX509Nioca {
    pub id: Uuid,
    pub expires: OffsetDateTime,
    pub cert_pem: String,
    pub cert_der: Document,
    pub key: String,
    pub fingerprint: String,
}

impl CaCertX509Nioca {
    pub async fn add_new(
        enc_keys: &EncKeys,
        id: Uuid,
        name: String,
        cert_pem: String,
        fingerprint: &str,
        key_plain: &str,
        exp: OffsetDateTime,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(), ErrorResponse> {
        let enc_key = enc_keys.enc_key.value.as_slice();
        let enc_key_id = enc_keys.enc_key.id;

        let fingerprint = encrypt(fingerprint.as_bytes(), enc_key)?;
        let entity_cert = CaCertX509Entity {
            id,
            typ: CaCertX509Type::Certificate,
            name: name.clone(),
            expires: Some(exp),
            data: cert_pem,
            fingerprint: Some(fingerprint),
            enc_key_id,
        };
        entity_cert.insert(txn).await?;

        let key_enc = encrypt(key_plain.as_bytes(), enc_key)?;
        let key_enc_hex = hex::encode(key_enc);
        let entity_key = CaCertX509Entity {
            id,
            typ: CaCertX509Type::Key,
            name,
            expires: None,
            data: key_enc_hex,
            fingerprint: None,
            enc_key_id,
        };
        entity_key.insert(txn).await?;

        Ok(())
    }

    pub async fn find_default(enc_keys: &EncKeys) -> Result<CaCertX509Nioca, ErrorResponse> {
        let cert_entity = CaCertX509Entity::find_default(CaCertX509Type::Certificate).await?;
        let key_entity = CaCertX509Entity::find_default(CaCertX509Type::Key).await?;
        Self::build(cert_entity, key_entity, enc_keys).await
    }

    #[allow(dead_code)]
    pub async fn find(id: &Uuid, enc_keys: &EncKeys) -> Result<CaCertX509Nioca, ErrorResponse> {
        let cert_entity = CaCertX509Entity::find_by_id(id, CaCertX509Type::Certificate).await?;
        let key_entity = CaCertX509Entity::find_by_id(id, CaCertX509Type::Key).await?;
        Self::build(cert_entity, key_entity, enc_keys).await
    }

    pub async fn build(
        cert_entity: CaCertX509Entity,
        key_entity: CaCertX509Entity,
        enc_keys: &EncKeys,
    ) -> Result<CaCertX509Nioca, ErrorResponse> {
        // private key
        let key_decoded = hex::decode(key_entity.data).expect("Decoding Cert Key from HEX");
        let (key_bytes, key_bytes_new) =
            decrypt_by_kid(&key_decoded, &cert_entity.enc_key_id, enc_keys).await?;
        let key = match String::from_utf8(key_bytes) {
            Ok(k) => k,
            Err(err) => {
                error!("{}", err);
                return Err(ErrorResponse::new(
                    ErrorResponseType::Internal,
                    "Error reconstructing the private key".to_string(),
                ));
            }
        };

        let db = Db::conn();
        if let Some(bytes_new) = key_bytes_new {
            let nioca_key_enc_hex = hex::encode(bytes_new);
            query!(
                "UPDATE ca_certs_x509 SET data = $1, enc_key_id = $2 WHERE id = $3 AND typ = $4",
                nioca_key_enc_hex,
                enc_keys.enc_key.id,
                key_entity.id,
                CaCertX509Type::Key.as_str(),
            )
            .execute(db)
            .await?;
        }

        // fingerprint
        let (fingerprint_bytes, fingerprint_bytes_new) = decrypt_by_kid(
            &cert_entity.fingerprint.unwrap(),
            &cert_entity.enc_key_id,
            enc_keys,
        )
        .await?;
        if let Some(bytes_new) = fingerprint_bytes_new {
            query!(
                "UPDATE ca_certs_x509 SET fingerprint = $1, enc_key_id = $2 WHERE id = $3 AND typ = $4",
                bytes_new,
                enc_keys.enc_key.id,
                cert_entity.id,
                CaCertX509Type::Certificate.as_str(),
            )
                .execute(db)
                .await?;
        }
        let fingerprint_str = String::from_utf8(fingerprint_bytes)?;
        info!("Nioca Intermediate PEM fingerprint: {}", fingerprint_str);

        // validate the fingerprint
        let finger = fingerprint(cert_entity.data.as_bytes());
        if fingerprint_str == finger {
            info!("Fingerprint for Nioca Intermediate PEM matches");
        } else {
            info!("\n\ncert_entity.data:\n{}\n\n", cert_entity.data);
            panic!(
                "Fingerprint mismatch for CaCertNioca: {} != {}",
                fingerprint_str, finger
            );
        }

        let cert_der = pem_to_der(&cert_entity.data)?;

        Ok(CaCertX509Nioca {
            id: cert_entity.id,
            expires: cert_entity.expires.unwrap(),
            cert_pem: cert_entity.data,
            cert_der,
            key,
            fingerprint: fingerprint_str,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CaCertX509Full {
    pub root: CaCertX509Root,
    pub intermediate: CaCertX509Nioca,
    // pub signing_cert: Certificate,
    pub ca_chain_pem: String,
}

impl CaCertX509Full {
    pub async fn build_by_id(id: &Uuid, enc_keys: &EncKeys) -> Result<Self, ErrorResponse> {
        let entities = CaCertX509Entity::find_all_by_id(id).await?;
        // TODO remove assertion after testing
        assert_eq!(entities.len(), 3);

        let mut root = None;
        let mut it = None;
        let mut key = None;
        for entity in entities {
            match entity.typ {
                CaCertX509Type::Unknown => panic!("Corrupted Database for CaCertX509Entity"),
                CaCertX509Type::Root => root = Some(entity),
                CaCertX509Type::Certificate => it = Some(entity),
                CaCertX509Type::Key => key = Some(entity),
            }
        }
        let root = root.expect("root x509 missing in CaCertX509Full::build_by_id()");
        let it = it.expect("it x509 missing in CaCertX509Full::build_by_id()");
        let key = key.expect("key x509 missing in CaCertX509Full::build_by_id()");

        let root = CaCertX509Root::build(root, enc_keys, false).await?;
        let intermediate = CaCertX509Nioca::build(it, key, enc_keys).await?;
        // let signing_cert = cert_from_key_pem(&intermediate.key, &intermediate.cert_pem).await?;
        let ca_chain_pem = format!("{}\n{}", intermediate.cert_pem, root.cert_pem);

        Ok(Self {
            root,
            intermediate,
            // signing_cert,
            ca_chain_pem,
        })
    }

    pub fn signing_cert(&self) -> Result<Certificate, ErrorResponse> {
        let res = cert_from_key_pem(&self.intermediate.key, &self.intermediate.cert_pem)?;
        Ok(res)
    }
}

use crate::certificates::encryption::{decrypt, encrypt, kdf_danger_static};
use crate::certificates::SshKeyAlg;
use crate::config::{Db, EncKeys};
use crate::models::api::error_response::ErrorResponse;
use crate::models::db::client_ssh::SshCertType;
use crate::models::db::enc_key::EncKeyEntity;
use der::pem::LineEnding;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{query, query_as};
use ssh_key::PrivateKey;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct CaCertSshEntity {
    pub id: Uuid,
    pub name: String,
    pub pub_key: String,
    pub data: Vec<u8>,
    pub enc_key_id: Uuid,
}

impl CaCertSshEntity {
    pub async fn insert(
        name: String,
        kp: SshKeyPairOpenssh,
        enc_key: &EncKeyEntity,
    ) -> Result<Self, ErrorResponse> {
        let pub_key = kp.id_pub;
        let data = encrypt(kp.id.as_bytes(), &enc_key.value)?;
        let slf = Self {
            id: Uuid::new_v4(),
            name,
            pub_key,
            data,
            enc_key_id: enc_key.id,
        };

        query!(
            r#"
            INSERT INTO ca_certs_ssh (id, name, pub_key, data, enc_key_id)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            slf.id,
            slf.name,
            slf.pub_key,
            slf.data,
            slf.enc_key_id,
        )
        .execute(Db::conn())
        .await?;

        Ok(slf)
    }

    pub async fn generate_new(
        name: String,
        alg: SshKeyAlg,
        enc_key: &EncKeyEntity,
    ) -> Result<Self, ErrorResponse> {
        let kp = SshKeyPairOpenssh::new(alg)?;
        let pub_key = kp.id_pub;
        let data = encrypt(kp.id.as_bytes(), &enc_key.value)?;
        let slf = Self {
            id: Uuid::new_v4(),
            name,
            pub_key,
            data,
            enc_key_id: enc_key.id,
        };

        query!(
            r#"
            INSERT INTO ca_certs_ssh (id, name, pub_key, data, enc_key_id)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            slf.id,
            slf.name,
            slf.pub_key,
            slf.data,
            slf.enc_key_id,
        )
        .execute(Db::conn())
        .await?;

        Ok(slf)
    }

    pub async fn find_all() -> Result<Vec<Self>, ErrorResponse> {
        let res = query_as!(Self, "SELECT * FROM ca_certs_ssh")
            .fetch_all(Db::conn())
            .await?;
        Ok(res)
    }

    // pub async fn find_by_id(id: &Uuid) -> Result<Self, ErrorResponse> {
    //     query_as!(Self, "select * from ca_certs_ssh where id = $1", id)
    //         .fetch_one(Db::conn())
    //         .await
    //         .map_err(ErrorResponse::from)
    // }

    pub async fn find_by_group(group_id: &Uuid) -> Result<Self, ErrorResponse> {
        let res = query_as!(
            Self,
            "SELECT * FROM ca_certs_ssh WHERE id = (SELECT ca_ssh FROM groups WHERE id = $1)",
            group_id
        )
        .fetch_one(Db::conn())
        .await?;
        Ok(res)
    }

    pub async fn delete_by_id(id: &Uuid) -> Result<(), ErrorResponse> {
        query!("DELETE FROM ca_certs_ssh WHERE id = $1", id)
            .execute(Db::conn())
            .await?;
        Ok(())
    }

    pub async fn get_private_key(&self, enc_keys: &EncKeys) -> Result<PrivateKey, ErrorResponse> {
        if self.enc_key_id != enc_keys.enc_key.id {
            let enc_key = EncKeyEntity::find(&self.enc_key_id, &enc_keys.master_key).await?;
            let dec = decrypt(&self.data, &enc_key.value)?;
            let key_openssh = String::from_utf8_lossy(&dec);
            let private_key = PrivateKey::from_openssh(key_openssh.as_bytes())?;

            // re-encrypt with the currently active key for future use
            let enc = encrypt(&dec, &enc_keys.enc_key.value)?;
            query!(
                "UPDATE ca_certs_ssh SET data = $1, enc_key_id = $2 WHERE id = $3",
                enc,
                enc_keys.enc_key.id,
                self.id,
            )
            .execute(Db::conn())
            .await?;

            Ok(private_key)
        } else {
            let dec = decrypt(&self.data, &enc_keys.enc_key.value)?;
            let key_openssh = String::from_utf8_lossy(&dec);
            let private_key = PrivateKey::from_openssh(key_openssh.as_bytes())?;

            Ok(private_key)
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SshKeyPairOpenssh {
    pub id: String,
    pub id_pub: String,
    pub alg: SshKeyAlg,
    pub typ: Option<SshCertType>,
}

impl SshKeyPairOpenssh {
    pub fn new(alg: SshKeyAlg) -> Result<Self, ErrorResponse> {
        let key = PrivateKey::random(&mut OsRng, alg.as_alg()).unwrap();
        let id_pub = key.public_key().to_openssh().unwrap();
        let id = key.to_openssh(LineEnding::LF).unwrap().to_string();

        Ok(Self {
            id,
            id_pub,
            alg,
            typ: None,
        })
    }

    pub async fn from_key_enc(key_enc_hex: &str, password: &str) -> Result<Self, ErrorResponse> {
        let bytes = hex::decode(key_enc_hex)?;
        let secret = kdf_danger_static(password.as_bytes()).await?;
        let dec = decrypt(&bytes, &secret)?;
        let dec_str = String::from_utf8_lossy(&dec);
        let key = PrivateKey::from_openssh(dec_str.as_ref())?;

        let alg = SshKeyAlg::from_alg(key.algorithm())?;
        let id = key.to_openssh(LineEnding::LF)?.to_string();
        let id_pub = key.public_key().to_openssh()?;

        Ok(SshKeyPairOpenssh {
            id,
            id_pub,
            alg,
            typ: None,
        })
    }
}

// #[derive(Debug, Clone, Default)]
// pub struct CaCertSshExtendedEntity {
//     pub cert_id: Uuid,
//     pub pub_key: String,
//     pub group_id: Uuid,
//     pub is_default: bool,
//     pub group_name: String,
//     pub enabled: bool,
// }
//
// impl CaCertSshExtendedEntity {
//     pub async fn find_all() -> Result<Vec<Self>, ErrorResponse> {
//         // query_as!(
//         //     Self,
//         //     r#"
//         //     SELECT c.id AS cert_id, c.pub_key, c.group_id, c.is_default, g.name AS group_name, g.enabled
//         //     FROM ca_certs_ssh c
//         //     JOIN groups g ON c.group_id = g.id
//         //     "#
//         // )
//         query_as!(Self, "SELECT * ca_certs_ssh")
//             .fetch_all(Db::conn())
//             .await
//             .map_err(ErrorResponse::from)
//     }
//
//     pub async fn find_by_id(id: &Uuid) -> Result<Self, ErrorResponse> {
//         query_as!(
//             Self,
//             r#"
//             SELECT c.id AS cert_id, c.pub_key, c.group_id, c.is_default, g.name AS group_name, g.enabled
//             FROM ca_certs_ssh c
//             JOIN groups g ON c.group_id = g.id
//             WHERE c.id = $1
//             "#,
//             id
//         )
//         .fetch_one(Db::conn())
//         .await
//         .map_err(ErrorResponse::from)
//     }
//
//     //
//     // pub async fn find_by_id(db: DbPool, id: &str) -> Result<Self, ErrorResponse> {
//     //     query_as!(Self, "select * from ca_certs_x509 where id = $1", id)
//     //         .fetch_one(&*db)
//     //         .await
//     //         .map_err(ErrorResponse::from)
//     // }
// }

// #[derive(Debug, Clone)]
// pub struct CaCertRoot {
//     pub expires: OffsetDateTime,
//     pub cert_pem: String,
//     pub cert_der: Document,
//     pub fingerprint: String,
// }
//
// impl CaCertRoot {
//     pub async fn find(
//         db: DbPool,
//         enc_keys: &EncKeys,
//         is_sealed: bool,
//     ) -> Result<CaCertRoot, ErrorResponse> {
//         let cert = CaCertSshEntity::find_by_id(db.clone(), "root_cert").await?;
//
//         let fingerprint_str = if is_sealed {
//             String::default()
//         } else {
//             let (bytes, bytes_new) =
//                 decrypt_by_kid(&cert.fingerprint.unwrap(), &cert.enc_key_id, enc_keys, &db).await?;
//             if let Some(bytes_new) = bytes_new {
//                 query!(
//                     "update ca_certs_x509 set fingerprint = $1, enc_key_id = $2 where id = 'root_cert'",
//                     bytes_new,
//                     enc_keys.enc_key.id,
//                 )
//                 .execute(&*db)
//                 .await?;
//             }
//             let fingerprint_str = String::from_utf8(bytes)?;
//             info!("Root PEM fingerprint: {}", fingerprint_str);
//
//             // validate the fingerprint
//             let finger = fingerprint(cert.data.as_bytes());
//             // let finger = fingerprint(cert.data.as_bytes());
//             if fingerprint_str == finger {
//                 info!("Fingerprint for Root PEM matches");
//             } else {
//                 info!("\n\ncert.data:\n{}\n\n", cert.data);
//                 panic!(
//                     "Fingerprint mismatch for CaCertRoot: {} != {}",
//                     fingerprint_str, finger
//                 );
//             }
//
//             fingerprint_str
//         };
//
//         let cert_der = pem_to_der(&cert.data)?;
//
//         Ok(CaCertRoot {
//             expires: cert.expires.unwrap(),
//             cert_pem: cert.data,
//             cert_der,
//             fingerprint: fingerprint_str,
//         })
//     }
// }
//
// #[derive(Debug, Clone)]
// pub struct CaCertNioca {
//     pub expires: OffsetDateTime,
//     pub cert_pem: String,
//     pub cert_der: Document,
//     pub key: String,
//     pub fingerprint: String,
// }
//
// impl CaCertNioca {
//     pub async fn find(db: DbPool, enc_keys: &EncKeys) -> Result<CaCertNioca, ErrorResponse> {
//         let cert_entity = CaCertSshEntity::find_by_id(db.clone(), "nioca_cert").await?;
//         let key_entity = CaCertSshEntity::find_by_id(db.clone(), "nioca_key").await?;
//
//         // private key
//         let key_decoded = hex::decode(key_entity.data).expect("Decoding Cert Key from HEX");
//         let (key_bytes, key_bytes_new) =
//             decrypt_by_kid(&key_decoded, &cert_entity.enc_key_id, enc_keys, &db).await?;
//         let key = match String::from_utf8(key_bytes) {
//             Ok(k) => k,
//             Err(err) => {
//                 error!("{}", err);
//                 return Err(ErrorResponse::new(
//                     ErrorResponseType::Internal,
//                     "Error reconstructing the private key".to_string(),
//                 ));
//             }
//         };
//         if let Some(bytes_new) = key_bytes_new {
//             let nioca_key_enc_hex = hex::encode(bytes_new);
//             query!(
//                 "update ca_certs_x509 set data = $1, enc_key_id = $2 where id = 'nioca_key'",
//                 nioca_key_enc_hex,
//                 enc_keys.enc_key.id,
//             )
//             .execute(&*db)
//             .await?;
//         }
//
//         // fingerprint
//         let (fingerprint_bytes, fingerprint_bytes_new) = decrypt_by_kid(
//             &cert_entity.fingerprint.unwrap(),
//             &cert_entity.enc_key_id,
//             enc_keys,
//             &db,
//         )
//         .await?;
//         if let Some(bytes_new) = fingerprint_bytes_new {
//             query!(
//                 "update ca_certs_x509 set fingerprint = $1, enc_key_id = $2 where id = 'nioca_cert'",
//                 bytes_new,
//                 enc_keys.enc_key.id,
//             )
//             .execute(&*db)
//             .await?;
//         }
//         let fingerprint_str = String::from_utf8(fingerprint_bytes)?;
//         info!("Nioca Intermediate PEM fingerprint: {}", fingerprint_str);
//
//         // validate the fingerprint
//         let finger = fingerprint(cert_entity.data.as_bytes());
//         if fingerprint_str == finger {
//             info!("Fingerprint for Nioca Intermediate PEM matches");
//         } else {
//             info!("\n\ncert_entity.data:\n{}\n\n", cert_entity.data);
//             panic!(
//                 "Fingerprint mismatch for CaCertNioca: {} != {}",
//                 fingerprint_str, finger
//             );
//         }
//
//         let cert_der = pem_to_der(&cert_entity.data)?;
//
//         Ok(CaCertNioca {
//             expires: cert_entity.expires.unwrap(),
//             cert_pem: cert_entity.data,
//             cert_der,
//             key,
//             fingerprint: fingerprint_str,
//         })
//     }
// }

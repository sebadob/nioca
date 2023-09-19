use crate::certificates::encryption::{decrypt, encrypt};
use crate::certificates::x509::singing::{
    gen_ecdsa_key_pair, gen_ed25519_key_pair, gen_rsa_key_pair,
};
use crate::certificates::{CertFormat, X509KeyAlg, X509KeyUsages, X509KeyUsagesExt};
use crate::config::{Db, EncKeys};
use crate::models::api::error_response::{ErrorResponse, ErrorResponseType};
use crate::models::api::request::ClientX509Request;
use crate::models::api::response::CertX509Response;
use crate::models::db::ca_cert_x509::CaCertX509Full;
use crate::models::db::cert_x509::CertX509Entity;
use crate::models::db::enc_key::EncKeyEntity;
use crate::models::db::groups::GroupEntity;
use crate::routes::AppStateExtract;
use crate::util::{b64_encode, csv_to_vec, fingerprint, pem_to_der, secure_random, vec_to_csv};
use p12::PFX;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyIdMethod, KeyUsagePurpose, SanType,
};
use sqlx::{query, query_as};
use std::net::IpAddr;
use std::ops::Sub;
use std::str::FromStr;
use time::OffsetDateTime;
use tracing::{debug, error, info};
use uuid::Uuid;
use x509_parser::nom::AsBytes;

#[derive(Debug, Clone)]
pub struct ClientX509Entity {
    pub id: Uuid,
    pub name: String,
    pub expires: Option<OffsetDateTime>,
    pub enabled: bool,
    pub group_id: Uuid,
    pub api_key: Vec<u8>,
    pub enc_key_id: Uuid,
    pub key_alg: String,
    pub common_name: String,
    pub country: Option<String>,
    pub locality: Option<String>,
    pub organizational_unit: Option<String>,
    pub organization: Option<String>,
    pub state_or_province: Option<String>,
    pub alt_names_dns: String,
    pub alt_names_ip: String,
    pub key_usage: Option<Vec<u8>>,
    pub key_usage_ext: Option<Vec<u8>>,
    pub valid_hours: i32,
    pub email: String,
    pub latest_cert: Option<i32>,
}

// CRUD
impl ClientX509Entity {
    pub async fn create(
        client: ClientX509Request,
        enc_key: &EncKeyEntity,
    ) -> Result<Self, ErrorResponse> {
        let uuid = Uuid::new_v4();
        let expires = ClientX509Entity::expires_from_req(client.expires)?;
        let group_id = if let Some(id) = client.group_id {
            id
        } else {
            GroupEntity::find_default_id().await?
        };
        let dns = vec_to_csv(&client.alt_names_dns);
        let ip = vec_to_csv(&client.alt_names_ip);
        let key_usage: Vec<u8> = client.key_usage.iter().map(|u| u.value()).collect();
        let key_usage_ext: Vec<u8> = client.key_usage_ext.iter().map(|u| u.value()).collect();
        let api_key_enc = encrypt(secure_random(48).as_bytes(), enc_key.value.as_bytes())?;
        let enc_key_id = enc_key.id;

        query!(
            r#"INSERT INTO clients_x509 (id, name, expires, api_key, enabled, group_id, enc_key_id, key_alg,
            common_name, country, locality, organizational_unit, organization, state_or_province,
            alt_names_dns, alt_names_ip, key_usage, key_usage_ext, valid_hours, email)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)"#,
            uuid,
            client.name,
            expires,
            api_key_enc,
            client.enabled,
            group_id,
            enc_key_id,
            client.key_alg.as_str(),
            client.common_name,
            client.country,
            client.locality,
            client.organizational_unit,
            client.organization,
            client.state_or_province,
            dns,
            ip,
            key_usage,
            key_usage_ext,
            client.valid_hours,
            client.email
        )
            .execute(Db::conn())
        .await?;

        // a second query instead of insert return to be able to switch to sqlite easily too
        let res = query_as!(Self, "SELECT * FROM clients_x509 WHERE id = $1", uuid)
            .fetch_one(Db::conn())
            .await?;

        Ok(res)
    }

    pub async fn delete(uuid: &Uuid) -> Result<(), ErrorResponse> {
        // Delete the client itself
        query!("DELETE FROM clients_x509 WHERE id = $1", uuid)
            .execute(Db::conn())
            .await?;

        // // Delete all saved certificates
        // query!("delete from certs where client = $1", uuid)
        //     .execute(&*db)
        //     .await?;

        Ok(())
    }

    pub async fn update(uuid: &Uuid, client: ClientX509Request) -> Result<Self, ErrorResponse> {
        let expires = ClientX509Entity::expires_from_req(client.expires)?;
        let dns = vec_to_csv(&client.alt_names_dns);
        let ip = vec_to_csv(&client.alt_names_ip);
        let key_usage: Vec<u8> = client.key_usage.iter().map(|u| u.value()).collect();
        let key_usage_ext: Vec<u8> = client.key_usage_ext.iter().map(|u| u.value()).collect();

        query!(
            r#"UPDATE clients_x509
            SET name = $1, expires = $2, enabled = $3, group_id = $4, key_alg = $5, common_name = $6, country = $7,
            locality = $8, organizational_unit = $9, organization = $10, state_or_province = $11, alt_names_dns = $12,
            alt_names_ip = $13, key_usage = $14, key_usage_ext = $15, valid_hours = $16, email = $17
            WHERE id = $18"#,
            client.name,
            expires,
            client.enabled,
            client.group_id,
            client.key_alg.as_str(),
            client.common_name,
            client.country,
            client.locality,
            client.organizational_unit,
            client.organization,
            client.state_or_province,
            dns,
            ip,
            key_usage,
            key_usage_ext,
            client.valid_hours,
            client.email,
            uuid,
        )
            .execute(Db::conn())
            .await?;

        // a second query instead of insert return to be able to switch to sqlite easily too
        let res = query_as!(Self, "SELECT * FROM clients_x509 WHERE id = $1", uuid)
            .fetch_one(Db::conn())
            .await?;

        Ok(res)
    }

    pub async fn find(uuid: &Uuid) -> Result<Self, ErrorResponse> {
        query_as!(Self, "SELECT * FROM clients_x509 WHERE id = $1", uuid)
            .fetch_one(Db::conn())
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn find_all() -> Result<Vec<Self>, ErrorResponse> {
        query_as!(Self, "SELECT * FROM clients_x509")
            .fetch_all(Db::conn())
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn find_secret(uuid: &Uuid, enc_keys: &EncKeys) -> Result<String, ErrorResponse> {
        let slf = Self::find(uuid).await?;
        slf.decrypt_api_key(enc_keys).await
    }

    pub async fn find_with_group(group_id: &Uuid) -> Result<Vec<String>, ErrorResponse> {
        let res = query!("SELECT id FROM clients_x509 WHERE group_id = $1", group_id)
            .fetch_all(Db::conn())
            .await?
            .into_iter()
            .map(|rec| rec.id.to_string())
            .collect();
        Ok(res)
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
                "UPDATE clients_x509 SET api_key = $1, enc_key_id = $2 WHERE id = $3",
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
            "UPDATE clients_x509 SET api_key = $1, enc_key_id = $2 WHERE id = $3",
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
            "UPDATE clients_x509 SET latest_cert = $1 WHERE id = $2",
            cert,
            client,
        )
        .execute(Db::conn())
        .await?;

        Ok(())
    }
}

impl ClientX509Entity {
    /// Creates a new x509 certificate for this client and saves the information in the DB
    pub async fn build_cert(
        &self,
        // state: AppStateExtract,
        ca: &CaCertX509Full,
        cert_format: CertFormat,
        // Optional password in case of CertFormat::PKCS12
        password: Option<&str>,
    ) -> Result<ClientX509EntityCert, ErrorResponse> {
        let mut params = CertificateParams::default();

        // let key_pair = gen_ed25519_key_pair()?;
        // params.alg = &rcgen::PKCS_ED25519;
        let key_pair = match X509KeyAlg::from_str(&self.key_alg) {
            X509KeyAlg::Rsa => {
                params.alg = &rcgen::PKCS_RSA_SHA256;
                gen_rsa_key_pair(2048)?
            }
            X509KeyAlg::Ecdsa => {
                params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
                gen_ecdsa_key_pair()?
            }
            X509KeyAlg::Ed25519 => {
                params.alg = &rcgen::PKCS_ED25519;
                gen_ed25519_key_pair()?
            }
        };
        params.key_pair = Some(key_pair);

        let mut alt_names = vec![];
        for name in csv_to_vec(&self.alt_names_dns) {
            if !name.is_empty() {
                alt_names.push(SanType::DnsName(name));
            }
        }
        for ip in csv_to_vec(&self.alt_names_ip) {
            if !ip.is_empty() {
                if let Ok(ip) = IpAddr::from_str(&ip) {
                    alt_names.push(SanType::IpAddress(ip));
                } else {
                    error!("Error serializing IP alt name for client {}", self.id);
                    debug!("ip: {}", ip);
                }
            }
        }
        params.subject_alt_names = alt_names;

        let mut sub = DistinguishedName::new();
        sub.push(DnType::CommonName, &self.common_name);
        if let Some(country) = self.country.as_ref() {
            sub.push(DnType::CountryName, country);
        }
        if let Some(loc) = self.locality.as_ref() {
            sub.push(DnType::LocalityName, loc);
        }
        if let Some(ou) = self.organizational_unit.as_ref() {
            sub.push(DnType::OrganizationalUnitName, ou);
        }
        if let Some(org) = self.organization.as_ref() {
            sub.push(DnType::OrganizationName, org);
        }
        if let Some(st) = self.state_or_province.as_ref() {
            sub.push(DnType::StateOrProvinceName, st);
        }
        params.distinguished_name = sub;

        params.is_ca = IsCa::ExplicitNoCa;

        let mut key_usages = vec![];
        if let Some(mut bytes) = self.key_usage.clone() {
            for b in bytes.drain(..) {
                let u = X509KeyUsages::from_value(b);
                key_usages.push(KeyUsagePurpose::from(u));
            }
        }
        params.key_usages = key_usages;

        let mut key_usage_ext = vec![];
        if let Some(mut bytes) = self.key_usage_ext.clone() {
            for b in bytes.drain(..) {
                let u = X509KeyUsagesExt::from_value(b);
                key_usage_ext.push(ExtendedKeyUsagePurpose::from(u));
            }
        };
        params.extended_key_usages = key_usage_ext;

        params.name_constraints = None;
        params.custom_extensions = vec![];
        params.use_authority_key_identifier_extension = true;
        params.key_identifier_method = KeyIdMethod::Sha256;

        // generate a certificate without data to get a serial from the DB
        let entity = CertX509Entity::from(self);
        let mut cert_entity = entity.insert().await?;
        assert!(cert_entity.serial > 0);
        params.serial_number = Some((cert_entity.serial as u64).into());
        params.not_before = OffsetDateTime::now_utc().sub(time::Duration::minutes(10));
        params.not_after = cert_entity.expires;

        let cert = Certificate::from_params(params)?;

        let (cert_der, cert_pem, cert_chain) = {
            // let signing_cert = &state.read().await.nioca_signing_cert;
            let signing_cert = ca.signing_cert()?;
            // let cert_der = cert.serialize_der_with_signer(signing_cert)?;
            let cert_pem = cert
                .serialize_pem_with_signer(&signing_cert)?
                // For some reason, this is getting created with CRLF
                .replace("\r\n", "\n");
            let cert_der = pem_to_der(&cert_pem).unwrap().to_vec();

            // let ca_chain = &state.read().await.ca_chain_pem;
            let cert_chain = format!("{}{}", cert_pem, ca.ca_chain_pem);
            (cert_der, cert_pem, cert_chain)
        };

        cert_entity.data = cert_der.clone();
        cert_entity.update_data().await?;
        ClientX509Entity::set_last_cert(
            cert_entity.client_id.as_ref().unwrap(),
            cert_entity.serial,
        )
        .await?;

        match cert_format {
            CertFormat::Pem => {
                let cert_fingerprint = fingerprint(cert_pem.as_bytes());
                let key = cert.serialize_private_key_pem();

                info!(
                    "New certificate signed for ClientX509Entity: {} with format {:?} and  fingerprint {}",
                    self.id, cert_format, cert_fingerprint
                );

                let resp = CertX509Response {
                    cert: cert_pem,
                    cert_fingerprint,
                    cert_chain,
                    key,
                    cert_format,
                    not_after: cert_entity.expires.unix_timestamp(),
                };

                Ok(ClientX509EntityCert::Pem(resp))
            }

            CertFormat::Der => {
                let key = b64_encode(&cert.serialize_private_key_der());
                let cert = b64_encode(&cert_der);
                let cert_fingerprint = fingerprint(cert_der.as_bytes());

                info!(
                    "New certificate signed for ClientX509Entity: {} with format {:?} and  fingerprint {}",
                    self.id, cert_format, cert_fingerprint
                );

                let resp = CertX509Response {
                    cert,
                    cert_fingerprint,
                    cert_chain,
                    key,
                    cert_format,
                    not_after: cert_entity.expires.unix_timestamp(),
                };

                Ok(ClientX509EntityCert::Der(resp))
            }

            CertFormat::PKCS12 => {
                let key = cert.serialize_private_key_der();
                let cert_fingerprint = fingerprint(cert_der.as_bytes());

                info!(
                    "New certificate signed for ClientX509Entity: {} with format {:?} and  fingerprint {}",
                    self.id, cert_format, cert_fingerprint
                );

                let password = if let Some(p) = password { p } else { "" };

                // let lock = state.read().await;
                // let root_der = lock.root_cert.cert_der.as_ref();
                // let nioca_der = lock.nioca_cert.cert_der.as_ref();
                let pfx = match PFX::new_with_cas(
                    &cert_der,
                    &key,
                    &[ca.root.cert_der.as_ref(), ca.intermediate.cert_der.as_ref()],
                    // &[root_der, nioca_der],
                    password,
                    &self.name,
                ) {
                    Some(pfx) => pfx,
                    None => {
                        return Err(ErrorResponse::new(
                            ErrorResponseType::Internal,
                            "Cannot build PKCS12 from Certificate".to_string(),
                        ))
                    }
                };

                Ok(ClientX509EntityCert::PKCS12(pfx.to_der()))
            }
        }
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
        state: AppStateExtract,
        api_key: &str,
    ) -> Result<Uuid, ErrorResponse> {
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
        let ca_id = group.ca_x509.ok_or_else(|| {
            ErrorResponse::new(
                ErrorResponseType::Internal,
                "This groups has no linked CA".to_string(),
            )
        })?;

        let enc_keys = state.read().await.enc_keys.clone();
        let client_key = self.decrypt_api_key(&enc_keys).await?;

        if api_key != client_key {
            return Err(ErrorResponse::new(
                ErrorResponseType::Unauthorized,
                "Bad Credentials".to_string(),
            ));
        }

        Ok(ca_id)
    }
}

#[derive(Debug)]
pub enum ClientX509EntityCert {
    Pem(CertX509Response),
    Der(CertX509Response),
    PKCS12(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    // json converts the \n LF to \r\n - ensure they are converted back correctly
    #[tokio::test]
    async fn test_json_lf() {
        let cert = "-----BEGIN CERTIFICATE-----\nMIICozCCAiqgAwIBAgIBBDAKBggqhkjOPQQDAzA2MRswGQYDVQQDDBJOaW9jYSBJ\nbnRlcm1lZGlhdGUxFzAVBgNVBAoMDk5ldElULVNlcnZpY2VzMB4XDTIzMDIxNDA3\nMjEzOVoXDTIzMDIxNzA3MzEzOVowgYcxGzAZBgNVBAMMEm5pb2NhLmxvY2FsaG9z\ndC5kZTELMAkGA1UEBgwCREUxEzARBgNVBAcMCkR1c3NlbGRvcmYxHzAdBgNVBAsM\nFk5ldElUIFNlcnZpY2VzIC0gTWV0ZW8xFzAVBgNVBAoMDk5ldElUIFNlcnZpY2Vz\nMQwwCgYDVQQIDANOUlcwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQpflCelDDvpG8D\n0ZzkaSyTnBwBL3e6uyEH40PkhkB0S+RRL1VKBoyNaQd9OiUh/sE62PGW8PKd9eSr\nqDRPNkSbdqPvELjHPENYkDm75IJYNtQ6JbysORWXTu6jM/DwnhOjgbkwgbYwHwYD\nVR0jBBgwFoAUEulZwplTBzEOv40F+38ozkbxoZMwNAYDVR0RBC0wK4ISbmlvY2Eu\nbG9jYWxob3N0LmRlgg9jYS5sb2NhbGhvc3QuZGWHBH8AAAEwDgYDVR0PAQH/BAQD\nAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAdBgNVHQ4EFgQULww6\n+DwOwE1U0HxSX9Jn824JjKYwDwYDVR0TAQH/BAUwAwEBADAKBggqhkjOPQQDAwNn\nADBkAjA5Fx52qd07PrAS+FL/to5jydQcMJR17GJRJDt9zOS9Uso/rahJBYFt/3Xm\nPalwTD8CMCg5T7v/TX8w/E69Tyt/GgPAl+v4viSDtPLEPmClTgpXtc7MTbApu2C1\n+EkAOdtEMQ==\n-----END CERTIFICATE-----";
        let cert_fingerprint = fingerprint(cert.as_bytes());

        let resp = CertX509Response {
            cert: cert.to_string(),
            cert_fingerprint,
            cert_chain: String::default(),
            key: String::default(),
            cert_format: CertFormat::Pem,
            not_after: OffsetDateTime::now_utc().unix_timestamp(),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let from_json = serde_json::from_str::<CertX509Response>(&json).unwrap();

        assert_eq!(cert, from_json.cert);
    }
}

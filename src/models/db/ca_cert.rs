// use crate::certificates::encryption::decrypt;
// use crate::config::DbPool;
// use crate::models::api::error_response::ErrorResponse;
// use sqlx::query_as;
// use time::OffsetDateTime;
//
// #[derive(Debug, Clone, Default)]
// pub struct CaCertsRow {
//     pub id: String,
//     pub expires: Option<OffsetDateTime>,
//     pub data: String,
// }
//
// impl CaCertsRow {
//     // pub async fn find_all(db: DbPool) -> Result<Vec<Self>, ErrorResponse> {
//     //     query_as!(Self, "select * from ca_certs")
//     //         .fetch_all(&db)
//     //         .await
//     //         .map_err(ErrorResponse::from)
//     // }
//
//     pub async fn find_by_id(db: &DbPool, id: &str) -> Result<Self, ErrorResponse> {
//         query_as!(Self, "select * from ca_certs where id = $1", id)
//             .fetch_one(db)
//             .await
//             .map_err(ErrorResponse::from)
//     }
// }
//
// #[derive(Debug, Clone)]
// pub struct CaCertRoot {
//     pub expires: OffsetDateTime,
//     pub cert_pem: String,
// }
//
// impl CaCertRoot {
//     pub async fn find(db: &DbPool) -> Result<CaCertRoot, ErrorResponse> {
//         let cert = CaCertsRow::find_by_id(db, "root_cert").await?;
//
//         Ok(CaCertRoot {
//             expires: cert.expires.unwrap(),
//             cert_pem: cert.data,
//         })
//     }
// }
//
// #[derive(Debug, Clone)]
// pub struct CaCertNioca {
//     pub expires: OffsetDateTime,
//     pub cert_pem: String,
//     pub key: Vec<u8>,
// }
//
// impl CaCertNioca {
//     pub async fn find(db: &DbPool, enc_key: &[u8]) -> Result<CaCertNioca, ErrorResponse> {
//         let cert = CaCertsRow::find_by_id(db, "nioca_cert").await?;
//         let key = CaCertsRow::find_by_id(db, "nioca_key").await?;
//
//         let kex_decodeded = hex::decode(key.data).expect("Decoding Cert Key from HEX");
//         let dec = decrypt(kex_decodeded.as_slice(), enc_key)?;
//         Ok(CaCertNioca {
//             expires: cert.expires.unwrap(),
//             cert_pem: cert.data,
//             key: dec,
//         })
//     }
// }

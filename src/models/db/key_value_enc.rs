use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Generic Key/Value/EncKey data type used in various places
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyValueEncEntity {
    pub key: String,
    pub enc_key_id: Uuid,
    pub value: Vec<u8>,
}

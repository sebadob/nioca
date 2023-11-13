use crate::config::{AppState, AppStateSealed};

pub mod ca;
pub mod clients_ssh;
pub mod clients_x509;
pub mod groups;
pub mod oidc;
pub mod sealed;
pub mod unsealed;
pub mod users;

pub type AppStateExtract = axum::extract::State<AppState>;
pub type AppStateSealedExtract = axum::extract::State<AppStateSealed>;

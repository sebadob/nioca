use crate::models::db::session::SessionEntity;
use std::time::Duration;
use tokio::time;
use tracing::{debug, error};

/// Cleans up expired sessions from the database
pub async fn sessions_cleanup() {
    let mut interval = time::interval(Duration::from_secs(3600));

    loop {
        interval.tick().await;
        debug!("Running sessions_cleanup scheduler");

        if let Err(err) = SessionEntity::delete_expired().await {
            error!("sessions_cleanup scheduler error: {:?}", err);
        }
    }
}

use crate::config::AppState;
use crate::constants::UNSEAL_RATE_LIMIT;
use crate::service::sealed::push_shard_to_remotes;
use std::env;
use std::time::Duration;
use tokio::time;
use tracing::{debug, error, info};

/// Creates a backup of the data store
pub async fn auto_unseal_task(state: AppState) {
    let sec_res = env::var("INTERVAL_AUTO_UNSEAL");
    if sec_res.is_err() {
        info!("Auto-Unsealing of remote nodes is disabled");
        return;
    }

    let sec = sec_res
        .unwrap()
        .parse::<u64>()
        .expect("Cannot parse INTERVAL_AUTO_UNSEAL to u46");
    let mut interval = time::interval(Duration::from_secs(sec));
    let rate_limit = Duration::from_secs(*UNSEAL_RATE_LIMIT as u64);

    let shard_1 = state.read().await.enc_keys.master_shard_1.clone();
    let shard_2 = state.read().await.enc_keys.master_shard_2.clone();
    let ca_chain = state.read().await.ca_chain_pem.clone();

    debug!("Running auto_unseal_task scheduler");

    loop {
        interval.tick().await;

        // try push first key
        if let Some(key) = &shard_1 {
            if let Err(err) = push_shard_to_remotes(key.clone(), ca_chain.as_bytes()).await {
                error!("{:?}", err);
            }
        }

        // sleep for the rate limiter
        time::sleep(rate_limit).await;
        // small security margin
        time::sleep(Duration::from_millis(100)).await;

        // try push the second key
        if let Some(key) = &shard_2 {
            if let Err(err) = push_shard_to_remotes(key.clone(), ca_chain.as_bytes()).await {
                error!("{:?}", err);
            }
        }
    }
}

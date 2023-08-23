use crate::config::AppState;
use crate::schedulers::remote_auto_unseal::auto_unseal_task;
use crate::schedulers::sessions::sessions_cleanup;
use std::thread;
use tracing::debug;

mod remote_auto_unseal;
mod sessions;

pub async fn scheduler_main(state: AppState) {
    debug!("Schedulers started on {:?}", thread::current().id());

    tokio::spawn(sessions_cleanup());
    tokio::spawn(auto_unseal_task(state));
}

// /// sleeps until the next scheduled event
// async fn sleep_schedule_next(schedule: &cron::Schedule) {
//     let next = schedule.upcoming(chrono::Local).next().unwrap();
//     let until = next.signed_duration_since(chrono::Local::now());
//     // we are adding a future date here --> safe to cast from i64 to u64
//     time::sleep(Duration::from_secs(until.num_seconds() as u64)).await;
// }

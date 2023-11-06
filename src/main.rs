// Copyright 2023 Sebastian Dobe <sebastiandobe@mailbox.org>

extern crate core;

use crate::certificates::ssh::bootstrap::bootstrap_ssh;
use crate::certificates::x509::bootstrap::bootstrap_x509;
use crate::cli::Cli;
use crate::logging::setup_logging;
use crate::server::run_server;
use clap::Parser;

/// Encryption and Signing
mod certificates;
/// CLI arguments parser
mod cli;
/// Application Config
mod config;
/// Application wide constants
mod constants;
/// Logging modules
mod logging;
/// Models / Structs used in the application
mod models;
/// OIDC SSO module
mod oidc;
/// API routes
mod routes;
/// Schedulers and cron jobs
mod schedulers;
/// The Nioca Server
mod server;
/// Business Logic Layer
mod service;
/// Utilities and Helpers
mod util;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let level = setup_logging();

    match Cli::parse() {
        Cli::Server => run_server(level.as_str()).await,
        Cli::Ssh(opt) => bootstrap_ssh(*opt).await,
        Cli::X509(opt) => bootstrap_x509(*opt).await,
    }
}

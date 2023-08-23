// Nioca - X509 and SSH Certificate Authority
// Copyright (C) 2023 Sebastian Dobe <sebastiandobe@mailbox.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

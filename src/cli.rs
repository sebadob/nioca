use crate::certificates::{SshKeyAlg, X509KeyAlg, X509KeyUsages, X509KeyUsagesExt};
use clap::builder::OsStr;
use clap::Parser;
use std::net::IpAddr;

/// Nioca CA server and command line utility
#[derive(Debug, PartialEq, Parser)]
#[command(author, version)]
pub enum Cli {
    /// Starts the server
    Server,
    Ssh(Box<SshOptions>),
    X509(Box<X509CliOptions>),
}

/// Issue X509 Certificates or bootstrap a full CA with Root / Intermediate / EndEntity certificates.
#[derive(Debug, Clone, PartialEq, Parser)]
#[command(author, version)]
pub struct X509CliOptions {
    /// The alternative DNS Names for the end entity certificate
    #[clap(long = "alt-name-dns")]
    pub alt_name_dns: Vec<String>,

    /// The alternative IpAddresses for the end entity certificate
    #[clap(long = "alt-name-ip")]
    pub alt_name_ip: Vec<IpAddr>,

    /// The alternative Rfc822Names for the end entity certificate
    #[clap(long = "alt-name-rfc")]
    pub alt_name_rfc: Vec<String>,

    /// The alternative URI's for the end entity certificate
    #[clap(long = "alt-name-uri")]
    pub alt_name_uri: Vec<String>,

    /// Cleanup any possibly existing data and create a fresh bootstrapped CA
    #[clap(short, long, default_value = OsStr::from("false"))]
    pub clean: bool,

    /// The issuer name of the CA
    #[arg(short, long, default_value = "Nioca CA")]
    pub issuer: String,

    /// The CommonName(CN) for the subject
    #[clap(long = "cn", default_value = "Nioca")]
    pub common_name: String,

    /// The Country(C) for the subject
    #[clap(long = "c")]
    pub country: Option<String>,

    /// The Locality(L) for the subject
    #[clap(long = "l")]
    pub locality: Option<String>,

    /// The OrganizationalUnitName(OU) for the subject
    #[clap(long = "ou")]
    pub organizational_unit: Option<String>,

    /// The OrganizationName(O) for the subject.
    #[clap(long = "o")]
    pub organization: Option<String>,

    /// The StateOrProvinceName(ST) for the subject
    #[clap(long = "st")]
    pub state_province_name: Option<String>,

    /// The Key algorithm to use
    #[clap(short = 'a', long = "alg", value_enum, default_value_t = X509KeyAlg::Ecdsa)]
    pub key_alg: X509KeyAlg,

    /// The key usages to allow for the end entity certificate
    #[clap(short = 'u', long = "usages", value_enum)]
    pub key_usage: Vec<X509KeyUsages>,

    /// The extended key usages to allow for the end entity certificate
    #[clap(short = 'e', long = "usages-ext", value_enum)]
    pub key_usage_ext: Vec<X509KeyUsagesExt>,

    /// The permitted DNS name constraints certificates can be issued for.
    /// If any 'name_constraint_dns' is set, everything else is excluded automatically.
    #[clap(long = "constraint-dns")]
    pub name_constraint_dns: Vec<String>,

    /// The permitted IP name constraints certificates can be issued for.
    /// If any 'name_constraint_ip' is set, everything else is excluded automatically.
    /// Format: 192.168.100.0/24
    #[clap(long = "constraint-ip")]
    pub name_constraint_ip: Vec<String>,

    /// The output directory
    #[clap(short = 'o', long = "out-dir", default_value = "./")]
    pub out_dir: String,

    /// Each bootstrap stage can be executed individually to have different subjects.
    /// If 'full' is chosen, the given arguments for the subject will be used in all certificates.
    #[clap(short = 's', long = "stage", value_enum)]
    pub stage: X509Stage,

    /// Validity in days for the end user certificate
    #[arg(long, default_value = OsStr::from("375"))]
    pub valid: u32,

    /// Validity in days for the intermediate certificate
    #[arg(long, default_value = OsStr::from("3650"))]
    pub valid_intermediate: u32,

    /// Validity in days for the root certificate
    #[arg(long, default_value = OsStr::from("10950"))]
    pub valid_root: u32,
}

#[derive(Debug, Clone, PartialEq, clap::ValueEnum)]
pub enum X509Stage {
    Full,
    Root,
    Intermediate,
    EndEntity,
}

/// Issue SSH Certificates or bootstrap a full CA.
#[derive(Debug, Clone, PartialEq, Parser)]
#[command(author, version)]
pub struct SshOptions {
    /// Cleanup any possibly existing data and create a fresh bootstrapped CA
    #[clap(short, long, default_value = OsStr::from("false"))]
    pub clean: bool,

    // Extensions
    /// Disables X11-forwarding for user certificates
    #[clap(long, default_value = OsStr::from("false"))]
    pub disable_x11_forwarding: bool,

    /// Disables agent-forwarding for user certificates
    #[clap(long, default_value = OsStr::from("false"))]
    pub disable_agent_forwarding: bool,

    /// Disables port-forwarding for user certificates
    #[clap(long, default_value = OsStr::from("false"))]
    pub disable_port_forwarding: bool,

    /// Disables pty for user certificates
    #[clap(long, default_value = OsStr::from("false"))]
    pub disable_pty: bool,

    /// Disables user-rc for user certificates
    #[clap(long, default_value = OsStr::from("false"))]
    pub disable_user_rc: bool,

    // Critical Options
    /// The command to force for user certificates upon login
    #[clap(long)]
    pub force_command: Option<String>,

    /// An allowed source IP the user can connect from. Format: CIDR, e.g. 192.168.1.0/24
    #[clap(long)]
    pub source_address: Option<Vec<String>>,

    /// The Key algorithm to use
    #[clap(short = 'a', long = "alg", value_enum, default_value_t = SshKeyAlg::Ed25519)]
    pub key_alg: SshKeyAlg,

    /// The output directory
    #[clap(short = 'o', long = "out-dir", default_value = "./")]
    pub out_dir: String,

    /// A valid principal. For Host certificates the hostnames it should be valid for. For User
    /// certificates the valid usernames the client is allowed to log in with. Multiple principals
    /// can be added.
    #[clap(short = 'p', long = "principal")]
    pub principal: Vec<String>,

    /// Each bootstrap stage can be executed individually to have different subjects.
    #[clap(short = 's', long = "stage", value_enum)]
    pub stage: SshStage,

    /// Validity in minutes
    #[arg(short = 'v', long = "valid", default_value = OsStr::from("43200"))]
    pub valid: u64,
}

impl SshOptions {
    pub(crate) fn get_alg(&self) -> ssh_key::Algorithm {
        self.key_alg.as_alg()
    }
}

#[derive(Debug, Clone, PartialEq, clap::ValueEnum)]
pub enum SshStage {
    Root,
    Host,
    User,
}

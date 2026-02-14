use std::{
    fmt::Debug,
    fs, io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    process,
};

use anyhow::{Context, Error};
use clap::{ArgMatches, CommandFactory, Parser, ValueEnum, parser::ValueSource};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum PinPromptKind {
    Tty,
    #[cfg(feature = "ui-gtk")]
    Ui,
}

impl Default for PinPromptKind {
    #[cfg(not(feature = "ui-gtk"))]
    fn default() -> PinPromptKind {
        PinPromptKind::Tty
    }

    #[cfg(feature = "ui-gtk")]
    fn default() -> PinPromptKind {
        PinPromptKind::Ui
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ConfigSlice {
    pub endpoint: Option<String>,
    pub nssdb_path: Option<String>,
    pub log: Option<String>,
    pub max_connections: Option<u8>,
    pub pin_prompt: Option<PinPromptKind>,
    pub allow_soft_tokens: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub endpoint: String,
    pub nssdb_path: String,
    pub log: String,
    pub max_connections: u8,
    pub pin_prompt: PinPromptKind,
    pub allow_soft_tokens: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: default_localhost_addr(),
            nssdb_path: default_nssdb_path(),
            log: String::from("info"),
            max_connections: 2,
            pin_prompt: PinPromptKind::default(),
            allow_soft_tokens: false,
        }
    }
}

impl Config {
    fn merge(self, slice: ConfigSlice) -> Config {
        Config {
            endpoint: slice.endpoint.unwrap_or(self.endpoint),
            nssdb_path: slice.nssdb_path.unwrap_or(self.nssdb_path),
            log: slice.log.unwrap_or(self.log),
            max_connections: slice.max_connections.unwrap_or(self.max_connections),
            pin_prompt: slice.pin_prompt.unwrap_or(self.pin_prompt),
            allow_soft_tokens: slice.allow_soft_tokens.unwrap_or(self.allow_soft_tokens),
        }
    }
}

// handle dual-stack case, fall back to IPv4
fn default_localhost_addr() -> String {
    let fallback_v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 17165));
    "localhost:17165"
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .unwrap_or(fallback_v4)
        .to_string()
}

fn default_nssdb_path() -> String {
    dirs::home_dir()
        .map(|p| p.join(".pki/nssdb"))
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

fn default_config_path() -> String {
    dirs::config_dir()
        .map(|p| p.join("epoxy.toml"))
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

/// SmartBox-compatible open source tool for signing ePorezi tax forms
#[derive(Clone, Debug, Parser, Serialize)]
#[command(version, about)]
pub struct ClapConfig {
    /// Path to an optional config file
    #[serde(skip)]
    #[arg(short = 'c', long, default_value_t = default_config_path())]
    config_path: String,

    /// IP:Port or `tokio-listener` address to use. Ports supported by ePorezi: 17165, 20806, 65097
    #[arg(short = 'e', long, default_value_t = Config::default().endpoint)]
    endpoint: String,

    /// Path to an NSS database
    #[arg(short = 'd', long, default_value_t = Config::default().nssdb_path)]
    nssdb_path: String,

    /// Logging directives (see https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives)
    #[arg(short = 'l', long, default_value_t = Config::default().log)]
    log: String,

    /// Max accepted connections
    #[arg(long, default_value_t = Config::default().max_connections)]
    max_connections: u8,

    /// PIN prompt method
    #[arg(long, value_enum, default_value_t = Config::default().pin_prompt)]
    pin_prompt: PinPromptKind,

    #[arg(long, default_value_t = Config::default().allow_soft_tokens)]
    /// Include certificates from software PKCS#11 tokens for testing
    allow_soft_tokens: bool,

    /// Print default config
    #[serde(skip)]
    #[arg(long, default_value_t = false)]
    print_config: bool,
}

fn get_cli_value<T>(matches: &ArgMatches, name: &'static str) -> Option<T>
where
    T: Clone + Send + Sync + 'static,
{
    if matches.value_source(name) != Some(ValueSource::CommandLine) {
        return None;
    }
    matches.get_one(name).cloned()
}

pub fn get_config() -> Result<Config, anyhow::Error> {
    let default_config = Config::default();

    let ClapConfig {
        config_path,
        print_config,
        ..
    } = ClapConfig::parse();

    if print_config {
        println!("{}", toml::to_string_pretty(&default_config)?);
        process::exit(0);
    }

    let toml_slice = match fs::read(config_path) {
        Ok(bytes) => toml::from_slice(&bytes).context("invalid config file"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ConfigSlice::default()),
        Err(e) => Err(Error::new(e).context("failed to read config file")),
    }?;

    let matches = ClapConfig::command().get_matches();
    let cli_slice = ConfigSlice {
        endpoint: get_cli_value(&matches, "endpoint"),
        nssdb_path: get_cli_value(&matches, "nssdb_path"),
        log: get_cli_value(&matches, "log"),
        max_connections: get_cli_value(&matches, "max_connections"),
        pin_prompt: get_cli_value(&matches, "pin_prompt"),
        allow_soft_tokens: get_cli_value(&matches, "allow_soft_tokens"),
    };

    let config = default_config.merge(toml_slice).merge(cli_slice);

    Ok(config)
}

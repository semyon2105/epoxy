mod clap_value;

use std::{
    fmt::Debug,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    process,
};

use anyhow::Context;
use clap::{Parser, ValueEnum};
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

use crate::config::clap_value::ClapValue;

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
    #[clap(short = 'c', long, default_value_t = default_config_path())]
    config_path: String,

    /// IP:Port or `tokio-listener` address to use. Ports supported by ePorezi: 17165, 20806, 65097
    #[clap(short = 'e', long, default_value_t = ClapValue::default(Config::default().endpoint))]
    endpoint: ClapValue<String>,

    /// Path to an NSS database
    #[clap(short = 'd', long, default_value_t = ClapValue::default(Config::default().nssdb_path))]
    nssdb_path: ClapValue<String>,

    /// Logging directives (see https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives)
    #[clap(short = 'l', long, default_value_t = ClapValue::default(Config::default().log))]
    log: ClapValue<String>,

    /// Max accepted connections
    #[clap(long, default_value_t = ClapValue::default(Config::default().max_connections))]
    max_connections: ClapValue<u8>,

    /// PIN prompt method
    #[clap(long, value_enum, default_value_t = ClapValue::default(Config::default().pin_prompt))]
    pin_prompt: ClapValue<PinPromptKind>,

    #[clap(long, default_value_t = ClapValue::default(Config::default().allow_soft_tokens))]
    /// Include certificates from software PKCS#11 tokens for testing
    allow_soft_tokens: ClapValue<bool>,

    /// Print default config
    #[serde(skip)]
    #[clap(long, default_value_t = false)]
    print_config: bool,
}

pub fn get_config() -> Result<Config, anyhow::Error> {
    let clap_config = ClapConfig::parse();
    if clap_config.print_config {
        println!("{}", toml::to_string_pretty(&clap_config)?);
        process::exit(0);
    }

    let config_path = clap_config.config_path.clone();

    let builtin_defaults = Serialized::defaults(Config::default());
    let provided_args = Serialized::defaults(clap_config);
    let config_file = Toml::file(config_path);

    Figment::from(builtin_defaults)
        .merge(provided_args)
        .merge(config_file)
        .extract()
        .context("failed to extract config")
}

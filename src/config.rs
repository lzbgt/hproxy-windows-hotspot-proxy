use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

pub type ConfigResult<T> = Result<T, ConfigError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    pub hotspot: HotspotConfig,
    pub outbound_proxy: ProxyConfig,
    pub proxy_preflight: ProxyPreflightConfig,
    pub dns: DnsConfig,
    pub policy: TransparentPolicy,
    pub ports: LocalPorts,
}

impl AppConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        self.hotspot.validate()?;
        self.outbound_proxy.validate()?;
        self.proxy_preflight.validate()?;
        self.dns.validate()?;
        self.ports.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyPreflightConfig {
    pub enabled: bool,
    pub target: SocketAddr,
    pub timeout_ms: u64,
}

impl ProxyPreflightConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.target.port() == 0 {
            return Err(ConfigError::Invalid(
                "proxy preflight target port must be greater than 0".to_string(),
            ));
        }
        if self.timeout_ms == 0 {
            return Err(ConfigError::Invalid(
                "proxy preflight timeout must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    pub upstream: SocketAddr,
    pub timeout_ms: u64,
    pub mode: DnsMode,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream: SocketAddr::from(([1, 1, 1, 1], 53)),
            timeout_ms: 5_000,
            mode: DnsMode::Forward,
        }
    }
}

impl DnsConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.upstream.port() == 0 {
            return Err(ConfigError::Invalid(
                "DNS upstream port must be greater than 0".to_string(),
            ));
        }
        if self.timeout_ms == 0 {
            return Err(ConfigError::Invalid(
                "DNS timeout must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsMode {
    Forward,
    Gateway,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotspotConfig {
    pub ssid: String,
    pub password: String,
    pub band: HotspotBand,
}

impl HotspotConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        let ssid_len = self.ssid.as_bytes().len();
        if ssid_len == 0 || ssid_len > 32 {
            return Err(ConfigError::Invalid(
                "SSID must be between 1 and 32 bytes".to_string(),
            ));
        }

        let password_len = self.password.as_bytes().len();
        if !(8..=63).contains(&password_len) {
            return Err(ConfigError::Invalid(
                "hotspot password must be between 8 and 63 bytes".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HotspotBand {
    Auto,
    TwoGhz,
    FiveGhz,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub endpoint: Option<HostEndpoint>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls_skip_verify: bool,
}

impl ProxyConfig {
    pub fn direct() -> Self {
        Self {
            kind: ProxyKind::Direct,
            endpoint: None,
            username: None,
            password: None,
            tls_skip_verify: false,
        }
    }

    pub fn with_tls_skip_verify(mut self, tls_skip_verify: bool) -> Self {
        self.tls_skip_verify = tls_skip_verify;
        self
    }

    pub fn is_direct(&self) -> bool {
        self.kind == ProxyKind::Direct
    }

    pub fn validate(&self) -> ConfigResult<()> {
        match self.kind {
            ProxyKind::Direct => {
                if self.endpoint.is_some() {
                    return Err(ConfigError::Invalid(
                        "direct mode must not include a proxy endpoint".to_string(),
                    ));
                }
                if self.tls_skip_verify {
                    return Err(ConfigError::Invalid(
                        "direct mode cannot use TLS verification options".to_string(),
                    ));
                }
            }
            ProxyKind::Socks5 | ProxyKind::HttpConnect => {
                let endpoint = self.endpoint.as_ref().ok_or_else(|| {
                    ConfigError::Invalid("proxy endpoint is required".to_string())
                })?;
                endpoint.validate()?;
                if self.tls_skip_verify {
                    return Err(ConfigError::Invalid(
                        "TLS verification options only apply to https-proxy mode".to_string(),
                    ));
                }
            }
            ProxyKind::HttpsConnect => {
                let endpoint = self.endpoint.as_ref().ok_or_else(|| {
                    ConfigError::Invalid("proxy endpoint is required".to_string())
                })?;
                endpoint.validate()?;
            }
        }

        Ok(())
    }
}

impl FromStr for ProxyConfig {
    type Err = ConfigError;

    fn from_str(value: &str) -> ConfigResult<Self> {
        if value.eq_ignore_ascii_case("direct") {
            return Ok(Self::direct());
        }

        let url = Url::parse(value)
            .map_err(|err| ConfigError::Invalid(format!("invalid proxy URI: {err}")))?;

        let kind = match url.scheme() {
            "socks5" => ProxyKind::Socks5,
            "http" | "http-proxy" => ProxyKind::HttpConnect,
            "https" | "https-proxy" => ProxyKind::HttpsConnect,
            scheme => {
                return Err(ConfigError::Invalid(format!(
                    "unsupported proxy scheme '{scheme}'"
                )));
            }
        };

        let host = url
            .host_str()
            .ok_or_else(|| ConfigError::Invalid("proxy URI requires a host".to_string()))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| ConfigError::Invalid("proxy URI requires a port".to_string()))?;
        let tls_skip_verify = parse_tls_skip_verify(&url)?;

        let config = Self {
            kind,
            endpoint: Some(HostEndpoint { host, port }),
            username: (!url.username().is_empty()).then(|| url.username().to_string()),
            password: url.password().map(ToString::to_string),
            tls_skip_verify,
        };
        config.validate()?;
        Ok(config)
    }
}

fn parse_tls_skip_verify(url: &Url) -> ConfigResult<bool> {
    let mut enabled = false;
    for (key, value) in url.query_pairs() {
        if key != "tls_skip_verify" && key != "tls-insecure" && key != "insecure" {
            continue;
        }

        enabled = match value.as_ref() {
            "1" | "true" | "yes" => true,
            "0" | "false" | "no" => false,
            other => {
                return Err(ConfigError::Invalid(format!(
                    "invalid boolean value for {key}: {other}"
                )));
            }
        };
    }
    Ok(enabled)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyKind {
    Direct,
    Socks5,
    HttpConnect,
    HttpsConnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEndpoint {
    pub host: String,
    pub port: u16,
}

impl HostEndpoint {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.host.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "endpoint host must not be empty".to_string(),
            ));
        }
        if self.port == 0 {
            return Err(ConfigError::Invalid(
                "endpoint port must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

impl fmt::Display for HostEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentPolicy {
    pub tcp: TcpPolicy,
    pub dns: DnsPolicy,
    pub udp: UdpPolicy,
    pub block_quic_udp_443: bool,
    pub bypass_private_lan: bool,
    pub upstream_proxy_ip: Option<IpAddr>,
}

impl Default for TransparentPolicy {
    fn default() -> Self {
        Self {
            tcp: TcpPolicy::Proxy,
            dns: DnsPolicy::Proxy,
            udp: UdpPolicy::DnsNtpDirectElseDrop,
            block_quic_udp_443: true,
            bypass_private_lan: true,
            upstream_proxy_ip: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpPolicy {
    Proxy,
    Direct,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsPolicy {
    Proxy,
    Direct,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdpPolicy {
    DnsNtpDirectElseDrop,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPorts {
    pub transparent_tcp: u16,
    pub dns_proxy: u16,
}

impl LocalPorts {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.transparent_tcp == 0 || self.dns_proxy == 0 {
            return Err(ConfigError::Invalid(
                "local ports must be greater than 0".to_string(),
            ));
        }
        if self.transparent_tcp == self.dns_proxy {
            return Err(ConfigError::Invalid(
                "transparent TCP and DNS ports must differ".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_socks5_uri() {
        let proxy: ProxyConfig = "socks5://user:pass@127.0.0.1:1080".parse().unwrap();
        assert_eq!(proxy.kind, ProxyKind::Socks5);
        assert_eq!(proxy.endpoint.unwrap().port, 1080);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("pass"));
        assert!(!proxy.tls_skip_verify);
    }

    #[test]
    fn parses_https_proxy_tls_skip_verify() {
        let proxy: ProxyConfig = "https-proxy://127.0.0.1:8120?tls_skip_verify=true"
            .parse()
            .unwrap();
        assert_eq!(proxy.kind, ProxyKind::HttpsConnect);
        assert!(proxy.tls_skip_verify);
    }

    #[test]
    fn rejects_tls_skip_verify_for_socks5() {
        let err = "socks5://127.0.0.1:8120?tls_skip_verify=true"
            .parse::<ProxyConfig>()
            .unwrap_err();
        assert!(err.to_string().contains("https-proxy mode"));
    }

    #[test]
    fn rejects_short_hotspot_password() {
        let hotspot = HotspotConfig {
            ssid: "VirtualProxyAP".to_string(),
            password: "short".to_string(),
            band: HotspotBand::Auto,
        };

        assert!(hotspot.validate().is_err());
    }

    #[test]
    fn validates_dns_timeout() {
        let config = DnsConfig {
            upstream: "1.1.1.1:53".parse().unwrap(),
            timeout_ms: 0,
            mode: DnsMode::Forward,
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn validates_proxy_preflight_timeout() {
        let config = ProxyPreflightConfig {
            enabled: true,
            target: "1.1.1.1:443".parse().unwrap(),
            timeout_ms: 0,
        };

        assert!(config.validate().is_err());
    }
}

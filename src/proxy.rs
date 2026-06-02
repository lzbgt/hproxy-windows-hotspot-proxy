use std::{
    fmt,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use native_tls::TlsConnector as NativeTlsConnector;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tokio_native_tls::TlsConnector as TokioTlsConnector;
use tracing::{debug, info, warn};

use crate::{
    config::{HostEndpoint, ProxyConfig, ProxyKind},
    flow::{FlowKey, FlowTable, TransportProtocol},
};

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedProxyStream = Box<dyn ProxyStream>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub host: TargetHost,
    pub port: u16,
}

impl Destination {
    pub fn from_ip(ip: IpAddr, port: u16) -> Self {
        Self {
            host: TargetHost::Ip(ip),
            port,
        }
    }

    pub fn from_domain(domain: impl Into<String>, port: u16) -> Self {
        Self {
            host: TargetHost::Domain(domain.into()),
            port,
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetHost {
    Ip(IpAddr),
    Domain(String),
}

impl fmt::Display for TargetHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetHost::Ip(ip) => write!(f, "{ip}"),
            TargetHost::Domain(domain) => write!(f, "{domain}"),
        }
    }
}

#[async_trait]
pub trait TcpConnector: Send + Sync {
    async fn connect(&self, destination: Destination) -> Result<BoxedProxyStream>;
}

pub fn connector_from_config(config: &ProxyConfig) -> Result<Arc<dyn TcpConnector>> {
    match config.kind {
        ProxyKind::Direct => Ok(Arc::new(DirectConnector)),
        ProxyKind::Socks5 => Ok(Arc::new(Socks5Connector::new(config.clone())?)),
        ProxyKind::HttpConnect => Ok(Arc::new(HttpConnectConnector::new(config.clone(), false)?)),
        ProxyKind::HttpsConnect => Ok(Arc::new(HttpConnectConnector::new(config.clone(), true)?)),
    }
}

pub struct DirectConnector;

#[async_trait]
impl TcpConnector for DirectConnector {
    async fn connect(&self, destination: Destination) -> Result<BoxedProxyStream> {
        let stream = match &destination.host {
            TargetHost::Ip(ip) => TcpStream::connect((*ip, destination.port)).await,
            TargetHost::Domain(domain) => {
                TcpStream::connect((domain.as_str(), destination.port)).await
            }
        }
        .with_context(|| format!("connect direct to {destination}"))?;
        Ok(Box::new(stream))
    }
}

pub struct Socks5Connector {
    endpoint: HostEndpoint,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Connector {
    pub fn new(config: ProxyConfig) -> Result<Self> {
        Ok(Self {
            endpoint: config
                .endpoint
                .ok_or_else(|| anyhow!("SOCKS5 endpoint is required"))?,
            username: config.username,
            password: config.password,
        })
    }
}

#[async_trait]
impl TcpConnector for Socks5Connector {
    async fn connect(&self, destination: Destination) -> Result<BoxedProxyStream> {
        let mut stream = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
            .await
            .with_context(|| format!("connect to SOCKS5 proxy {}", self.endpoint))?;

        if self.username.is_some() || self.password.is_some() {
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }

        let mut method_reply = [0_u8; 2];
        stream.read_exact(&mut method_reply).await?;
        match method_reply {
            [0x05, 0x00] => {}
            [0x05, 0x02] => {
                let username = self.username.as_deref().unwrap_or("");
                let password = self.password.as_deref().unwrap_or("");
                if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                    bail!("SOCKS5 username/password is too long");
                }
                let mut auth = Vec::with_capacity(3 + username.len() + password.len());
                auth.push(0x01);
                auth.push(username.len() as u8);
                auth.extend_from_slice(username.as_bytes());
                auth.push(password.len() as u8);
                auth.extend_from_slice(password.as_bytes());
                stream.write_all(&auth).await?;

                let mut auth_reply = [0_u8; 2];
                stream.read_exact(&mut auth_reply).await?;
                if auth_reply != [0x01, 0x00] {
                    bail!("SOCKS5 username/password authentication failed");
                }
            }
            [0x05, 0xff] => bail!("SOCKS5 proxy rejected all authentication methods"),
            other => bail!("invalid SOCKS5 method reply: {other:?}"),
        }

        let mut request = vec![0x05, 0x01, 0x00];
        match &destination.host {
            TargetHost::Ip(IpAddr::V4(ip)) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            TargetHost::Ip(IpAddr::V6(ip)) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
            TargetHost::Domain(domain) => {
                if domain.len() > u8::MAX as usize {
                    bail!("SOCKS5 domain destination is too long: {domain}");
                }
                request.push(0x03);
                request.push(domain.len() as u8);
                request.extend_from_slice(domain.as_bytes());
            }
        }
        request.extend_from_slice(&destination.port.to_be_bytes());
        stream.write_all(&request).await?;

        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x05 || header[1] != 0x00 {
            bail!("SOCKS5 CONNECT failed with reply code {}", header[1]);
        }

        let addr_len = match header[3] {
            0x01 => 4,
            0x03 => {
                let mut len = [0_u8; 1];
                stream.read_exact(&mut len).await?;
                len[0] as usize
            }
            0x04 => 16,
            atyp => bail!("SOCKS5 proxy returned invalid address type {atyp}"),
        };
        let mut discard = vec![0_u8; addr_len + 2];
        stream.read_exact(&mut discard).await?;
        Ok(Box::new(stream))
    }
}

pub struct HttpConnectConnector {
    endpoint: HostEndpoint,
    use_tls: bool,
    tls_skip_verify: bool,
}

impl HttpConnectConnector {
    pub fn new(config: ProxyConfig, use_tls: bool) -> Result<Self> {
        Ok(Self {
            endpoint: config
                .endpoint
                .ok_or_else(|| anyhow!("HTTP CONNECT endpoint is required"))?,
            use_tls,
            tls_skip_verify: config.tls_skip_verify,
        })
    }
}

#[async_trait]
impl TcpConnector for HttpConnectConnector {
    async fn connect(&self, destination: Destination) -> Result<BoxedProxyStream> {
        let stream = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
            .await
            .with_context(|| format!("connect to CONNECT proxy {}", self.endpoint))?;

        if self.use_tls {
            let mut builder = NativeTlsConnector::builder();
            if self.tls_skip_verify {
                builder.danger_accept_invalid_certs(true);
                builder.danger_accept_invalid_hostnames(true);
            }
            let connector = TokioTlsConnector::from(
                builder
                    .build()
                    .context("build TLS connector for HTTPS proxy")?,
            );
            let mut tls_stream = connector
                .connect(self.endpoint.host.as_str(), stream)
                .await
                .with_context(|| format!("TLS handshake with HTTPS proxy {}", self.endpoint))?;
            send_connect_request(&mut tls_stream, &destination).await?;
            return Ok(Box::new(tls_stream));
        }

        let mut stream = stream;
        send_connect_request(&mut stream, &destination).await?;
        Ok(Box::new(stream))
    }
}

async fn send_connect_request<S>(stream: &mut S, destination: &Destination) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        destination.host, destination.port, destination.host, destination.port
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while response.len() < 8192 {
        stream.read_exact(&mut byte).await?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    if !response.ends_with(b"\r\n\r\n") {
        bail!("CONNECT proxy response headers exceeded 8192 bytes");
    }

    let text = String::from_utf8_lossy(&response);
    if !text.starts_with("HTTP/1.1 200") && !text.starts_with("HTTP/1.0 200") {
        bail!("CONNECT failed: {}", text.lines().next().unwrap_or(""));
    }

    Ok(())
}

pub struct TransparentTcpProxy {
    listener: TcpListener,
    flow_table: FlowTable,
    connector: Arc<dyn TcpConnector>,
}

static TCP_RELAY_DIAG_LINES: AtomicUsize = AtomicUsize::new(0);
const TCP_RELAY_DIAG_LIMIT: usize = 64;
const MAX_HTTP_REQUEST_HEAD_SIZE: usize = 16 * 1024;

impl TransparentTcpProxy {
    pub async fn bind(
        listen_port: u16,
        flow_table: FlowTable,
        connector: Arc<dyn TcpConnector>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", listen_port))
            .await
            .with_context(|| format!("bind transparent TCP proxy on port {listen_port}"))?;
        Ok(Self {
            listener,
            flow_table,
            connector,
        })
    }

    pub async fn run(self) -> Result<()> {
        let listen_addr = self.listener.local_addr()?;
        info!("transparent TCP proxy listening on {}", listen_addr);

        loop {
            let (client, peer) = self.listener.accept().await?;
            let flow_table = self.flow_table.clone();
            let connector = Arc::clone(&self.connector);
            tokio::spawn(async move {
                if let Err(err) =
                    relay_one(client, peer.ip(), peer.port(), flow_table, connector).await
                {
                    warn!("transparent TCP relay failed: {err:#}");
                }
            });
        }
    }
}

pub struct GatewayTcpProxy {
    listener: TcpListener,
    port: u16,
    connector: Arc<dyn TcpConnector>,
}

impl GatewayTcpProxy {
    pub async fn bind(listen_port: u16, connector: Arc<dyn TcpConnector>) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", listen_port))
            .await
            .with_context(|| format!("bind gateway TCP proxy on port {listen_port}"))?;
        Ok(Self {
            listener,
            port: listen_port,
            connector,
        })
    }

    pub async fn run(self) -> Result<()> {
        let listen_addr = self.listener.local_addr()?;
        info!("gateway TCP proxy listening on {}", listen_addr);

        loop {
            let (client, peer) = self.listener.accept().await?;
            let connector = Arc::clone(&self.connector);
            let port = self.port;
            tokio::spawn(async move {
                if let Err(err) = relay_gateway(client, port, connector).await {
                    warn!("gateway TCP relay from {peer} failed: {err:#}");
                }
            });
        }
    }
}

async fn relay_gateway(
    client: TcpStream,
    local_port: u16,
    connector: Arc<dyn TcpConnector>,
) -> Result<()> {
    match local_port {
        80 => relay_http_gateway(client, connector).await,
        443 => relay_tls_gateway(client, connector).await,
        other => bail!("unsupported gateway TCP listen port {other}; expected 80 or 443"),
    }
}

async fn relay_http_gateway(client: TcpStream, connector: Arc<dyn TcpConnector>) -> Result<()> {
    let mut client = client;
    let request = read_http_request_head(&mut client).await?;
    let header_end = find_http_header_end(&request)
        .ok_or_else(|| anyhow!("HTTP request header is incomplete"))?;
    let host = parse_http_host(&request[..header_end]).context("parse HTTP Host header")?;

    let destination = Destination::from_domain(host, 80);
    log_tcp_relay_diag(format_args!(
        "gateway http; connecting upstream {destination}"
    ));
    let mut upstream = connector.connect(destination).await?;
    upstream.write_all(&request).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn read_http_request_head(client: &mut TcpStream) -> Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024);
    loop {
        if request.len() >= MAX_HTTP_REQUEST_HEAD_SIZE {
            bail!("HTTP request headers exceeded {MAX_HTTP_REQUEST_HEAD_SIZE} bytes");
        }

        let before = request.len();
        request.reserve(1024);
        let read = client.read_buf(&mut request).await?;
        if read == 0 {
            bail!("client closed before sending complete HTTP request headers");
        }

        if find_http_header_end(&request[before.saturating_sub(3)..]).is_some()
            || find_http_header_end(&request).is_some()
        {
            return Ok(request);
        }
    }
}

fn find_http_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

async fn relay_tls_gateway(client: TcpStream, connector: Arc<dyn TcpConnector>) -> Result<()> {
    let mut client = BufReader::new(client);
    let mut client_hello = Vec::with_capacity(1024);
    let sni = read_tls_sni(&mut client, &mut client_hello).await?;

    let destination = Destination::from_domain(sni, 443);
    log_tcp_relay_diag(format_args!(
        "gateway tls; connecting upstream {destination}"
    ));
    let mut upstream = connector.connect(destination).await?;
    upstream.write_all(&client_hello).await?;
    let mut client = client.into_inner();
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

fn parse_http_host(request: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(request).context("HTTP headers are not UTF-8")?;
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            let host = value.trim();
            if host.is_empty() {
                bail!("HTTP Host header is empty");
            }
            return Ok(strip_host_port(host).to_string());
        }
    }
    bail!("HTTP Host header missing")
}

fn strip_host_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host
            .strip_prefix('[')
            .and_then(|value| value.split_once(']').map(|(inner, _)| inner))
            .unwrap_or(host);
    }
    host.split_once(':').map(|(name, _)| name).unwrap_or(host)
}

async fn read_tls_sni<R>(reader: &mut R, captured: &mut Vec<u8>) -> Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 5];
    reader.read_exact(&mut header).await?;
    captured.extend_from_slice(&header);

    if header[0] != 0x16 {
        bail!(
            "TLS gateway expected handshake record, got content type {}",
            header[0]
        );
    }
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len == 0 || record_len > 16 * 1024 {
        bail!("TLS ClientHello record length is invalid: {record_len}");
    }

    let mut body = vec![0_u8; record_len];
    reader.read_exact(&mut body).await?;
    captured.extend_from_slice(&body);
    parse_tls_sni_from_record(&body)
}

fn parse_tls_sni_from_record(body: &[u8]) -> Result<String> {
    if body.len() < 42 || body[0] != 0x01 {
        bail!("TLS record is not a ClientHello");
    }

    let handshake_len = read_u24(&body[1..4])?;
    if handshake_len + 4 > body.len() {
        bail!("TLS ClientHello length exceeds record");
    }

    let mut offset = 4 + 2 + 32;
    let session_len = *body
        .get(offset)
        .ok_or_else(|| anyhow!("TLS ClientHello missing session id length"))?
        as usize;
    offset += 1 + session_len;

    let cipher_len = read_u16_at(body, offset)? as usize;
    offset += 2 + cipher_len;

    let compression_len = *body
        .get(offset)
        .ok_or_else(|| anyhow!("TLS ClientHello missing compression length"))?
        as usize;
    offset += 1 + compression_len;

    let extensions_len = read_u16_at(body, offset)? as usize;
    offset += 2;
    let extensions_end = offset + extensions_len;
    if extensions_end > body.len() {
        bail!("TLS ClientHello extensions exceed record");
    }

    while offset + 4 <= extensions_end {
        let extension_type = read_u16_at(body, offset)?;
        let extension_len = read_u16_at(body, offset + 2)? as usize;
        offset += 4;
        let extension_end = offset + extension_len;
        if extension_end > extensions_end {
            bail!("TLS ClientHello extension exceeds extensions block");
        }

        if extension_type == 0 {
            return parse_sni_extension(&body[offset..extension_end]);
        }
        offset = extension_end;
    }

    bail!("TLS ClientHello does not contain SNI")
}

fn parse_sni_extension(extension: &[u8]) -> Result<String> {
    let list_len = read_u16_at(extension, 0)? as usize;
    if list_len + 2 > extension.len() {
        bail!("TLS SNI list exceeds extension");
    }
    let mut offset = 2;
    let list_end = 2 + list_len;
    while offset + 3 <= list_end {
        let name_type = extension[offset];
        let name_len = read_u16_at(extension, offset + 1)? as usize;
        offset += 3;
        let name_end = offset + name_len;
        if name_end > list_end {
            bail!("TLS SNI name exceeds list");
        }
        if name_type == 0 {
            let name = std::str::from_utf8(&extension[offset..name_end])
                .context("TLS SNI hostname is not UTF-8")?;
            return Ok(name.to_string());
        }
        offset = name_end;
    }
    bail!("TLS SNI extension does not contain a host_name")
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    let pair = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("buffer too short for u16"))?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}

fn read_u24(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 3 {
        bail!("buffer too short for u24");
    }
    Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

async fn relay_one(
    mut client: TcpStream,
    client_ip: IpAddr,
    client_port: u16,
    flow_table: FlowTable,
    connector: Arc<dyn TcpConnector>,
) -> Result<()> {
    let key = FlowKey {
        protocol: TransportProtocol::Tcp,
        client_ip,
        client_port,
    };
    let flow = flow_table.get(&key).ok_or_else(|| {
        log_tcp_relay_diag(format_args!("missing flow for accepted client {key}"));
        anyhow!("missing original destination for {key}")
    })?;
    let destination = Destination::from_ip(flow.original_dst_ip, flow.original_dst_port);

    log_tcp_relay_diag(format_args!(
        "accepted {key}; connecting upstream {destination}",
    ));
    debug!("relay {key} to {destination}");
    let mut upstream = connector.connect(destination).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    flow_table.remove(&key);
    Ok(())
}

fn log_tcp_relay_diag(args: std::fmt::Arguments<'_>) {
    let line = TCP_RELAY_DIAG_LINES.fetch_add(1, Ordering::Relaxed);
    if line >= TCP_RELAY_DIAG_LIMIT {
        return;
    }

    info!("hproxy tcp relay: {args}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_host_header_without_port() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: test\r\n\r\n";
        assert_eq!(parse_http_host(request).unwrap(), "example.com");
    }

    #[test]
    fn finds_http_header_end_before_body() {
        let request = b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        assert_eq!(find_http_header_end(request), Some(38));
    }

    #[test]
    fn strips_bracketed_ipv6_host_port() {
        assert_eq!(strip_host_port("[2001:db8::1]:443"), "2001:db8::1");
    }

    #[test]
    fn parses_tls_sni_from_client_hello() {
        let host = b"example.com";
        let mut body = vec![0x01, 0x00, 0x00, 0x00];
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);

        let extension_data_len = 2 + 1 + 2 + host.len();
        let extensions_len = 4 + extension_data_len;
        body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        body.extend_from_slice(&[0x00, 0x00]);
        body.extend_from_slice(&(extension_data_len as u16).to_be_bytes());
        body.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
        body.push(0x00);
        body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        body.extend_from_slice(host);

        let handshake_len = body.len() - 4;
        body[1] = ((handshake_len >> 16) & 0xff) as u8;
        body[2] = ((handshake_len >> 8) & 0xff) as u8;
        body[3] = (handshake_len & 0xff) as u8;

        assert_eq!(parse_tls_sni_from_record(&body).unwrap(), "example.com");
    }
}

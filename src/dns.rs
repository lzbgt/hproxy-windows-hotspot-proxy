use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{net::UdpSocket, time::timeout};
use tracing::{debug, info, warn};

use crate::config::{DnsConfig, DnsMode};

const MAX_DNS_PACKET_SIZE: usize = 4096;

pub struct DnsProxy {
    socket: Arc<UdpSocket>,
    config: DnsConfig,
    gateway_ip: Option<Ipv4Addr>,
}

impl DnsProxy {
    pub async fn bind(
        listen_port: u16,
        config: DnsConfig,
        gateway_ip: Option<Ipv4Addr>,
    ) -> Result<Self> {
        let socket = Arc::new(
            UdpSocket::bind(("0.0.0.0", listen_port))
                .await
                .with_context(|| format!("bind DNS proxy on port {listen_port}"))?,
        );
        Ok(Self {
            socket,
            config,
            gateway_ip,
        })
    }

    pub async fn run(self) -> Result<()> {
        info!(
            "DNS proxy listening on {}, upstream {}",
            self.socket.local_addr()?,
            self.config.upstream
        );

        let mut buf = [0_u8; MAX_DNS_PACKET_SIZE];
        loop {
            let (len, peer) = self.socket.recv_from(&mut buf).await?;
            if self.config.mode == DnsMode::Gateway
                && let Some(gateway_ip) = self.gateway_ip
                && let Some(response) = gateway_dns_response(&buf[..len], gateway_ip)
            {
                self.socket
                    .send_to(&response, peer)
                    .await
                    .with_context(|| format!("send gateway DNS response to {peer}"))?;
                debug!("answered gateway DNS query for {peer} with {gateway_ip}");
                continue;
            }

            let client_socket = Arc::clone(&self.socket);
            let query = buf[..len].to_vec();
            let upstream = self.config.upstream;
            let timeout_duration = Duration::from_millis(self.config.timeout_ms);

            tokio::spawn(async move {
                if let Err(err) =
                    forward_dns_query(client_socket, peer, query, upstream, timeout_duration).await
                {
                    warn!("DNS query from {peer} failed: {err:#}");
                }
            });
        }
    }
}

async fn forward_dns_query(
    client_socket: Arc<UdpSocket>,
    peer: SocketAddr,
    query: Vec<u8>,
    upstream: SocketAddr,
    timeout_duration: Duration,
) -> Result<()> {
    let bind_addr = wildcard_bind_addr(upstream);
    let upstream_socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("bind DNS upstream socket on {bind_addr}"))?;

    upstream_socket
        .send_to(&query, upstream)
        .await
        .with_context(|| format!("send DNS query to {upstream}"))?;

    let mut response = [0_u8; MAX_DNS_PACKET_SIZE];
    let (len, source) = timeout(timeout_duration, upstream_socket.recv_from(&mut response))
        .await
        .with_context(|| format!("DNS query to {upstream} timed out"))?
        .with_context(|| format!("receive DNS response from {upstream}"))?;

    if source.ip() != upstream.ip() {
        warn!("ignoring DNS response from unexpected source {source}");
        return Ok(());
    }

    client_socket
        .send_to(&response[..len], peer)
        .await
        .with_context(|| format!("send DNS response to {peer}"))?;
    debug!("forwarded DNS query for {peer} through {upstream}");
    Ok(())
}

fn wildcard_bind_addr(upstream: SocketAddr) -> SocketAddr {
    if upstream.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    }
}

fn gateway_dns_response(query: &[u8], gateway_ip: Ipv4Addr) -> Option<Vec<u8>> {
    let parsed = parse_single_question(query)?;
    let mut response = Vec::with_capacity(query.len() + 16);
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&[0x00, 0x01]);
    if parsed.qtype == 1 {
        response.extend_from_slice(&[0x00, 0x01]);
    } else {
        response.extend_from_slice(&[0x00, 0x00]);
    }
    response.extend_from_slice(&[0x00, 0x00]);
    response.extend_from_slice(&[0x00, 0x00]);
    response.extend_from_slice(&query[12..parsed.question_end]);
    if parsed.qtype != 1 {
        return Some(response);
    }

    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
    response.extend_from_slice(&[0x00, 0x04]);
    response.extend_from_slice(&gateway_ip.octets());
    Some(response)
}

struct DnsQuestion {
    qtype: u16,
    question_end: usize,
}

fn parse_single_question(query: &[u8]) -> Option<DnsQuestion> {
    if query.len() < 17 {
        return None;
    }
    if u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }

    let mut offset = 12;
    loop {
        let len = *query.get(offset)? as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || offset + len > query.len() {
            return None;
        }
        offset += len;
    }

    if offset + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
    let qclass = u16::from_be_bytes([query[offset + 2], query[offset + 3]]);
    if qclass != 1 {
        return None;
    }
    Some(DnsQuestion {
        qtype,
        question_end: offset + 4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_ipv4_wildcard_for_ipv4_upstream() {
        let bind = wildcard_bind_addr("1.1.1.1:53".parse().unwrap());
        assert!(bind.is_ipv4());
        assert_eq!(bind.port(), 0);
    }

    #[test]
    fn chooses_ipv6_wildcard_for_ipv6_upstream() {
        let bind = wildcard_bind_addr("[2606:4700:4700::1111]:53".parse().unwrap());
        assert!(bind.is_ipv6());
        assert_eq!(bind.port(), 0);
    }

    #[test]
    fn builds_gateway_a_response() {
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let response = gateway_dns_response(&query, Ipv4Addr::new(192, 168, 137, 1)).unwrap();
        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_eq!(&response[6..8], &[0x00, 0x01]);
        assert!(response.ends_with(&[192, 168, 137, 1]));
    }

    #[test]
    fn builds_empty_gateway_response_for_non_a_queries() {
        let query = [
            0x12, 0x35, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00,
            0x01,
        ];
        let response = gateway_dns_response(&query, Ipv4Addr::new(192, 168, 137, 1)).unwrap();
        assert_eq!(&response[0..2], &[0x12, 0x35]);
        assert_eq!(&response[6..8], &[0x00, 0x00]);
        assert_eq!(response.len(), query.len());
    }
}

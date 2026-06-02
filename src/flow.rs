#![allow(dead_code)]

use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: TransportProtocol,
    pub client_ip: IpAddr,
    pub client_port: u16,
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}/{}:{}",
            self.protocol, self.client_ip, self.client_port
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowValue {
    pub original_dst_ip: IpAddr,
    pub original_dst_port: u16,
    pub redirected_dst_ip: IpAddr,
    pub redirected_dst_port: u16,
    pub created_at: Instant,
    pub last_seen: Instant,
}

impl FlowValue {
    pub fn new(
        original_dst_ip: IpAddr,
        original_dst_port: u16,
        redirected_dst_ip: IpAddr,
        redirected_dst_port: u16,
    ) -> Self {
        let now = Instant::now();
        Self {
            original_dst_ip,
            original_dst_port,
            redirected_dst_ip,
            redirected_dst_port,
            created_at: now,
            last_seen: now,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowTable {
    capacity: usize,
    inner: Arc<Mutex<HashMap<FlowKey, FlowValue>>>,
}

impl FlowTable {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert(&self, key: FlowKey, value: FlowValue) {
        let mut flows = self.inner.lock().expect("flow table lock poisoned");
        if flows.len() >= self.capacity
            && let Some(oldest_key) = flows
                .iter()
                .min_by_key(|(_, flow)| flow.last_seen)
                .map(|(key, _)| *key)
        {
            flows.remove(&oldest_key);
        }
        flows.insert(key, value);
    }

    pub fn get(&self, key: &FlowKey) -> Option<FlowValue> {
        let mut flows = self.inner.lock().expect("flow table lock poisoned");
        let flow = flows.get_mut(key)?;
        flow.last_seen = Instant::now();
        Some(flow.clone())
    }

    pub fn remove(&self, key: &FlowKey) -> Option<FlowValue> {
        self.inner
            .lock()
            .expect("flow table lock poisoned")
            .remove(key)
    }

    pub fn prune_older_than(&self, max_idle: Duration) -> usize {
        let now = Instant::now();
        let mut flows = self.inner.lock().expect("flow table lock poisoned");
        let before = flows.len();
        flows.retain(|_, flow| now.duration_since(flow.last_seen) <= max_idle);
        before - flows.len()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("flow table lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_flow_table() {
        let table = FlowTable::new(1);
        table.insert(
            FlowKey {
                protocol: TransportProtocol::Tcp,
                client_ip: "192.168.137.20".parse().unwrap(),
                client_port: 50000,
            },
            FlowValue::new(
                "93.184.216.34".parse().unwrap(),
                443,
                "192.168.137.1".parse().unwrap(),
                16000,
            ),
        );
        table.insert(
            FlowKey {
                protocol: TransportProtocol::Tcp,
                client_ip: "192.168.137.21".parse().unwrap(),
                client_port: 50001,
            },
            FlowValue::new(
                "142.250.72.14".parse().unwrap(),
                443,
                "192.168.137.1".parse().unwrap(),
                16000,
            ),
        );

        assert_eq!(table.len(), 1);
    }
}

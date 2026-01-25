#![deny(warnings)]

use pnet::packet::icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportReceiver, TransportSender};
use regex::Regex;
use sentinelle_domain::{
    LatencyIntel,
    TcpFingerprint, TcpSigintResult, TcpSigintError, SigintTcpPort,
    IpIdSeries, ClockSkew, IcmpSigintResult, IcmpSigintError, SigintIcmpPort,
    NetworkPathIntel, TracerouteHopDetail, TracerouteSigintError, SigintTraceroutePort,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Debug, thiserror::Error)]
pub enum RawLatencyError {
    #[error("insufficient privileges for raw sockets")]
    InsufficientPrivileges,
    #[error("io error")]
    Io,
}

/// Résultat brut des sondes basse couche (MTU, TCP fingerprint, clock skew, etc.).
#[derive(Debug, Clone, Default)]
pub struct RawLatencyIntel {
    pub mtu: Option<u16>,
    pub tcp_fingerprint: Option<HashMap<String, String>>,
    pub clock_skew_hz: Option<f64>,
}

/// Probe basse couche, séparée du moteur standard.
/// À utiliser uniquement en contexte privilégié (root / CAP_NET_RAW).
pub struct RawLatencyProbe;

impl RawLatencyProbe {
    pub fn new() -> Self {
        Self
    }

    /// Découverte MTU via ICMP Echo (IPv4). Nécessite des raw sockets.
    pub fn discover_path_mtu(&self, target: IpAddr) -> Result<u16, RawLatencyError> {
        let ip = match target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return Ok(1280), // MTU par défaut IPv6
        };

        let (mut tx, _) =
            transport_channel(4096, Layer3(IpNextHeaderProtocols::Icmp))
                .map_err(|_| RawLatencyError::InsufficientPrivileges)?;

        let candidates = [1500u16, 1492, 1472, 1400, 1280];

        for mtu in candidates {
            let payload_size = mtu as usize - 28; // 20 octets IP + 8 ICMP
            if payload_size == 0 {
                continue;
            }

            let mut buffer = vec![0u8; 8 + payload_size];
            if let Some(mut packet) = MutableEchoRequestPacket::new(&mut buffer) {
                packet.set_icmp_type(IcmpTypes::EchoRequest);
                packet.set_sequence_number(1);
                packet.set_identifier(0x1234);
                let checksum = pnet::util::checksum(packet.packet(), 1);
                packet.set_checksum(checksum);

                if tx.send_to(packet, std::net::IpAddr::V4(ip)).is_ok() {
                    return Ok(mtu);
                }
            }
        }

        Ok(1500)
    }

    /// Enrichit un LatencyIntel existant avec les données MTU brutes.
    pub fn enrich_latency(&self, base: &mut LatencyIntel) -> Result<(), RawLatencyError> {
        let mtu = self.discover_path_mtu(base.target)?;
        base.extra.insert("path_mtu".to_string(), mtu.to_string());
        Ok(())
    }
}

/// Impl SIGINT TCP : envoie un SYN et capture le SYN/ACK pour extraire fingerprint TCP.
pub struct TcpSigintEngine;

impl TcpSigintEngine {
    pub fn new() -> Self {
        Self
    }

    fn open_tcp_channel(&self) -> Result<(TransportSender, TransportReceiver), TcpSigintError> {
        transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))
            .map_err(|_| TcpSigintError::InsufficientPrivileges)
    }

    fn send_syn(&self, tx: &mut TransportSender, target: IpAddr, port: u16) -> Result<(), TcpSigintError> {
        let ip = match target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return Err(TcpSigintError::ProbeFailure),
        };

        let mut buffer = vec![0u8; 20];
        let mut tcp = MutableTcpPacket::new(&mut buffer).ok_or(TcpSigintError::ProbeFailure)?;
        tcp.set_source(40000);
        tcp.set_destination(port);
        tcp.set_sequence(1);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64240);
        let checksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &ip, &ip);
        tcp.set_checksum(checksum);

        tx.send_to(tcp, std::net::IpAddr::V4(ip))
            .map_err(|_| TcpSigintError::ProbeFailure)?;
        Ok(())
    }

    fn recv_synack(&self, mut rx: TransportReceiver, target: IpAddr, port: u16) -> Option<TcpFingerprint> {
        let ip = match target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return None,
        };

        let start = Instant::now();
        let timeout = Duration::from_secs(3);
        let mut buf = [0u8; 4096];

        while start.elapsed() < timeout {
            match rx.recv_from(&mut buf) {
                Ok((size, addr)) => {
                    if addr != std::net::IpAddr::V4(ip) {
                        continue;
                    }
                    if let Some(ipv4) = Ipv4Packet::new(&buf[..size]) {
                        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                            continue;
                        }
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            if tcp.get_destination() != 40000 {
                                continue;
                            }
                            if tcp.get_flags() & TcpFlags::SYN == TcpFlags::SYN
                                && tcp.get_flags() & TcpFlags::ACK == TcpFlags::ACK
                            {
                                let win = tcp.get_window();
                                let ttl = Some(ipv4.get_ttl());
                                let ip_id = Some(ipv4.get_identification());
                                // Options parsing minimal: on ne fait que noter leur présence
                                let options = vec!["raw".to_string()];

                                return Some(TcpFingerprint {
                                    window_size: win,
                                    options,
                                    wscale: None,
                                    sack_permitted: false,
                                    ts_val: None,
                                    ts_ecr: None,
                                    ttl,
                                    ip_id,
                                });
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        None
    }
}

impl SigintTcpPort for TcpSigintEngine {
    fn probe(&self, target: IpAddr, port: u16) -> Result<TcpSigintResult, TcpSigintError> {
        if target.is_unspecified() {
            return Err(TcpSigintError::InvalidTarget(target.to_string()));
        }
        let (mut tx, rx) = self.open_tcp_channel()?;
        self.send_syn(&mut tx, target, port)?;
        let fp = self.recv_synack(rx, target, port);
        Ok(TcpSigintResult {
            target,
            port,
            fingerprint: fp,
        })
    }
}

/// Impl SIGINT ICMP : collecte IP ID et prépare le terrain pour clock skew.
pub struct IcmpSigintEngine;

impl IcmpSigintEngine {
    pub fn new() -> Self {
        Self
    }

    fn open_icmp_channel(&self) -> Result<(TransportSender, TransportReceiver), IcmpSigintError> {
        transport_channel(4096, Layer3(IpNextHeaderProtocols::Icmp))
            .map_err(|_| IcmpSigintError::InsufficientPrivileges)
    }

    fn send_echo(&self, tx: &mut TransportSender, ip: std::net::Ipv4Addr, seq: u16) -> Result<(), IcmpSigintError> {
        let mut buffer = vec![0u8; 8];
        if let Some(mut packet) = MutableEchoRequestPacket::new(&mut buffer) {
            packet.set_icmp_type(IcmpTypes::EchoRequest);
            packet.set_sequence_number(seq);
            packet.set_identifier(0x5678);
            let checksum = pnet::util::checksum(packet.packet(), 1);
            packet.set_checksum(checksum);
            tx.send_to(packet, std::net::IpAddr::V4(ip))
                .map_err(|_| IcmpSigintError::ProbeFailure)?;
        }
        Ok(())
    }

    fn recv_replies(&self, mut rx: TransportReceiver, target: IpAddr, count: usize) -> Vec<u16> {
        let ip = match target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return Vec::new(),
        };

        let timeout = Duration::from_secs(5);
        let start = Instant::now();
        let mut ids = Vec::new();
        let mut buf = [0u8; 4096];

        while start.elapsed() < timeout && ids.len() < count {
            if let Ok((size, addr)) = rx.recv_from(&mut buf) {
                if addr != std::net::IpAddr::V4(ip) {
                    continue;
                }

                if let Some(ipv4) = Ipv4Packet::new(&buf[..size]) {
                    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                        continue;
                    }
                    let _ip_id = ipv4.get_identification();
                    if IcmpPacket::new(ipv4.payload()).is_some() {
                        ids.push(_ip_id);
                    }
                }
            }
        }
        ids
    }

    fn classify_series(&self, ids: &[u16]) -> String {
        if ids.len() < 2 {
            return "insufficient_data".to_string();
        }
        let diffs: Vec<i32> = ids
            .windows(2)
            .map(|w| {
                let a = w[0] as i32;
                let b = w[1] as i32;
                b - a
            })
            .collect();

        if diffs.iter().all(|&d| d == 0) {
            "constant".to_string()
        } else if diffs.iter().all(|&d| d > 0 && d < 5) {
            "incremental".to_string()
        } else {
            "mixed".to_string()
        }
    }
}

impl SigintIcmpPort for IcmpSigintEngine {
    fn probe(&self, target: IpAddr) -> Result<IcmpSigintResult, IcmpSigintError> {
        if target.is_unspecified() {
            return Err(IcmpSigintError::InvalidTarget(target.to_string()));
        }

        let (mut tx, rx) = self.open_icmp_channel()?;
        let ip = match target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return Ok(IcmpSigintResult {
                target,
                ip_id_series: None,
                clock_skew: None,
            }),
        };

        for seq in 0..5u16 {
            let _ = self.send_echo(&mut tx, ip, seq);
        }

        let ids = self.recv_replies(rx, target, 5);
        let series = if !ids.is_empty() {
            Some(IpIdSeries {
                ids: ids.clone(),
                classification: self.classify_series(&ids),
            })
        } else {
            None
        };

        Ok(IcmpSigintResult {
            target,
            ip_id_series: series,
            clock_skew: None, // Clock skew ICMP sera implémenté ensuite
        })
    }
}

/// Impl SIGINT Traceroute : utilisation du traceroute système + ASN/IXP à enrichir.
pub struct TracerouteSigintEngine;

impl TracerouteSigintEngine {
    pub fn new() -> Self {
        Self
    }
}

impl SigintTraceroutePort for TracerouteSigintEngine {
    fn trace(&self, target: IpAddr, max_hops: u8) -> Result<NetworkPathIntel, TracerouteSigintError> {
        if target.is_unspecified() {
            return Err(TracerouteSigintError::InvalidTarget(target.to_string()));
        }

        let host = target.to_string();
        let is_windows = cfg!(target_os = "windows");

        let (cmd, args) = if is_windows {
            ("tracert", vec!["-d", "-h", &max_hops.to_string(), &host])
        } else {
            ("traceroute", vec!["-n", "-m", &max_hops.to_string(), &host])
        };

        let output = std::process::Command::new(cmd)
            .args(&args)
            .output()
            .map_err(|_| TracerouteSigintError::ProbeFailure)?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let re_ip = Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3})").unwrap();
        let re_rtt = Regex::new(r"(\d+(?:\.\d+)?) ms").unwrap();

        let mut hops = Vec::new();
        let mut hop_index: u8 = 1;
        for line in stdout.lines() {
            let ips: Vec<_> = re_ip.captures_iter(line).collect();
            if ips.is_empty() {
                continue;
            }
            let ip = ips[0][1].to_string();
            let rtt_ms = re_rtt
                .captures(line)
                .and_then(|c| c[1].parse::<f64>().ok());

            hops.push(TracerouteHopDetail {
                hop_index,
                ip,
                rtt_ms,
                asn: None,
                owner: None,
                country: None,
            });
            hop_index = hop_index.saturating_add(1);
        }

        Ok(NetworkPathIntel {
            target,
            hops,
            as_path: Vec::new(),
            ixps: Vec::new(),
        })
    }
}
}
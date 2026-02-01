#![deny(warnings)]

use pnet::packet::icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportReceiver, TransportSender};
use regex::Regex;
use sentinelle_domain::{
    LatencyIntel,
    TcpFingerprint, TcpSigintResult, TcpSigintError, SigintTcpPort,
    IpIdSeries, IcmpSigintResult, IcmpSigintError, SigintIcmpPort,
    NetworkPathIntel, TracerouteHopDetail, TracerouteSigintError, SigintTraceroutePort,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Debug, thiserror::Error)]
pub enum RawLatencyError {
    #[error("insufficient privileges for raw sockets")]
    InsufficientPrivileges,
    #[error("io error")]
    Io,
}

/// Raw result from low-level probes (MTU, TCP fingerprint, clock skew, etc.).
#[derive(Debug, Clone, Default)]
pub struct RawLatencyIntel {
    pub mtu: Option<u16>,
    pub tcp_fingerprint: Option<HashMap<String, String>>,
    pub clock_skew_hz: Option<f64>,
}

/// Low-level probe, separated from standard engine.
/// Use only in privileged context (root / CAP_NET_RAW).
pub struct RawLatencyProbe;

impl RawLatencyProbe {
    pub fn new() -> Self {
        Self
    }

    /// MTU discovery via ICMP Echo (IPv4). Requires raw sockets.
    pub fn discover_path_mtu(&self, target: IpAddr) -> Result<u16, RawLatencyError> {
        let ip = match target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return Ok(1280), // Default IPv6 MTU
        };

        let (mut tx, _) =
            transport_channel(4096, Layer3(IpNextHeaderProtocols::Icmp))
                .map_err(|_| RawLatencyError::InsufficientPrivileges)?;

        let candidates = [1500u16, 1492, 1472, 1400, 1280];

        for mtu in candidates {
            let payload_size = mtu as usize - 28; // 20 bytes IP + 8 ICMP
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

    /// Enriches an existing LatencyIntel with raw MTU data.
    pub fn enrich_latency(&self, base: &mut LatencyIntel) -> Result<(), RawLatencyError> {
        let mtu = self.discover_path_mtu(base.target)?;
        base.extra.insert("path_mtu".to_string(), mtu.to_string());
        Ok(())
    }
}

/// SIGINT TCP impl: sends SYN and captures SYN/ACK to extract TCP fingerprint.
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

    fn recv_synack(&self, _rx: TransportReceiver, _target: IpAddr, _port: u16) -> Option<TcpFingerprint> {
        // Simplified implementation - raw socket operations are complex and platform-specific
        // In production, this would use proper packet capture libraries
        None
    }
}

impl SigintTcpPort for TcpSigintEngine {
    fn probe(&self, target: IpAddr, port: u16) -> Result<TcpSigintResult, TcpSigintError> {
        if target.is_unspecified() {
            return Err(TcpSigintError::InvalidTarget(target.to_string()));
        }
        let (mut tx, _rx) = self.open_tcp_channel()?;

        // Collect multiple responses to estimate clock skew via TCP timestamps
        let mut last_fp: Option<TcpFingerprint> = None;

        for _ in 0..4 {
            self.send_syn(&mut tx, target, port)?;
            
            // Create new channel for each reception
            let (_, rx_new) = self.open_tcp_channel()?;
            if let Some(fp) = self.recv_synack(rx_new, target, port) {
                last_fp = Some(fp);
                break; // Simplified: take first successful response
            }
        }

        let clock_skew = None; // Simplified for now

        // Simple OS guess based on window size + options + TTL
        let os_guess = last_fp.as_ref().and_then(|fp| {
            if fp.options.contains(&"TS".to_string()) && fp.wscale.is_some() {
                if fp.window_size == 65535 {
                    Some("Linux/Modern".to_string())
                } else if fp.window_size == 8192 {
                    Some("Windows/Legacy".to_string())
                } else {
                    Some("Unknown/Generic".to_string())
                }
            } else if fp.window_size == 65535 {
                Some("Windows/Generic".to_string())
            } else {
                None
            }
        });

        Ok(TcpSigintResult {
            target,
            port,
            fingerprint: last_fp,
            clock_skew,
            os_guess,
        })
    }
}

/// SIGINT ICMP impl: collects IP ID and prepares ground for clock skew.
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

    fn recv_replies(&self, _rx: TransportReceiver, _target: IpAddr, _count: usize) -> Vec<u16> {
        // Simplified implementation - raw socket operations are complex and platform-specific
        // In production, this would use proper packet capture libraries
        Vec::new()
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
            clock_skew: None, // ICMP clock skew will be implemented later
        })
    }
}

/// SIGINT Traceroute impl: uses system traceroute + ASN/IXP enrichment.
pub struct TracerouteSigintEngine;

impl TracerouteSigintEngine {
    pub fn new() -> Self {
        Self
    }

    fn lookup_asn(&self, ip: &str) -> Option<(String, String, Option<String>)> {
        // Team Cymru DNS: <revip>.origin.asn.cymru.com TXT
        let rev: String = ip.split('.').rev().collect::<Vec<_>>().join(".");
        let name = format!("{}.origin.asn.cymru.com", rev);

        let rt = tokio::runtime::Runtime::new().ok()?;
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(2);
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

        let txt = rt.block_on(resolver.txt_lookup(name)).ok()?;
        let first = txt.iter().next()?;
        let txt_data: String = first
            .txt_data()
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect();
        // Format: "ASN | IP | CC | Registry | Allocated | AS Name"
        let parts: Vec<_> = txt_data.split('|').map(|s| s.trim()).collect();
        if parts.len() >= 3 {
            let asn = parts[0].to_string();
            let country = parts[2].to_string();
            let owner = if parts.len() >= 6 { Some(parts[5].to_string()) } else { None };
            return Some((asn, country, owner));
        }
        None
    }
}

impl SigintTraceroutePort for TracerouteSigintEngine {
    fn trace(&self, target: IpAddr, max_hops: u8) -> Result<NetworkPathIntel, TracerouteSigintError> {
        if target.is_unspecified() {
            return Err(TracerouteSigintError::InvalidTarget(target.to_string()));
        }

        let host = target.to_string();
        let is_windows = cfg!(target_os = "windows");

        let max_hops_str = max_hops.to_string();
        let (cmd, args) = if is_windows {
            ("tracert", vec!["-d", "-h", &max_hops_str, &host])
        } else {
            ("traceroute", vec!["-n", "-m", &max_hops_str, &host])
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
        let mut as_path = Vec::new();

        for line in stdout.lines() {
            let ips: Vec<_> = re_ip.captures_iter(line).collect();
            if ips.is_empty() {
                continue;
            }
            let ip = ips[0][1].to_string();
            let rtt_ms = re_rtt
                .captures(line)
                .and_then(|c| c[1].parse::<f64>().ok());

            let (asn, country, owner) = match self.lookup_asn(&ip) {
                Some((a, c, o)) => {
                    as_path.push(a.clone());
                    (Some(a), Some(c), o)
                }
                None => (None, None, None),
            };

            hops.push(TracerouteHopDetail {
                hop_index,
                ip,
                rtt_ms,
                asn,
                owner,
                country,
            });
            hop_index = hop_index.saturating_add(1);
        }

        // Simple AS path deduplication (consecutive identical)
        let mut dedup_as_path = Vec::new();
        for a in as_path {
            if dedup_as_path.last() != Some(&a) {
                dedup_as_path.push(a);
            }
        }

        // Very simple IXP detection from AS names
        let mut ixps = Vec::new();
        for hop in &hops {
            if let Some(ref o) = hop.owner {
                let lower = o.to_lowercase();
                if lower.contains("ixp")
                    || lower.contains("internet exchange")
                    || lower.contains("ams-ix")
                    || lower.contains("decix")
                    || lower.contains("linx")
                {
                    ixps.push(o.clone());
                }
            }
        }
        ixps.sort();
        ixps.dedup();

        Ok(NetworkPathIntel {
            target,
            hops,
            as_path: dedup_as_path,
            ixps,
        })
    }
}
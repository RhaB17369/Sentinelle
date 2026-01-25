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

        while start.elapsed() &lt; timeout {
            match rx.recv_from(&mut buf) {
                Ok((size, addr)) =&gt; {
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
                            if tcp.get_flags() &amp; TcpFlags::SYN == TcpFlags::SYN
                                &amp;&amp; tcp.get_flags() &amp; TcpFlags::ACK == TcpFlags::ACK
                            {
                                let win = tcp.get_window();
                                let ttl = Some(ipv4.get_ttl());
                                let ip_id = Some(ipv4.get_identification());

                                // Parsing des options TCP brutes
                                let mut options = Vec::new();
                                let mut wscale = None;
                                let mut sack_permitted = false;
                                let mut ts_val = None;
                                let mut ts_ecr = None;

                                if let Some(raw_opts) = tcp.get_options_raw() {
                                    let mut i = 0;
                                    while i &lt; raw_opts.len() {
                                        let kind = raw_opts[i];
                                        match kind {
                                            0 =&gt; {
                                                options.push("EOL".to_string());
                                                break;
                                            }
                                            1 =&gt; {
                                                options.push("NOP".to_string());
                                                i += 1;
                                            }
                                            2 =&gt; {
                                                if i + 4 &lt;= raw_opts.len() {
                                                    options.push("MSS".to_string());
                                                    i += 4;
                                                } else {
                                                    break;
                                                }
                                            }
                                            3 =&gt; {
                                                if i + 3 &lt;= raw_opts.len() {
                                                    wscale = Some(raw_opts[i + 2]);
                                                    options.push("WS".to_string());
                                                    i += 3;
                                                } else {
                                                    break;
                                                }
                                            }
                                            4 =&gt; {
                                                options.push("SACK".to_string());
                                                sack_permitted = true;
                                                i += 2;
                                            }
                                            8 =&gt; {
                                                if i + 10 &lt;= raw_opts.len() {
                                                    let ts_bytes = &raw_opts[i + 2..i + 10];
                                                    let ts_val_u32 = u32::from_be_bytes([
                                                        ts_bytes[0], ts_bytes[1],
                                                        ts_bytes[2], ts_bytes[3],
                                                    ]);
                                                    let ts_ecr_u32 = u32::from_be_bytes([
                                                        ts_bytes[4], ts_bytes[5],
                                                        ts_bytes[6], ts_bytes[7],
                                                    ]);
                                                    ts_val = Some(ts_val_u32);
                                                    ts_ecr = Some(ts_ecr_u32);
                                                    options.push("TS".to_string());
                                                    i += 10;
                                                } else {
                                                    break;
                                                }
                                            }
                                            _ =&gt; {
                                                // Option inconnue : lire longueur et sauter
                                                if i + 2 &lt;= raw_opts.len() {
                                                    let len = raw_opts[i + 1] as usize;
                                                    if len &lt; 2 || i + len &gt; raw_opts.len() {
                                                        break;
                                                    }
                                                    options.push(format!("OPT{}", kind));
                                                    i += len;
                                                } else {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }

                                return Some(TcpFingerprint {
                                    window_size: win,
                                    options,
                                    wscale,
                                    sack_permitted,
                                    ts_val,
                                    ts_ecr,
                                    ttl,
                                    ip_id,
                                });
                            }
                        }
                    }
                }
                Err(_) =&gt; continue,
            }
        }

        None
    }

impl SigintTcpPort for TcpSigintEngine {
    fn probe(&self, target: IpAddr, port: u16) -> Result<TcpSigintResult, TcpSigintError> {
        if target.is_unspecified() {
            return Err(TcpSigintError::InvalidTarget(target.to_string()));
        }
        let (mut tx, rx) = self.open_tcp_channel()?;

        // Collecte de plusieurs réponses pour estimer le clock skew via timestamps TCP
        let mut samples: Vec<(f64, u32)> = Vec::new();
        let mut last_fp: Option<TcpFingerprint> = None;

        for _ in 0..4 {
            let t0 = Instant::now();
            self.send_syn(&mut tx, target, port)?;
            if let Some(fp) = self.recv_synack(rx.try_clone().unwrap(), target, port) {
                let t = t0.elapsed().as_secs_f64();
                if let Some(ts) = fp.ts_val {
                    samples.push((t, ts));
                }
                last_fp = Some(fp);
            }
        }

        let clock_skew = if samples.len() &gt;= 2 {
            // Régression linéaire simple: ts = a * t + b => a ~ skew
            let n = samples.len() as f64;
            let sum_t: f64 = samples.iter().map(|(t, _)| *t).sum();
            let sum_ts: f64 = samples.iter().map(|(_, ts)| *ts as f64).sum();
            let sum_tts: f64 = samples.iter().map(|(t, ts)| *t * (*ts as f64)).sum();
            let sum_tt: f64 = samples.iter().map(|(t, _)| t * t).sum();

            let denom = n * sum_tt - sum_t * sum_t;
            if denom.abs() &gt; f64::EPSILON {
                let a = (n * sum_tts - sum_t * sum_ts) / denom;
                Some(ClockSkew {
                    hz: a,
                    sample_count: samples.len(),
                })
            } else {
                None
            }
        } else {
            None
        };

        // OS guess simple basé sur taille fenêtre + options + TTL
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

impl TracerouteSigintEngine {
    fn lookup_asn(&self, ip: &str) -> Option<(String, String)> {
        // Team Cymru DNS: &lt;revip&gt;.origin.asn.cymru.com TXT
        let rev: String = ip.split('.').rev().collect::<Vec&lt;_&gt;>().join(".");
        let name = format!("{rev}.origin.asn.cymru.com");

        let mut rt = tokio::runtime::Runtime::new().ok()?;
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(2);
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts).ok()?;

        let txt = rt.block_on(resolver.txt_lookup(name)).ok()?;
        let first = txt.iter().next()?;
        let txt_data: String = first
            .txt_data()
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect();
        // Format: "ASN | IP | CC | Registry | Allocated | AS Name"
        let parts: Vec&lt;_&gt; = txt_data.split('|').map(|s| s.trim()).collect();
        if parts.len() &gt;= 3 {
            let asn = parts[0].to_string();
            let country = parts[2].to_string();
            let owner = if parts.len() &gt;= 6 { Some(parts[5].to_string()) } else { None };
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
        let re_ip = Regex::new(r"(\\d{1,3}(?:\\.\\d{1,3}){3})").unwrap();
        let re_rtt = Regex::new(r"(\\d+(?:\\.\\d+)?) ms").unwrap();

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

        // Déduplication simple de l'AS path (consécutifs identiques)
        let mut dedup_as_path = Vec::new();
        for a in as_path {
            if dedup_as_path.last() != Some(&a) {
                dedup_as_path.push(a);
            }
        }

        // Détection très simple d'IXP à partir des noms d'AS
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
#![deny(warnings)]

use pnet::packet::icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use sentinelle_domain::LatencyIntel;
use std::collections::HashMap;
use std::net::IpAddr;

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

    /// TCP SYN fingerprint minimaliste: construit un paquet SYN avec un set d'options
    /// et renvoie les paramètres utilisés (taille fenêtre, options).
    /// Note: sur un moteur SIGINT complet, il faut aussi capturer la réponse.
    pub fn tcp_syn_fingerprint(&self, target: IpAddr, port: u16) -> Result<HashMap<String, String>, RawLatencyError> {
        let ip = match target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return Err(RawLatencyError::Io), // à étendre pour IPv6
        };

        // Construction d'un paquet TCP SYN brut.
        let mut buffer = vec![0u8; 20]; // en-tête TCP minimal
        let mut tcp = MutableTcpPacket::new(&mut buffer).ok_or(RawLatencyError::Io)?;
        tcp.set_source(40000);
        tcp.set_destination(port);
        tcp.set_sequence(1);
        tcp.set_flags(pnet::packet::tcp::TcpFlags::SYN);
        tcp.set_window(64240);
        let checksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &ip, &ip);
        tcp.set_checksum(checksum);

        // Envoi best-effort en Layer3; capture de la réponse à implémenter si nécessaire.
        let (mut tx, _) =
            transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp))
                .map_err(|_| RawLatencyError::InsufficientPrivileges)?;
        let _ = tx.send_to(tcp, std::net::IpAddr::V4(ip));

        let mut fp = HashMap::new();
        fp.insert("window_size".to_string(), "64240".to_string());
        fp.insert("flags".to_string(), "SYN".to_string());
        Ok(fp)
    }
}
}
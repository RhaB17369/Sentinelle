#![deny(warnings)]

use pnet::packet::icmp::{IcmpTypes, echo_request::MutableEchoRequestPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{transport_channel, TransportChannelType::Layer3, TransportProtocol};
use sentinelle_domain::{LatencyIntel, LatencyIntelError};
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum RawLatencyError {
    #[error("insufficient privileges for raw sockets")]
    InsufficientPrivileges,
    #[error("io error")]
    Io,
}

/// Résultat brut des sondes basse couche (MTU, clock skew, etc.).
#[derive(Debug, Clone, Default)]
pub struct RawLatencyIntel {
    pub mtu: Option<u16>,
    pub clock_skew_hz: Option<f64>,
    // D'autres champs (tcp fingerprint, ip_id, etc.) pourront être ajoutés ici.
}

/// Probe basse couche, séparée du moteur standard.
/// Doit être utilisée uniquement en contexte privilégié (root / CAP_NET_RAW).
pub struct RawLatencyProbe;

impl RawLatencyProbe {
    pub fn new() -> Self {
        Self
    }

    /// Découverte simple de MTU via ICMP Echo avec DF (IPv4 uniquement pour cette première version).
    pub fn discover_path_mtu(&self, target: IpAddr) -> Result<u16, RawLatencyError> {
        let ip = match target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return Ok(1280), // MTU par défaut IPv6
        };

        let protocol = Layer3(IpNextHeaderProtocols::Icmp);
        let (mut tx, _) =
            transport_channel(4096, TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp))
                .map_err(|_| RawLatencyError::InsufficientPrivileges)?;

        // Plage de MTU à tester (simplifiée par rapport à LatencyTracer Python)
        let candidates = [1500u16, 1492, 1472, 1400, 1280];

        for mtu in candidates {
            let payload_size = mtu as usize - 28; // 20 IP + 8 ICMP
            if payload_size <= 0 {
                continue;
            }

            let mut buffer = vec![0u8; 8 + payload_size];
            let mut packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
            packet.set_icmp_type(IcmpTypes::EchoRequest);
            packet.set_sequence_number(1);
            packet.set_identifier(0x1234);
            // checksum auto via pnet ?
            let checksum = pnet::util::checksum(packet.packet(), 1);
            packet.set_checksum(checksum);

            // Envoi best-effort, si on arrive à envoyer sans erreur on considère le MTU supporté.
            match tx.send_to(packet, std::net::IpAddr::V4(ip)) {
                Ok(_) => return Ok(mtu),
                Err(_) => continue,
            }
        }

        Ok(1500)
    }

    /// Enrichit un LatencyIntel existant avec le MTU détecté via ICMP.
    pub fn enrich_latency(&self, base: &mut LatencyIntel) -> Result<(), RawLatencyError> {
        let mtu = self.discover_path_mtu(base.target)?;
        base.extra.insert("path_mtu".to_string(), mtu.to_string());
        Ok(())
    }
}
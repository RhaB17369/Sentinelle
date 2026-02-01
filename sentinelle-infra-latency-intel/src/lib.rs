#![deny(warnings)]

use sentinelle_domain::{
    LatencyIntelligencePort, LatencyIntel, LatencyIntelError,
    RttStats, LinkQuality, AsnInfo, TraceroutePath,
};
use std::net::IpAddr;
use std::process::Stdio;
use tokio::process::Command;
use regex::Regex;

#[derive(Debug)]
pub struct LatencyIntelEngine;

impl LatencyIntelEngine {
    pub fn new() -> Self {
        Self
    }

    fn parse_ping_output(output: &str, is_windows: bool) -> Option<RttStats> {
        let mut loss_pct = 100.0;

        let loss_re_unix = Regex::new(r"(?:\d+)\s+packets transmitted.*?(\d+(?:[.,]\d+)?)% packet loss")
            .unwrap();
        let loss_re_win = Regex::new(r"Lost = \d+ \((\d+)%\s*loss\)").unwrap();

        if let Some(caps) = loss_re_unix.captures(output) {
            loss_pct = caps[1].replace(',', ".").parse().ok()?;
        } else if let Some(caps) = loss_re_win.captures(output) {
            loss_pct = caps[1].parse().ok()?;
        }

        if is_windows {
            let re = Regex::new(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms").unwrap();
            if let Some(caps) = re.captures(output) {
                let min = caps[1].parse().ok()?;
                let max = caps[2].parse().ok()?;
                let avg = caps[3].parse().ok()?;
                return Some(RttStats {
                    min,
                    avg,
                    max,
                    mdev: 0.0,
                    loss_pct,
                });
            }
        } else {
            let re = Regex::new(
                r"= ?([0-9]+(?:[.,][0-9]+)?)/([0-9]+(?:[.,][0-9]+)?)/([0-9]+(?:[.,][0-9]+)?)/([0-9]+(?:[.,][0-9]+)?) ms",
            )
            .unwrap();
            if let Some(caps) = re.captures(output) {
                let min = caps[1].replace(',', ".").parse().ok()?;
                let avg = caps[2].replace(',', ".").parse().ok()?;
                let max = caps[3].replace(',', ".").parse().ok()?;
                let mdev = caps[4].replace(',', ".").parse().ok()?;
                return Some(RttStats {
                    min,
                    avg,
                    max,
                    mdev,
                    loss_pct,
                });
            }
        }

        None
    }

    fn classify_link_type(avg_rtt: f64, jitter: f64) -> String {
        const SAT_RTT_THRESHOLD: f64 = 480.0;
        const STARLINK_RTT_MAX: f64 = 100.0;
        const STARLINK_JITTER_THRESHOLD: f64 = 20.0;
        const MOBILE_JITTER_THRESHOLD: f64 = 15.0;

        if avg_rtt > SAT_RTT_THRESHOLD {
            return "Geostationary Satellite (High Latency)".to_string();
        }

        if avg_rtt > 25.0 && avg_rtt < STARLINK_RTT_MAX && jitter > STARLINK_JITTER_THRESHOLD {
            return "LEO Satellite (Likely Starlink)".to_string();
        }

        if jitter > MOBILE_JITTER_THRESHOLD {
            return "Mobile/Radio (4G/5G/LTE)".to_string();
        }

        "Terrestrial (Fiber/Copper)".to_string()
    }

    fn calculate_link_quality(rtt: &RttStats) -> LinkQuality {
        let mut score = 100.0;
        let loss = rtt.loss_pct;
        let jitter = rtt.mdev;

        // pénalisation perte
        score -= loss * 1.5;
        // pénalisation jitter
        score -= f64::min(25.0, jitter * 1.5);

        let avg = rtt.avg;
        if avg > 0.0 {
            let bloat_factor = rtt.max / avg;
            if bloat_factor > 1.5 {
                score -= f64::min(20.0, (bloat_factor - 1.5) * 10.0);
            }
        }

        let rating = if score < 30.0 {
            "Critical"
        } else if score < 50.0 {
            "Degraded"
        } else if score < 75.0 {
            "Nominal"
        } else if score < 90.0 {
            "High-Quality"
        } else {
            "Elite"
        };

        LinkQuality {
            quality_score: score.max(0.0).round(),
            rating: rating.to_string(),
            packet_loss_pct: loss,
        }
    }

    fn estimate_distance(avg_rtt: f64, mdev: f64) -> (f64, f64) {
        const FIBER_SPEED_KM_MS: f64 = 200.0;
        const ROUTING_OVERHEAD_FACTOR: f64 = 1.05;

        if avg_rtt <= 0.0 {
            return (0.0, 0.0);
        }
        let one_way = avg_rtt / 2.0;
        let effective = f64::max(0.1, one_way - 1.0);
        let dist = (effective * FIBER_SPEED_KM_MS) * ROUTING_OVERHEAD_FACTOR;
        let margin = (mdev * FIBER_SPEED_KM_MS) + (dist * 0.1);
        (dist.round(), margin.round())
    }

    async fn run_ping(&self, target: IpAddr) -> Option<RttStats> {
        let is_windows = cfg!(target_os = "windows");
        let host = target.to_string();

        let (cmd, args) = if is_windows {
            ("ping", vec!["-n", "5", &host])
        } else {
            ("ping", vec!["-c", "5", "-W", "3", &host])
        };

        let output = Command::new(cmd)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        Self::parse_ping_output(&stdout, is_windows)
    }

    async fn run_traceroute(&self, _target: IpAddr) -> Option<TraceroutePath> {
        // Placeholder pour l'instant : la logique traceroute détaillée sera ajoutée
        // en s'appuyant sur traceroute système + DNS ASN (Team Cymru ou autre).
        None
    }

    async fn get_asn_info(&self, _target: IpAddr) -> Option<AsnInfo> {
        // Placeholder : peut être implémenté via Team Cymru DNS ou API BGP.
        None
    }

    async fn analyze_async(&self, target: IpAddr) -> Result<LatencyIntel, LatencyIntelError> {
        if target.is_unspecified() {
            return Err(LatencyIntelError::InvalidIp(target.to_string()));
        }

        let rtt = self.run_ping(target).await;
        let (link_quality, jitter_ms, distance_km, distance_margin_km, link_medium) = if let Some(ref stats) = rtt {
            let jitter = stats.mdev;
            let link = Self::classify_link_type(stats.avg, jitter);
            let lq = Self::calculate_link_quality(stats);
            let (dist, margin) = Self::estimate_distance(stats.avg, jitter);
            (Some(lq), Some(jitter), Some(dist), Some(margin), Some(link))
        } else {
            (None, None, None, None, None)
        };

        let traceroute = self.run_traceroute(target).await;
        let asn = self.get_asn_info(target).await;

        Ok(LatencyIntel {
            target,
            rtt,
            jitter_ms,
            link_medium,
            link_quality,
            asn,
            traceroute,
            distance_km,
            distance_margin_km,
            extra: std::collections::HashMap::new(),
        })
    }
}

impl LatencyIntelligencePort for LatencyIntelEngine {
    fn analyze(&self, target: IpAddr) -> Result<LatencyIntel, LatencyIntelError> {
        let rt = tokio::runtime::Runtime::new().map_err(|_| LatencyIntelError::UpstreamFailure)?;
        rt.block_on(self.analyze_async(target))
    }
}
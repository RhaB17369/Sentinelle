use crate::{geojs::GeoJsClient, ip_api::IpApiClient};
use reqwest::Client;
use sentinelle_domain::{IpIntelligencePort, IpIntelligence, IpIntelError, MetricsPort};
use std::net::IpAddr;

#[derive(Debug)]
pub struct CompositeIpIntelligence<M: MetricsPort + Clone> {
    ip_api: IpApiClient<M>,
    geojs: GeoJsClient<M>,
}

impl<M: MetricsPort + Clone> CompositeIpIntelligence<M> {
    pub fn new(http: Client, metrics: M) -> Self {
        let ip_api = IpApiClient::new(http.clone(), metrics.clone());
        let geojs = GeoJsClient::new(http, metrics);
        Self { ip_api, geojs }
    }

    pub fn new_with_default_client(metrics: M) -> Self {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("Sentinelle-OSINT/1.0")
            .build()
            .expect("Failed to create HTTP client");
        Self::new(http, metrics)
    }
}

impl<M: MetricsPort + Clone + Send + Sync> IpIntelligencePort for CompositeIpIntelligence<M> {
    fn analyze_ip(&self, ip: IpAddr) -> Result<IpIntelligence, IpIntelError> {
        // Validation d'entrée obligatoire - utilise is_global() stable alternative
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
            return Err(IpIntelError::InvalidIp(format!("IP address {} is not global", ip)));
        }
        
        // Vérification manuelle pour les adresses globales
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_private() || v4.is_link_local() || v4.is_broadcast() {
                    return Err(IpIntelError::InvalidIp(format!("IP address {} is not global", ip)));
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() {
                    return Err(IpIntelError::InvalidIp(format!("IP address {} is not global", ip)));
                }
            }
        }

        // Utilise le runtime tokio existant ou crée un runtime minimal
        let rt = tokio::runtime::Runtime::new()
            .map_err(|_| IpIntelError::ProviderFailure)?;
        rt.block_on(self.analyze_ip_async(ip))
    }
}

impl<M: MetricsPort + Clone + Send + Sync> CompositeIpIntelligence<M> {
    async fn analyze_ip_async(&self, ip: IpAddr) -> Result<IpIntelligence, IpIntelError> {
        // 1) ip-api avec timeout et retry
        if let Some(mut data) = self.ip_api.fetch(ip).await? {
            // 2) geojs pour compléter les trous
            if let Some(extra) = self.geojs.fetch(ip).await? {
                if data.country.is_none() {
                    data.country = extra.country;
                }
                if data.country_code.is_none() {
                    data.country_code = extra.country_code;
                }
                if data.region.is_none() {
                    data.region = extra.region;
                }
                if data.city.is_none() {
                    data.city = extra.city;
                }
                if data.latitude.is_none() {
                    data.latitude = extra.latitude;
                }
                if data.longitude.is_none() {
                    data.longitude = extra.longitude;
                }
                if data.timezone.is_none() {
                    data.timezone = extra.timezone;
                }
                if data.isp.is_none() {
                    data.isp = extra.isp;
                }
                if data.asn.is_none() {
                    data.asn = extra.asn;
                }
            }
            Ok(data)
        } else if let Some(data) = self.geojs.fetch(ip).await? {
            Ok(data)
        } else {
            Err(IpIntelError::NoData)
        }
    }
}
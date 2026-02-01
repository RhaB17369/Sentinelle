use crate::{
    ip_api::IpApiClient, 
    geojs::GeoJsClient, 
    ipinfo::IpInfoClient,
};
use reqwest::Client;
use sentinelle_domain::{
    IpIntelligencePort, IpIntelligence, IpIntelError,
    MetricsPort,
};
use std::net::IpAddr;

/// Enhanced IP Intelligence Engine with multiple data sources
#[derive(Debug)]
pub struct EnrichedIpIntelligenceEngine<M: MetricsPort + Clone> {
    ip_api: IpApiClient<M>,
    geojs: GeoJsClient<M>,
    ipinfo: IpInfoClient<M>,
}

impl<M: MetricsPort + Clone> EnrichedIpIntelligenceEngine<M> {
    pub fn new_with_default_client(metrics: M) -> Self {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("Sentinelle-OSINT-Pro/2.0")
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            ip_api: IpApiClient::new(http.clone(), metrics.clone()),
            geojs: GeoJsClient::new(http.clone(), metrics.clone()),
            ipinfo: IpInfoClient::new(http, metrics),
        }
    }

    async fn gather_intelligence_async(&self, ip: IpAddr) -> Result<IpIntelligence, IpIntelError> {
        // Suppression des println! qui cassent l'interface TUI
        
        // Try multiple sources in sequence for better reliability
        
        // 1. Try IP-API first (most reliable)
        if let Ok(Some(mut intel)) = self.ip_api.fetch(ip).await {
            // Suppression des println! qui cassent l'interface TUI
            
            // 2. Enhance with GeoJS if needed
            if let Ok(Some(geojs_data)) = self.geojs.fetch(ip).await {
                // Suppression des println! qui cassent l'interface TUI
                if intel.country.is_none() { intel.country = geojs_data.country; }
                if intel.city.is_none() { intel.city = geojs_data.city; }
                if intel.latitude.is_none() { intel.latitude = geojs_data.latitude; }
                if intel.longitude.is_none() { intel.longitude = geojs_data.longitude; }
                if intel.isp.is_none() { intel.isp = geojs_data.isp; }
            }
            
            // 3. Try to enhance with IPInfo if available
            if let Ok(Some(ipinfo_data)) = self.ipinfo.fetch(ip).await {
                // Suppression des println! qui cassent l'interface TUI
                if intel.ptr.is_none() { intel.ptr = ipinfo_data.ptr; }
                if intel.timezone.is_none() { intel.timezone = ipinfo_data.timezone; }
            }
            
            return Ok(intel);
        }
        
        // 4. Fallback to GeoJS
        if let Ok(Some(intel)) = self.geojs.fetch(ip).await {
            // Suppression des println! qui cassent l'interface TUI
            return Ok(intel);
        }
        
        // 5. Last resort: IPInfo
        if let Ok(Some(intel)) = self.ipinfo.fetch(ip).await {
            // Suppression des println! qui cassent l'interface TUI
            return Ok(intel);
        }
        
        // Suppression des println! qui cassent l'interface TUI
        Err(IpIntelError::NoData)
    }
}

impl<M: MetricsPort + Clone + Send + Sync> IpIntelligencePort for EnrichedIpIntelligenceEngine<M> {
    fn analyze_ip(&self, ip: IpAddr) -> Result<IpIntelligence, IpIntelError> {
        // Input validation
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
            return Err(IpIntelError::InvalidIp(format!("IP address {} is not global", ip)));
        }
        
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

        // Use async runtime for intelligence gathering
        let rt = tokio::runtime::Runtime::new()
            .map_err(|_| IpIntelError::ProviderFailure)?;
        
        rt.block_on(self.gather_intelligence_async(ip))
    }
}
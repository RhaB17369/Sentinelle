use reqwest::Client;
use serde::Deserialize;
use sentinelle_domain::{IpIntelligence, IpIntelError, MetricsPort};
use std::net::IpAddr;
use std::time::Instant;

/// IPInfo.io client - provides comprehensive IP intelligence
#[derive(Debug)]
pub struct IpInfoClient<M: MetricsPort> {
    http: Client,
    metrics: M,
    api_token: Option<String>,
}

impl<M: MetricsPort> IpInfoClient<M> {
    pub fn new(http: Client, metrics: M) -> Self {
        Self { 
            http, 
            metrics,
            api_token: std::env::var("IPINFO_TOKEN").ok(),
        }
    }

    pub async fn fetch(&self, ip: IpAddr) -> Result<Option<IpIntelligence>, IpIntelError> {
        let mut url = format!("https://ipinfo.io/{ip}/json");
        
        // Add token if available for higher rate limits and more data
        if let Some(token) = &self.api_token {
            url.push_str(&format!("?token={}", token));
        }

        let start = Instant::now();
        let resp = self
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(8))
            .send()
            .await
            .map_err(|e| {
                eprintln!("IPInfo request failed: {}", e);
                IpIntelError::ProviderFailure
            })?;
        let elapsed = start.elapsed();

        let ok = resp.status().is_success();
        self.metrics.observe_provider("ipinfo", elapsed, ok);

        if !ok {
            eprintln!("IPInfo returned status: {}", resp.status());
            return Err(IpIntelError::ProviderFailure);
        }

        let body: IpInfoResponse = resp
            .json()
            .await
            .map_err(|e| {
                eprintln!("IPInfo JSON parsing failed: {}", e);
                IpIntelError::ProviderFailure
            })?;

        // Parse location coordinates
        let (latitude, longitude) = if let Some(loc) = &body.loc {
            let coords: Vec<&str> = loc.split(',').collect();
            if coords.len() == 2 {
                let lat = coords[0].parse::<f64>().ok();
                let lon = coords[1].parse::<f64>().ok();
                (lat, lon)
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        Ok(Some(IpIntelligence {
            ip,
            country: body.country.clone(),
            country_code: body.country.clone().map(|_| body.country.clone().unwrap_or_default()),
            region: body.region,
            city: body.city,
            latitude,
            longitude,
            timezone: body.timezone,
            isp: body.org.clone(),
            asn: body.org,
            ptr: body.hostname,
        }))
    }
}

#[derive(Debug, Deserialize)]
struct IpInfoResponse {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    loc: Option<String>, // "lat,lon" format
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    org: Option<String>, // Contains ASN and ISP info
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    postal: Option<String>,
}
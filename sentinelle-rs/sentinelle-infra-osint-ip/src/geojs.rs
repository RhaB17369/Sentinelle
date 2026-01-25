use reqwest::Client;
use serde::Deserialize;
use sentinelle_domain::{IpIntelligence, IpIntelError, MetricsPort};
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug)]
pub struct GeoJsClient<M: MetricsPort> {
    http: Client,
    metrics: M,
}

impl<M: MetricsPort> GeoJsClient<M> {
    pub fn new(http: Client, metrics: M) -> Self {
        Self { http, metrics }
    }

    pub async fn fetch(&self, ip: IpAddr) -> Result<Option<IpIntelligence>, IpIntelError> {
        let url = format!("https://get.geojs.io/v1/ip/geo/{ip}.json");

        let start = Instant::now();
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|_| IpIntelError::ProviderFailure)?;
        let elapsed = start.elapsed();

        let ok = resp.status().is_success();
        self.metrics.observe_provider("geojs", elapsed, ok);

        if !ok {
            return Err(IpIntelError::ProviderFailure);
        }

        let body: GeoResponse = resp
            .json()
            .await
            .map_err(|_| IpIntelError::ProviderFailure)?;

        Ok(Some(IpIntelligence {
            ip,
            country: body.country,
            country_code: body.country_code,
            region: body.region,
            city: body.city,
            latitude: body.latitude,
            longitude: body.longitude,
            timezone: body.timezone,
            isp: body.organization_name,
            asn: body.asn,
            ptr: None,
        }))
    }
}

#[derive(Debug, Deserialize)]
struct GeoResponse {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    organization_name: Option<String>,
    #[serde(default)]
    asn: Option<String>,
}
use reqwest::Client;
use serde::Deserialize;
use sentinelle_domain::{IpIntelligence, IpIntelError, MetricsPort};
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug)]
pub struct IpApiClient<M: MetricsPort> {
    http: Client,
    metrics: M,
}

impl<M: MetricsPort> IpApiClient<M> {
    pub fn new(http: Client, metrics: M) -> Self {
        Self { http, metrics }
    }

    pub async fn fetch(&self, ip: IpAddr) -> Result<Option<IpIntelligence>, IpIntelError> {
        let url = format!(
            "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,as,query"
        );

        let start = Instant::now();
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|_| IpIntelError::ProviderFailure)?;
        let elapsed = start.elapsed();

        let ok = resp.status().is_success();
        self.metrics.observe_provider("ip-api", elapsed, ok);

        if !ok {
            return Err(IpIntelError::ProviderFailure);
        }

        let body: ApiResponse = resp
            .json()
            .await
            .map_err(|_| IpIntelError::ProviderFailure)?;

        if body.status == "success" {
            Ok(Some(IpIntelligence {
                ip,
                country: body.country,
                country_code: body.country_code,
                region: body.region_name,
                city: body.city,
                latitude: body.lat,
                longitude: body.lon,
                timezone: body.timezone,
                isp: body.isp,
                asn: body.as_field,
                ptr: None,
            }))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    status: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(rename = "countryCode")]
    #[serde(default)]
    country_code: Option<String>,
    #[serde(rename = "regionName")]
    #[serde(default)]
    region_name: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(rename = "as")]
    #[serde(default)]
    as_field: Option<String>,
}
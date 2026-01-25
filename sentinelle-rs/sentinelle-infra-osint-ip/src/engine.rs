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
    pub fn new(http: Client, metrics: M) -&gt; Self {
        let ip_api = IpApiClient::new(http.clone(), metrics.clone());
        let geojs = GeoJsClient::new(http, metrics);
        Self { ip_api, geojs }
    }
}

impl&lt;M: MetricsPort + Clone + Send + Sync&gt; IpIntelligencePort for CompositeIpIntelligence&lt;M&gt; {
    fn analyze_ip(&self, ip: IpAddr) -&gt; Result&lt;IpIntelligence, IpIntelError&gt; {
        // On reste sync au niveau du port, on utilise un runtime local tokio
        let rt = tokio::runtime::Runtime::new().map_err(|_| IpIntelError::ProviderFailure)?;

        rt.block_on(async {
            // 1) ip-api
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
        })
    }
}
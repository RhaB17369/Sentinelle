#![deny(warnings)]

use phonenumber::{Mode, country, parse};
use reqwest::Client;
use sentinelle_domain::{
    PhoneIntelligencePort, PhoneIntel, PhoneIntelError, PhoneNumber, GpsLocation,
};
use std::env;
use std::time::Duration;

#[derive(Debug)]
pub struct PhoneIntelEngine {
    http: Client,
    opencage_key: Option<String>,
}

impl PhoneIntelEngine {
    pub fn new(opencage_key: Option<String>) -&gt; Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http client");
        let key = opencage_key.or_else(|| env::var("OPENCAGE_API_KEY").ok());
        Self { http, opencage_key: key }
    }

    async fn geocode(
        &self,
        location: &str,
        country_code: Option&lt;&amp;str&gt;,
    ) -&gt; (Option&lt;GpsLocation&gt;, Option&lt;String&gt;) {
        let key = match &self.opencage_key {
            Some(k) =&gt; k,
            None =&gt; return (None, Some("OPENCAGE_API_KEY not configured".to_string())),
        };

        let url = "https://api.opencagedata.com/geocode/v1/json";
        let mut params = vec![
            ("q", location.to_string()),
            ("key", key.to_string()),
            ("limit", "1".to_string()),
        ];
        if let Some(cc) = country_code {
            params.push(("countrycode", cc.to_lowercase()));
        }

        match self.http.get(url).query(&params).send().await {
            Ok(resp) =&gt; {
                if !resp.status().is_success() {
                    return (None, Some(format!("OpenCage API Error: {}", resp.status())));
                }
                let json = match resp.json::<serde_json::Value>().await {
                    Ok(v) =&gt; v,
                    Err(e) =&gt; return (None, Some(format!("OpenCage parse error: {e}"))),
                };
                if let Some(first) = json.get("results").and_then(|r| r.get(0)) {
                    if let Some(geom) = first.get("geometry") {
                        if let (Some(lat), Some(lng)) =
                            (geom.get("lat"), geom.get("lng"))
                        {
                            if let (Some(lat_f), Some(lng_f)) =
                                (lat.as_f64(), lng.as_f64())
                            {
                                return (Some(GpsLocation { lat: lat_f, lng: lng_f }), None);
                            }
                        }
                    }
                }
                (None, Some("No results found for this location".to_string()))
            }
            Err(e) =&gt; (None, Some(format!("HTTP error: {e}"))),
        }
    }

    async fn analyze_async(&self, phone: PhoneNumber) -&gt; Result&lt;PhoneIntel, PhoneIntelError&gt; {
        let raw = phone.as_str();

        // Essaye d'inférer le pays à partir du préfixe (+33, +1, etc.) en mode international.
        let parsed = parse(None, raw).map_err(|_| PhoneIntelError::InvalidPhone(raw.to_string()))?;

        let is_valid = phonenumber::is_valid(&parsed);
        if !is_valid {
            return Ok(PhoneIntel {
                phone_number: phone,
                is_valid: false,
                country: None,
                region: None,
                number_type: None,
                carrier: None,
                location: None,
                gps_coordinates: None,
                geocoding_error: None,
                error: Some("Invalid phone number format".to_string()),
            });
        }

        let region_code = country::id(&parsed).map(|c| c.alpha2().to_string());
        let number_type = format!("{:?}", phonenumber::number_type(&parsed));

        // phonenumber crate ne fournit pas directement carrier, on laisse ce champ à None.
        let carrier = None;

        // Description régionale approximative (on peut utiliser 'national' mode pour certaines heuristiques)
        let region = None::<String>;
        let location = None::<String>;

        // Géocodage via OpenCage si possible (en utilisant région + pays si on en avait,
        // ici on se contente du pays pour une première version).
        let country_full = region_code.clone();
        let (gps, geo_err) = if let Some(ref cc) = country_full {
            self.geocode(cc, region_code.as_deref()).await
        } else {
            (None, Some("No country code for geocoding".to_string()))
        };

        Ok(PhoneIntel {
            phone_number: phone,
            is_valid: true,
            country: region_code,
            region,
            number_type: Some(number_type),
            carrier,
            location,
            gps_coordinates: gps,
            geocoding_error: geo_err,
            error: None,
        })
    }
}

impl PhoneIntelligencePort for PhoneIntelEngine {
    fn analyze(&self, phone: PhoneNumber) -&gt; Result&lt;PhoneIntel, PhoneIntelError&gt; {
        let rt = tokio::runtime::Runtime::new().map_err(|_| PhoneIntelError::UpstreamFailure)?;
        rt.block_on(self.analyze_async(phone))
    }
}
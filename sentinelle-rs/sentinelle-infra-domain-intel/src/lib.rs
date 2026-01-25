#![deny(warnings)]

use reqwest::Client;
use sentinelle_domain::{
    DomainIntelligencePort, DomainIntel, DomainIntelError,
    WhoisData, DnsRecords, SslData, HttpData,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use whois_rust::{WhoIs, WhoIsLookupOptions};

#[derive(Debug)]
pub struct DomainIntelEngine {
    http: Client,
}

impl DomainIntelEngine {
    pub fn new() -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http client");
        Self { http }
    }

    fn validate_domain(domain: &str) -> bool {
        // Filtre minimal, les contrôles plus poussés peuvent être ajoutés si nécessaire
        !domain.is_empty() && domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    }

    async fn run_whois(&self, domain: &str) -> Option<WhoisData> {
        let whois = WhoIs::from_path("/etc/whois.conf").unwrap_or_else(|_| WhoIs::default());
        let opts = WhoIsLookupOptions::from_string(domain.to_string()).ok()?;

        let raw = tokio::task::spawn_blocking(move || whois.lookup(opts).ok())
            .await
            .ok()
            .flatten()?;

        let text = raw.as_str();
        let registrar = extract_field(text, &["Registrar:", "registrar:"]);
        let creation_date = extract_field(text, &["Creation Date:", "created:"]);
        let expiration_date = extract_field(text, &["Registry Expiry Date:", "paid-till:"]);
        let org = extract_field(text, &["OrgName:", "org:", "Organization:"]);
        let country = extract_field(text, &["Country:", "country:"]);

        let name_servers = extract_multi_field(text, &["Name Server:", "nserver:"]);

        Some(WhoisData {
            registrar,
            creation_date,
            expiration_date,
            name_servers,
            org,
            country,
        })
    }

    async fn run_dns(&self, domain: &str) -> Option<DnsRecords> {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(3);
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts).ok()?;

        let a = resolver
            .lookup_ip(domain)
            .await
            .ok()
            .map(|resp| resp.iter().map(|ip| ip.to_string()).collect())
            .unwrap_or_else(Vec::new);

        let mx = resolver
            .mx_lookup(domain)
            .await
            .ok()
            .map(|resp| resp.iter().map(|mx| mx.exchange().to_string()).collect())
            .unwrap_or_else(Vec::new);

        let ns = resolver
            .ns_lookup(domain)
            .await
            .ok()
            .map(|resp| resp.iter().map(|ns| ns.to_string()).collect())
            .unwrap_or_else(Vec::new);

        let txt = resolver
            .txt_lookup(domain)
            .await
            .ok()
            .map(|resp| {
                resp.iter()
                    .map(|txt| {
                        txt.txt_data()
                            .iter()
                            .map(|b| String::from_utf8_lossy(b).to_string())
                            .collect::<String>()
                    })
                    .collect()
            })
            .unwrap_or_else(Vec::new);

        Some(DnsRecords { a, mx, ns, txt })
    }

    async fn run_ssl(&self, domain: &str) -> Option<SslData> {
        use rustls::{ClientConfig, RootCertStore};
        use std::sync::Arc;
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::pki_types::ServerName;
        use webpki_roots::TLS_SERVER_ROOTS;
        use x509_parser::prelude::*;

        // Construire une config TLS avec les racines publiques (webpki-roots)
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| ta.to_trust_anchor()));

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        let addr = format!("{domain}:443");
        let tcp = TcpStream::connect(addr).await.ok()?;

        let server_name = ServerName::try_from(domain.to_string()).ok()?;
        let mut tls = connector.connect(server_name, tcp).await.ok()?;

        // Récupérer les certificats du pair
        let peer_certs = tls
            .get_ref()
            .1
            .peer_certificates()
            .to_vec();

        let first = peer_certs.first()?;

        // Parser le certificat en DER avec x509-parser
        let (_, x509) = X509Certificate::from_der(first.as_ref()).ok()?;

        let mut subject = HashMap::new();
        if let Some(cn) = x509.subject().iter_common_name().next() {
            if let Ok(cn_str) = cn.as_str() {
                subject.insert("commonName".to_string(), cn_str.to_string());
            }
        }

        let mut issuer = HashMap::new();
        if let Some(cn) = x509.issuer().iter_common_name().next() {
            if let Ok(cn_str) = cn.as_str() {
                issuer.insert("commonName".to_string(), cn_str.to_string());
            }
        }

        let not_after = x509.validity().not_after.to_rfc2822().ok();

        Some(SslData {
            subject,
            issuer,
            not_after,
        })
    }

    async fn run_http(&self, domain: &str) -> Option<HttpData> {
        let url = format!("https://{domain}");
        let resp = self.http.get(&url).send().await.ok()?;

        let status_code = resp.status().as_u16();
        let headers = resp.headers();
        let server = headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let powered_by = headers
            .get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        Some(HttpData {
            status_code,
            server,
            powered_by,
        })
    }

    async fn analyze_async(&self, domain: &str) -> Result<DomainIntel, DomainIntelError> {
        use chrono::Utc;

        if !Self::validate_domain(domain) {
            return Err(DomainIntelError::InvalidDomain(domain.to_string()));
        }

        let ts = Utc::now().to_rfc3339();

        let whois_fut = self.run_whois(domain);
        let dns_fut = self.run_dns(domain);
        let ssl_fut = self.run_ssl(domain);
        let http_fut = self.run_http(domain);

        let (whois, dns, ssl, http) = tokio::join!(whois_fut, dns_fut, ssl_fut, http_fut);

        Ok(DomainIntel {
            domain: domain.to_string(),
            timestamp: ts,
            whois,
            dns,
            ssl,
            http,
        })
    }
}

impl DomainIntelligencePort for DomainIntelEngine {
    fn analyze(&self, domain: &str) -> Result<DomainIntel, DomainIntelError> {
        let rt = tokio::runtime::Runtime::new().map_err(|_| DomainIntelError::UpstreamFailure)?;
        rt.block_on(self.analyze_async(domain))
    }
}

fn extract_field(text: &str, keys: &[&str]) -> Option<String> {
    for key in keys {
        for line in text.lines() {
            if line.to_lowercase().starts_with(&key.to_lowercase()) {
                let value = line.splitn(2, ':').nth(1)?.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn extract_multi_field(text: &str, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for key in keys {
        for line in text.lines() {
            if line.to_lowercase().starts_with(&key.to_lowercase()) {
                let value = line.splitn(2, ':').nth(1).unwrap_or("").trim();
                if !value.is_empty() {
                    out.push(value.to_string());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[derive(Debug, Deserialize)]
struct _Placeholder {}
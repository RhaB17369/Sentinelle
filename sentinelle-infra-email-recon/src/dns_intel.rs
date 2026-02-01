use sentinelle_domain::DnsProviderHint;
use std::time::Duration;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// Récupération DNS avancée (MX, SPF, DMARC, DKIM) et inférence des fournisseurs.
#[derive(Debug)]
pub struct DnsIntelClient {
    resolver: TokioAsyncResolver,
}

#[derive(Debug, thiserror::Error)]
pub enum DnsIntelError {
    #[error("resolver init error")]
    Init,
    #[error("lookup error")]
    Lookup,
}

impl DnsIntelClient {
    pub fn new() -> Result<Self, DnsIntelError> {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);
        Ok(Self { resolver })
    }

    pub async fn gather(&self, domain: &str) -> Result<DnsProviderHint, DnsIntelError> {
        let mx_hosts = self.fetch_mx(domain).await.unwrap_or_default();
        let spf_record = self.fetch_spf(domain).await.unwrap_or(None);
        let dmarc_record = self.fetch_dmarc(domain).await.unwrap_or(None);
        let dkim_selectors = self.guess_dkim(domain, &["default", "selector1", "selector2"]).await;

        let inferred_providers = infer_providers(&mx_hosts, spf_record.as_deref());

        Ok(DnsProviderHint {
            domain: domain.to_string(),
            mx_hosts,
            spf_record,
            dmarc_record,
            dkim_selectors,
            inferred_providers,
        })
    }

    async fn fetch_mx(&self, domain: &str) -> Result<Vec<String>, DnsIntelError> {
        let response = self
            .resolver
            .mx_lookup(domain)
            .await
            .map_err(|_| DnsIntelError::Lookup)?;
        let mut hosts: Vec<String> = response
            .iter()
            .map(|mx| mx.exchange().to_string())
            .collect();
        hosts.sort();
        hosts.dedup();
        Ok(hosts)
    }

    async fn fetch_spf(&self, domain: &str) -> Result<Option<String>, DnsIntelError> {
        let response = self
            .resolver
            .txt_lookup(domain)
            .await
            .map_err(|_| DnsIntelError::Lookup)?;
        for txt in response.iter() {
            let txt_data: String = txt
                .txt_data()
                .iter()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .collect();
            if txt_data.to_lowercase().starts_with("v=spf1") {
                return Ok(Some(txt_data));
            }
        }
        Ok(None)
    }

    async fn fetch_dmarc(&self, domain: &str) -> Result<Option<String>, DnsIntelError> {
        let name = format!("_dmarc.{domain}");
        let response = self
            .resolver
            .txt_lookup(name.as_str())
            .await
            .map_err(|_| DnsIntelError::Lookup)?;
        for txt in response.iter() {
            let txt_data: String = txt
                .txt_data()
                .iter()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .collect();
            if txt_data.to_lowercase().starts_with("v=dmarc1") {
                return Ok(Some(txt_data));
            }
        }
        Ok(None)
    }

    async fn guess_dkim(&self, domain: &str, selectors: &[&str]) -> Vec<String> {
        let mut found = Vec::new();
        for sel in selectors {
            let name = format!("{sel}._domainkey.{domain}");
            if self.resolver.txt_lookup(name.as_str()).await.is_ok() {
                found.push((*sel).to_string());
            }
        }
        found
    }
}

/// Heuristiques d'inférence de fournisseurs à partir des MX / SPF.
fn infer_providers(mx_hosts: &[String], spf: Option<&str>) -> Vec<String> {
    let mut providers = Vec::new();
    let lower_mx: Vec<String> = mx_hosts.iter().map(|h| h.to_lowercase()).collect();
    let spf_l = spf.unwrap_or("").to_lowercase();

    // Google Workspace
    if lower_mx.iter().any(|h| h.contains("aspmx.l.google.com"))
        || spf_l.contains("include:_spf.google.com")
    {
        providers.push("google-workspace".to_string());
    }

    // Microsoft 365 / Exchange Online
    if lower_mx
        .iter()
        .any(|h| h.contains(".protection.outlook.com") || h.ends_with(".outlook.com"))
        || spf_l.contains("include:spf.protection.outlook.com")
    {
        providers.push("microsoft-365".to_string());
    }

    // Proton
    if lower_mx
        .iter()
        .any(|h| h.contains("protonmail.ch") || h.contains("protonmail.com"))
    {
        providers.push("protonmail".to_string());
    }

    // Fastmail
    if lower_mx
        .iter()
        .any(|h| h.contains("fastmail.com") || h.contains("messagingengine.com"))
    {
        providers.push("fastmail".to_string());
    }

    providers.sort();
    providers.dedup();
    providers
}
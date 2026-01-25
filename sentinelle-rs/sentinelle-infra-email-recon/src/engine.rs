use crate::{ct_logs::CtLogsClient, dns_intel::DnsIntelClient, archives::ArchivesClient};
use reqwest::Client;
use sentinelle_domain::{
    Email, EmailReconPort, EmailReconResult, EmailReconError, DnsProviderHint,
};
use std::net::IpAddr;

/// Implémentation gouvernementale de EmailReconPort:
/// - CT logs via crt.sh
/// - DNS avancé (MX/SPF/DMARC/DKIM, inférence de fournisseurs)
/// - Archives publiques (Wayback, Common Crawl)
#[derive(Debug)]
pub struct EmailReconEngine {
    http: Client,
}

impl EmailReconEngine {
    pub fn new() -&gt; Self {
        let http = Client::new();
        Self { http }
    }

    fn domain_from_email(&self, email: &Email) -&gt; Option&lt;String&gt; {
        email
            .as_str()
            .split('@')
            .nth(1)
            .map(|d| d.to_string())
    }

    async fn recon_async(&self, email: Email) -&gt; Result&lt;EmailReconResult, EmailReconError&gt; {
        let domain = self
            .domain_from_email(&email)
            .ok_or_else(|| EmailReconError::InvalidEmail(email.as_str().to_string()))?;

        // DNS intelligence
        let dns_client = DnsIntelClient::new().map_err(|_| EmailReconError::UpstreamFailure)?;
        let dns_hint: Option&lt;DnsProviderHint&gt; = match dns_client.gather(&domain).await {
            Ok(h) =&gt; Some(h),
            Err(_) =&gt; None,
        };

        // CT logs
        let ct_client = CtLogsClient::new(self.http.clone());
        let ct_domains = ct_client
            .fetch_domains(&domain)
            .await
            .unwrap_or_default();

        // Archives
        let archives_client = ArchivesClient::new(self.http.clone());
        let archive_hits = archives_client
            .wayback_count(&domain)
            .await
            .unwrap_or(0);
        let common_crawl_hits = archives_client
            .common_crawl_count(&domain)
            .await
            .unwrap_or(0);

        // DNS passif: IPs associées (ici laissé vide, mais on pourrait enrichir via d'autres sources).
        let related_ips: Vec&lt;IpAddr&gt; = Vec::new();

        Ok(EmailReconResult {
            email,
            domain,
            dns: dns_hint,
            ct_domains,
            archive_hits,
            common_crawl_hits,
            related_ips,
        })
    }
}

impl EmailReconPort for EmailReconEngine {
    fn recon(&self, email: Email) -&gt; Result&lt;EmailReconResult, EmailReconError&gt; {
        let rt = tokio::runtime::Runtime::new().map_err(|_| EmailReconError::UpstreamFailure)?;
        rt.block_on(self.recon_async(email))
    }
}
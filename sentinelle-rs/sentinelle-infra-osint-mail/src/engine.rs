use crate::probe::{MailServiceProbe, ProbeError, GravatarProbe};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use sentinelle_domain::{
    Email, MailIntelligencePort, MailScanError, MailScanSummary, MailServiceResult,
};
use std::sync::Arc;

/// Implémentation Rust de MailIntelligencePort, remplaçant MailEngine Python.
/// - Pas d'I/O console
/// - Pas de CSV
/// - Pas de state global
/// - Concurrence contrôlée via FuturesUnordered
#[derive(Debug)]
pub struct MailOsintEngine {
    http: Client,
    probes: Vec<Arc<dyn MailServiceProbe>>,
}

impl MailOsintEngine {
    /// Configure un moteur avec un ensemble de probes réels.
    pub fn new_with_default_probes() -> Self {
        let http = Client::new();
        let probes: Vec<Arc<dyn MailServiceProbe>> = vec![
            Arc::new(GravatarProbe::default()),
        ];

        Self { http, probes }
    }

    pub fn new(http: Client, probes: Vec<Arc<dyn MailServiceProbe>>) -> Self {
        Self { http, probes }
    }
}

    pub fn new(http: Client, probes: Vec<Arc<dyn MailServiceProbe>>) -> Self {
        Self { http, probes }
    }
}

impl MailOsintEngine {
    async fn run_async(&self, email: Email) -> Result<MailScanSummary, MailScanError> {
        if self.probes.is_empty() {
            return Err(MailScanError::ScanFailed);
        }

        let mut tasks = FuturesUnordered::new();

        for probe in &self.probes {
            let client = self.http.clone();
            let email_clone = email.clone();
            let probe_clone = Arc::clone(probe);

            tasks.push(async move {
                let base = MailServiceResult {
                    service_name: probe_clone.name().to_string(),
                    exists: false,
                    rate_limited: false,
                    error: true,
                    email_recovery: None,
                    phone_number: None,
                    full_name: None,
                    created_at: None,
                };

                match probe_clone.probe(&client, &email_clone).await {
                    Ok(res) => res,
                    Err(ProbeError::Http | ProbeError::UnexpectedResponse) => base,
                }
            });
        }

        let mut services = Vec::with_capacity(self.probes.len());
        while let Some(res) = tasks.next().await {
            services.push(res);
        }

        Ok(MailScanSummary { email, services })
    }
}

impl MailIntelligencePort for MailOsintEngine {
    fn scan_email(&self, email: Email) -> Result<MailScanSummary, MailScanError> {
        let rt = tokio::runtime::Runtime::new().map_err(|_| MailScanError::ScanFailed)?;
        rt.block_on(self.run_async(email))
    }
}
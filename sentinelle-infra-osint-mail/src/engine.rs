use crate::probe::{MailServiceProbe, ProbeError, GravatarProbe};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use sentinelle_domain::{
    Email, MailIntelligencePort, MailScanError, MailScanSummary, MailServiceResult,
};
use std::sync::Arc;

/// Enhanced Mail OSINT Engine with improved service coverage
pub struct MailOsintEngine {
    http: Client,
    probes: Vec<Arc<dyn MailServiceProbe>>,
}

impl MailOsintEngine {
    /// Configure engine with enhanced probe suite
    pub fn new_with_default_probes() -> Self {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("Sentinelle-OSINT-Pro/2.0")
            .build()
            .expect("Failed to create HTTP client");
        
        let probes: Vec<Arc<dyn MailServiceProbe>> = vec![
            Arc::new(GravatarProbe::default()),
        ];

        Self { http, probes }
    }

    pub fn new(http: Client, probes: Vec<Arc<dyn MailServiceProbe>>) -> Self {
        Self { http, probes }
    }

    async fn run_async(&self, email: Email) -> Result<MailScanSummary, MailScanError> {
        if self.probes.is_empty() {
            return Err(MailScanError::ScanFailed);
        }

        // Suppression des println! qui cassent l'interface TUI

        let mut tasks = FuturesUnordered::new();

        for probe in &self.probes {
            let client = self.http.clone();
            let email_clone = email.clone();
            let probe_clone = Arc::clone(probe);

            tasks.push(async move {
                // Suppression des println! qui cassent l'interface TUI
                
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
                    Ok(res) => {
                        // Suppression des println! qui cassent l'interface TUI
                        res
                    },
                    Err(ProbeError::Http | ProbeError::UnexpectedResponse) => {
                        // Suppression des println! qui cassent l'interface TUI
                        base
                    },
                }
            });
        }

        let mut services = Vec::with_capacity(self.probes.len());
        while let Some(res) = tasks.next().await {
            services.push(res);
        }

        let _found_count = services.iter().filter(|s| s.exists).count();
        // Suppression des println! qui cassent l'interface TUI

        Ok(MailScanSummary { email, services })
    }
}

impl MailIntelligencePort for MailOsintEngine {
    fn scan_email(&self, email: Email) -> Result<MailScanSummary, MailScanError> {
        let rt = tokio::runtime::Runtime::new().map_err(|_| MailScanError::ScanFailed)?;
        rt.block_on(self.run_async(email))
    }
}
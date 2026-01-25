use crate::probe::{SocialServiceProbe, SocialProbeError, MockSocialProbe};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use sentinelle_domain::{
    SocialIntelligencePort, SocialScanResult, SocialScanError, SocialTarget, SocialAccount,
};
use std::sync::Arc;

/// Implémentation Rust de SocialIntelligencePort, remplaçant SocialEngine Python.
/// - Pas de config globale mutée
/// - Pas d'I/O console, pas d'input utilisateur
/// - Chaque "site" est un SocialServiceProbe typé
#[derive(Debug)]
pub struct SocialOsintEngine {
    http: Client,
    probes: Vec<Arc<dyn SocialServiceProbe>>,
}

impl SocialOsintEngine {
    pub fn new_with_default_probes() -> Self {
        let http = Client::new();
        let probes: Vec<Arc<dyn SocialServiceProbe>> = vec![Arc::new(MockSocialProbe::default())];

        Self { http, probes }
    }

    pub fn new(http: Client, probes: Vec<Arc<dyn SocialServiceProbe>>) -> Self {
        Self { http, probes }
    }
}

impl SocialOsintEngine {
    async fn run_async(
        &self,
        target: SocialTarget,
    ) -> Result<SocialScanResult, SocialScanError> {
        if self.probes.is_empty() {
            return Err(SocialScanError::External);
        }

        let mut tasks = FuturesUnordered::new();

        for probe in &self.probes {
            let client = self.http.clone();
            let target_clone = target.clone();
            let probe_clone = Arc::clone(probe);

            tasks.push(async move {
                let base = SocialAccount {
                    site_name: probe_clone.name().to_string(),
                    profile_url: None,
                    status: sentinelle_domain::AccountStatus::Error,
                };

                match probe_clone.probe(&client, &target_clone).await {
                    Ok(acc) => acc,
                    Err(SocialProbeError::Http | SocialProbeError::UnexpectedResponse) => base,
                }
            });
        }

        let mut accounts = Vec::with_capacity(self.probes.len());
        while let Some(acc) = tasks.next().await {
            accounts.push(acc);
        }

        Ok(SocialScanResult {
            target,
            accounts,
            ai_analysis: None,
        })
    }
}

impl SocialIntelligencePort for SocialOsintEngine {
    fn scan(&self, target: SocialTarget) -> Result<SocialScanResult, SocialScanError> {
        let rt = tokio::runtime::Runtime::new().map_err(|_| SocialScanError::External)?;
        rt.block_on(self.run_async(target))
    }
}
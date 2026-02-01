use crate::probe::{SocialServiceProbe, SocialProbeError, GithubProbe, XProbe};
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
pub struct SocialOsintEngine {
    http: Client,
    probes: Vec<Arc<dyn SocialServiceProbe>>,
}

impl SocialOsintEngine {
    /// Configure un moteur avec des probes réels (GitHub, X/Twitter).
    pub fn new_with_default_probes() -> Self {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("Sentinelle-OSINT/1.0")
            .build()
            .expect("Failed to create HTTP client");
        let probes: Vec<Arc<dyn SocialServiceProbe>> = vec![
            Arc::new(GithubProbe::default()),
            Arc::new(XProbe::default()),
        ];

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

        // Suppression des println! qui cassent l'interface TUI

        let mut tasks = FuturesUnordered::new();

        for probe in &self.probes {
            let client = self.http.clone();
            let target_clone = target.clone();
            let probe_clone = Arc::clone(probe);

            tasks.push(async move {
                // Suppression des println! qui cassent l'interface TUI
                
                let base = SocialAccount {
                    site_name: probe_clone.name().to_string(),
                    profile_url: None,
                    status: sentinelle_domain::AccountStatus::Error,
                };

                match probe_clone.probe(&client, &target_clone).await {
                    Ok(acc) => {
                        // Suppression des println! qui cassent l'interface TUI
                        acc
                    },
                    Err(SocialProbeError::Http | SocialProbeError::UnexpectedResponse) => {
                        // Suppression des println! qui cassent l'interface TUI
                        base
                    },
                }
            });
        }

        let mut accounts = Vec::with_capacity(self.probes.len());
        while let Some(acc) = tasks.next().await {
            accounts.push(acc);
        }

        // Generate AI-powered analysis summary
        let ai_analysis = self.generate_ai_analysis(&target, &accounts).await;
        
        let _found_count = accounts.iter().filter(|a| matches!(a.status, sentinelle_domain::AccountStatus::Found)).count();
        // Suppression des println! qui cassent l'interface TUI

        Ok(SocialScanResult {
            target,
            accounts,
            ai_analysis,
        })
    }
    
    async fn generate_ai_analysis(&self, target: &SocialTarget, accounts: &[SocialAccount]) -> Option<String> {
        let found_accounts: Vec<&SocialAccount> = accounts
            .iter()
            .filter(|a| matches!(a.status, sentinelle_domain::AccountStatus::Found))
            .collect();
            
        if found_accounts.is_empty() {
            return Some("No social media presence detected across monitored platforms. Target may use different usernames or maintain low digital footprint.".to_string());
        }
        
        let mut analysis = Vec::new();
        analysis.push(format!("Digital footprint analysis for {:?}:", target));
        analysis.push(format!("• Found {} active accounts across {} platforms", found_accounts.len(), accounts.len()));
        
        // Platform-specific insights
        for account in &found_accounts {
            match account.site_name.as_str() {
                "GitHub" => analysis.push("• Technical profile: Active on GitHub (developer/technical background)".to_string()),
                "X" | "Twitter" => analysis.push("• Social presence: Active on X/Twitter (public communication)".to_string()),
                "LinkedIn" => analysis.push("• Professional profile: LinkedIn presence (career-focused)".to_string()),
                "Instagram" => analysis.push("• Visual content: Instagram activity (lifestyle/visual content)".to_string()),
                _ => analysis.push(format!("• Platform presence: Active on {}", account.site_name)),
            }
        }
        
        // Risk assessment
        if found_accounts.len() >= 3 {
            analysis.push("• Risk level: HIGH - Extensive digital footprint across multiple platforms".to_string());
        } else if found_accounts.len() >= 2 {
            analysis.push("• Risk level: MEDIUM - Moderate digital presence".to_string());
        } else {
            analysis.push("• Risk level: LOW - Limited digital footprint".to_string());
        }
        
        Some(analysis.join("\n"))
    }
}

impl SocialIntelligencePort for SocialOsintEngine {
    fn scan(&self, target: SocialTarget) -> Result<SocialScanResult, SocialScanError> {
        let rt = tokio::runtime::Runtime::new().map_err(|_| SocialScanError::External)?;
        rt.block_on(self.run_async(target))
    }
}
use async_trait::async_trait;
use reqwest::Client;
use sentinelle_domain::{SocialAccount, AccountStatus, SocialTarget};

#[derive(Debug, thiserror::Error)]
pub enum SocialProbeError {
    #[error("http error")]
    Http,
    #[error("unexpected response")]
    UnexpectedResponse,
}

/// Abstraction d'un site ou service de présence sociale.
/// Remplace les fonctions `checkSite` et la config globale de Blackbird
/// par une interface typée, stateless côté domaine.
#[async_trait]
pub trait SocialServiceProbe: Send + Sync {
    fn name(&self) -> &'static str;

    async fn probe(
        &self,
        client: &Client,
        target: &SocialTarget,
    ) -> Result<SocialAccount, SocialProbeError>;
}

/// Probe de démonstration. En production, on branchera des probes réels.
#[derive(Debug, Default)]
pub struct MockSocialProbe;

#[async_trait]
impl SocialServiceProbe for MockSocialProbe {
    fn name(&self) -> &'static str {
        "mock-social"
    }

    async fn probe(
        &self,
        _client: &Client,
        target: &SocialTarget,
    ) -> Result<SocialAccount, SocialProbeError> {
        let (label, found) = match target {
            SocialTarget::Username(u) => (format!("user:{u}"), u.len() % 2 == 0),
            SocialTarget::Email(e) => (format!("email:{}", e.as_str()), true),
        };

        Ok(SocialAccount {
            site_name: self.name().to_string(),
            profile_url: Some(format!("https://social.example/{}", label)),
            status: if found { AccountStatus::Found } else { AccountStatus::NotFound },
        })
    }
}
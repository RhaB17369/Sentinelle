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
#[async_trait]
pub trait SocialServiceProbe: Send + Sync {
    fn name(&self) -> &'static str;

    async fn probe(
        &self,
        client: &Client,
        target: &SocialTarget,
    ) -> Result<SocialAccount, SocialProbeError>;
}

/// Probe réelle : GitHub.
/// Vérifie l'existence d'un profil public à https://github.com/{username}.
#[derive(Debug, Default)]
pub struct GithubProbe;

#[async_trait]
impl SocialServiceProbe for GithubProbe {
    fn name(&self) -> &'static str {
        "github"
    }

    async fn probe(
        &self,
        client: &Client,
        target: &SocialTarget,
    ) -> Result<SocialAccount, SocialProbeError> {
        let username = match target {
            SocialTarget::Username(u) => u,
            SocialTarget::Email(_) => {
                // GitHub ne permet pas une résolution directe par email via HTTP public.
                return Ok(SocialAccount {
                    site_name: self.name().to_string(),
                    profile_url: None,
                    status: AccountStatus::NotFound,
                });
            }
        };

        let url = format!("https://github.com/{username}");
        let resp = client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| {
                eprintln!("GitHub request failed: {}", e);
                SocialProbeError::Http
            })?;
        let status = resp.status();

        let (acc_status, profile_url) = if status.is_success() {
            (AccountStatus::Found, Some(url))
        } else if status.as_u16() == 404 {
            (AccountStatus::NotFound, None)
        } else {
            eprintln!("GitHub returned unexpected status: {}", status);
            (AccountStatus::Error, None)
        };

        Ok(SocialAccount {
            site_name: self.name().to_string(),
            profile_url,
            status: acc_status,
        })
    }
}

/// Probe réelle : X (Twitter).
/// Vérifie l'existence d'un profil public à https://x.com/{username}.
#[derive(Debug, Default)]
pub struct XProbe;

#[async_trait]
impl SocialServiceProbe for XProbe {
    fn name(&self) -> &'static str {
        "x"
    }

    async fn probe(
        &self,
        client: &Client,
        target: &SocialTarget,
    ) -> Result<SocialAccount, SocialProbeError> {
        let username = match target {
            SocialTarget::Username(u) => u,
            SocialTarget::Email(_) => {
                return Ok(SocialAccount {
                    site_name: self.name().to_string(),
                    profile_url: None,
                    status: AccountStatus::NotFound,
                });
            }
        };

        let url = format!("https://x.com/{username}");
        let resp = client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| {
                eprintln!("X/Twitter request failed: {}", e);
                SocialProbeError::Http
            })?;
        let status = resp.status();

        let (acc_status, profile_url) = if status.is_success() {
            (AccountStatus::Found, Some(url))
        } else if status.as_u16() == 404 {
            (AccountStatus::NotFound, None)
        } else {
            eprintln!("X/Twitter returned unexpected status: {}", status);
            (AccountStatus::Error, None)
        };

        Ok(SocialAccount {
            site_name: self.name().to_string(),
            profile_url,
            status: acc_status,
        })
    }
}
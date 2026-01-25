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
        let resp = client.get(&url).send().await.map_err(|_| SocialProbeError::Http)?;
        let status = resp.status();

        let (acc_status, profile_url) = if status.is_success() {
            (AccountStatus::Found, Some(url))
        } else if status.as_u16() == 404 {
            (AccountStatus::NotFound, None)
        } else {
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
        let resp = client.get(&url).send().await.map_err(|_| SocialProbeError::Http)?;
        let status = resp.status();

        let (acc_status, profile_url) = if status.is_success() {
            (AccountStatus::Found, Some(url))
        } else if status.as_u16() == 404 {
            (AccountStatus::NotFound, None)
        } else {
            (AccountStatus::Error, None)
        };

        Ok(SocialAccount {
            site_name: self.name().to_string(),
            profile_url,
            status: acc_status,
        })
    }
}
///   * 200 => FOUND
///   * 404 => NOT_FOUND
///   * autre => ERROR
#[derive(Debug, Default)]
pub struct GitHubProbe;

#[async_trait]
impl SocialServiceProbe for GitHubProbe {
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
                // On ne traite que les usernames pour ce probe.
                return Ok(SocialAccount {
                    site_name: self.name().to_string(),
                    profile_url: None,
                    status: AccountStatus::Error,
                });
            }
        };

        let url = format!("https://github.com/{username}");
        let resp = client.get(&url).send().await.map_err(|_| SocialProbeError::Http)?;
        let status = resp.status();

        let account_status = if status.is_success() {
            AccountStatus::Found
        } else if status.as_u16() == 404 {
            AccountStatus::NotFound
        } else {
            AccountStatus::Error
        };

        Ok(SocialAccount {
            site_name: self.name().to_string(),
            profile_url: Some(url),
            status: account_status,
        })
    }
}
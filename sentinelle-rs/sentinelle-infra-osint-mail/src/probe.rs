use async_trait::async_trait;
use reqwest::Client;
use sentinelle_domain::{Email, MailServiceResult};

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("http error")]
    Http,
    #[error("unexpected response")]
    UnexpectedResponse,
}

/// Abstraction d'un "site" ou service testant l'existence d'un email.
/// Dans la version Python, chaque module holehe était un module dynamique.
/// Ici, on a une interface typée, extensible.
#[async_trait]
pub trait MailServiceProbe: Send + Sync {
    fn name(&self) -> &'static str;

    async fn probe(
        &self,
        client: &Client,
        email: &Email,
    ) -> Result<MailServiceResult, ProbeError>;
}

/// Exemple de probe "mock" pour démontrer le pattern.
/// En production, on implémentera un ensemble de probes réels.
#[derive(Debug, Default)]
pub struct MockProbe;

#[async_trait]
impl MailServiceProbe for MockProbe {
    fn name(&self) -> &'static str {
        "mock-service"
    }

    async fn probe(
        &self,
        _client: &Client,
        email: &Email,
    ) -> Result<MailServiceResult, ProbeError> {
        // Démo : considère que tout email se termine par "used"
        let exists = email.as_str().contains("used");

        Ok(MailServiceResult {
            service_name: self.name().to_string(),
            exists,
            rate_limited: false,
            error: false,
            email_recovery: None,
            phone_number: None,
            full_name: None,
            created_at: None,
        })
    }
}
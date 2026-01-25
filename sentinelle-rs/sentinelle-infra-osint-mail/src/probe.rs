use async_trait::async_trait;
use md5;
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
#[async_trait]
pub trait MailServiceProbe: Send + Sync {
    fn name(&self) -> &'static str;

    async fn probe(
        &self,
        client: &Client,
        email: &Email,
    ) -> Result<MailServiceResult, ProbeError>;
}

/// Probe réelle : vérifie la présence d'un avatar Gravatar pour l'email.
/// Gravatar est massivement utilisé et fournit un signal OSINT fiable
/// sur l'existence d'un compte lié à cet email.
#[derive(Debug, Default)]
pub struct GravatarProbe;

#[async_trait]
impl MailServiceProbe for GravatarProbe {
    fn name(&self) -> &'static str {
        "gravatar"
    }

    async fn probe(
        &self,
        client: &Client,
        email: &Email,
    ) -> Result<MailServiceResult, ProbeError> {
        // Gravatar utilise MD5 de l'email normalisé (trim + lowercase)
        let normalized = email.as_str().trim().to_lowercase();
        let hash = format!("{:x}", md5::compute(normalized.as_bytes()));
        let url = format!("https://www.gravatar.com/avatar/{hash}?d=404");

        let resp = client.head(&url).send().await.map_err(|_| ProbeError::Http)?;
        let status = resp.status();

        let (exists, error) = if status.is_success() {
            (true, false)
        } else if status.as_u16() == 404 {
            (false, false)
        } else {
            (false, true)
        };

        Ok(MailServiceResult {
            service_name: self.name().to_string(),
            exists,
            rate_limited: false,
            error,
            email_recovery: None,
            phone_number: None,
            full_name: None,
            created_at: None,
        })
    }
}

/// Probe réel : Gravatar.
/// Règle : si une image existe pour le hash MD5(email normalisé),
/// Gravatar renvoie un statut différent de 404.
/// - 200 => email associé à un avatar
/// - 404 => aucun avatar => on considère "non trouvé"
#[derive(Debug, Default)]
pub struct GravatarProbe;

impl GravatarProbe {
    fn gravatar_url(email: &Email) -> String {
        let normalized = email.as_str().trim().to_lowercase();
        let mut hasher = Md5::new();
        hasher.update(normalized.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        format!("https://www.gravatar.com/avatar/{hash}?d=404")
    }
}

#[async_trait]
impl MailServiceProbe for GravatarProbe {
    fn name(&self) -> &'static str {
        "gravatar"
    }

    async fn probe(
        &self,
        client: &Client,
        email: &Email,
    ) -> Result<MailServiceResult, ProbeError> {
        let url = Self::gravatar_url(email);
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|_| ProbeError::Http)?;

        let status = resp.status();
        let exists = status.is_success();
        let rate_limited = status.as_u16() == 429;

        Ok(MailServiceResult {
            service_name: self.name().to_string(),
            exists,
            rate_limited,
            error: !status.is_success() && !status.is_client_error() && !status.is_redirection(),
            email_recovery: None,
            phone_number: None,
            full_name: None,
            created_at: None,
        })
    }
}
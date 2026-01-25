use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

/// Interrogation des CT logs via l'API publique crt.sh.
/// Permet de récupérer les FQDN liés à un domaine, sans scraping HTML.
#[derive(Debug)]
pub struct CtLogsClient {
    http: Client,
}

impl CtLogsClient {
    pub fn new(http: Client) -> Self {
        Self { http }
    }

    pub async fn fetch_domains(&self, domain: &str) -> Result<Vec<String>, CtError> {
        let url = format!(
            "https://crt.sh/?q=%25.{domain}&output=json",
        );

        let resp = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|_| CtError::Http)?;

        if !resp.status().is_success() {
            return Err(CtError::Upstream);
        }

        let body = resp.text().await.map_err(|_| CtError::Upstream)?;

        // crt.sh renvoie parfois plusieurs objets JSON concatenés; on tente un parse ligne par ligne.
        let mut out = Vec::new();
        for line in body.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(rec) = serde_json::from_str::<CtRecord>(line) {
                if let Some(name) = rec.name_value {
                    // name_value peut contenir plusieurs lignes/entrées, on split
                    for part in name.split('\n') {
                        let trimmed = part.trim().to_string();
                        if !trimmed.is_empty() {
                            out.push(trimmed);
                        }
                    }
                }
            }
        }

        out.sort();
        out.dedup();
        Ok(out)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CtError {
    #[error("http error")]
    Http,
    #[error("upstream error")]
    Upstream,
}

#[derive(Debug, Deserialize)]
struct CtRecord {
    #[serde(default)]
    name_value: Option<String>,
}
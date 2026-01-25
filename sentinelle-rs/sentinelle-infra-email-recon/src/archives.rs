use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

/// Scraping passif via Archive.org (Wayback Machine) + Common Crawl index.
/// Pas de scraping HTML live, uniquement des index publics.
#[derive(Debug)]
pub struct ArchivesClient {
    http: Client,
}

#[derive(Debug, thiserror::Error)]
pub enum ArchivesError {
    #[error("http error")]
    Http,
    #[error("upstream error")]
    Upstream,
}

impl ArchivesClient {
    pub fn new(http: Client) -> Self {
        Self { http }
    }

    /// Nombre d'entrées dans Wayback Machine pour un domaine.
    pub async fn wayback_count(&self, domain: &str) -> Result<u64, ArchivesError> {
        let url = format!(
            "http://web.archive.org/cdx/search/cdx?url=*.{}&output=json&filter=statuscode:200&limit=1&showNumPages=true",
            domain
        );

        let resp = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .map_err(|_| ArchivesError::Http)?;

        if !resp.status().is_success() {
            return Err(ArchivesError::Upstream);
        }

        let body = resp.text().await.map_err(|_| ArchivesError::Upstream)?;
        // La première ligne JSON contient le nombre de pages ou total; on garde une estimation simple.
        // Exemple: [[ "urlkey", "timestamp", ...], ["com,example)/", "20200101000000", ...], ...]
        let lines: Vec<&str> = body.lines().collect();
        if lines.len() <= 1 {
            return Ok(0);
        }
        // On considère le nombre de lignes - 1 comme approximation.
        Ok((lines.len() - 1) as u64)
    }

    /// Nombre d'entrées dans Common Crawl pour un domaine (approximation via l'index courant).
    pub async fn common_crawl_count(&self, domain: &str) -> Result<u64, ArchivesError> {
        // Utilisation d'un index générique CC-MAIN-2023-14 (exemple).
        let url = format!(
            "http://index.commoncrawl.org/CC-MAIN-2023-14-index?url=*.{}&output=json&filter=status:200&showNumPages=true",
            domain
        );

        let resp = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .map_err(|_| ArchivesError::Http)?;

        if !resp.status().is_success() {
            return Err(ArchivesError::Upstream);
        }

        let body = resp.text().await.map_err(|_| ArchivesError::Upstream)?;
        // Comme pour Wayback, on calcule une approximation en fonction des lignes retournées.
        let lines: Vec<&str> = body.lines().collect();
        if lines.is_empty() {
            return Ok(0);
        }

        Ok(lines.len() as u64)
    }
}

#[derive(Debug, Deserialize)]
struct _CdxEntry {
    // placeholder pour d'éventuelles évolutions (non utilisé pour le comptage simple)
    urlkey: Option<String>,
}
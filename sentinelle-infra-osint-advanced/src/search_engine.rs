#![deny(warnings)]

use serde::{Deserialize, Serialize};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use thiserror::Error;

/// Descripteur minimal d'un moteur de recherche externe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEngineDescriptor {
    pub id: String,
    pub name: String,
    /// URL de base, ex: "https://www.google.com/search".
    pub base_url: String,
    /// Nom du paramètre de requête, ex: "q".
    pub query_param: String,
}

/// Résultat agrégé d'une requête multi-moteurs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchAggregateResult {
    pub query: String,
    pub engine_ids: Vec<String>,
}

#[derive(Debug, Error)]
pub enum SearchEngineError {
    #[error("http client error")]
    Http,
}

/// Moteur simple orchestrant plusieurs moteurs de recherche déclarés.
#[derive(Debug)]
pub struct SearchQueryEngine {
    client: Client,
    engines: Vec<SearchEngineDescriptor>,
}

impl SearchQueryEngine {
    pub fn new(client: Client, engines: Vec<SearchEngineDescriptor>) -> Self {
        Self { client, engines }
    }

    /// Constructeur pratique avec un client par défaut et aucun moteur déclaré.
    pub fn new_empty() -> Self {
        let client = Client::builder()
            .user_agent("Sentinelle-OSINT-Search/1.0")
            .build()
            .expect("failed to build reqwest client");
        Self {
            client,
            engines: Vec::new(),
        }
    }

    /// Effectue une requête "fire-and-forget" vers tous les moteurs déclarés.
    /// Cette implémentation ne parse pas encore les pages de résultats :
    /// elle se concentre sur l'orchestration concurrente.
    pub async fn search(&self, query: &str) -> Result<SearchAggregateResult, SearchEngineError> {
        if self.engines.is_empty() {
            return Ok(SearchAggregateResult {
                query: query.to_string(),
                engine_ids: Vec::new(),
            });
        }

        let mut tasks = FuturesUnordered::new();

        for engine in &self.engines {
            let engine_id = engine.id.clone();
            let base_url = engine.base_url.clone();
            let query_param = engine.query_param.clone();
            let client = self.client.clone();
            let q = query.to_string();

            tasks.push(async move {
                let url = reqwest::Url::parse_with_params(
                    &base_url,
                    &[(query_param.as_str(), q.as_str())],
                );

                let url = match url {
                    Ok(u) => u,
                    Err(_) => {
                        return None;
                    }
                };

                let res = client.get(url).send().await;
                match res {
                    Ok(_) => Some(engine_id),
                    Err(_) => None,
                }
            });
        }

        let mut engine_ids = Vec::new();
        while let Some(maybe_id) = tasks.next().await {
            if let Some(id) = maybe_id {
                engine_ids.push(id);
            }
        }

        Ok(SearchAggregateResult {
            query: query.to_string(),
            engine_ids,
        })
    }
}

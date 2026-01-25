#![deny(warnings)]

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("sqlite error")]
    Sqlite,
    #[error("serialization error")]
    Serde,
}

/// Cache simple basé sur SQLite pour stocker des profils (IP, email, etc.)
/// Clé arbitraire, valeur = JSON sérialisé (par ex. Vec&lt;String&gt; de lignes de rapport).
pub struct SqliteCache {
    conn: Connection,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheRow {
    value: String,
    updated_at: u64,
}

impl SqliteCache {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, CacheError> {
        let conn = Connection::open(path).map_err(|_| CacheError::Sqlite)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )
        .map_err(|_| CacheError::Sqlite)?;
        Ok(Self { conn })
    }

    pub fn get(&self, key: &str) -> Result<Option<CacheRow>, CacheError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value, updated_at FROM cache WHERE key = ?1")
            .map_err(|_| CacheError::Sqlite)?;

        let mut rows = stmt
            .query_map(params![key], |row| {
                Ok(CacheRow {
                    value: row.get(0)?,
                    updated_at: row.get(1)?,
                })
            })
            .map_err(|_| CacheError::Sqlite)?;

        if let Some(Ok(row)) = rows.next() {
            Ok(Some(row))
        } else {
            Ok(None)
        }
    }

    pub fn set_json<T: Serialize>(&self, key: &str, value: &T) -> Result<(), CacheError> {
        let json = serde_json::to_string(value).map_err(|_| CacheError::Serde)?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CacheError::Sqlite)?
            .as_secs() as i64;

        self.conn
            .execute(
                "INSERT INTO cache (key, value, updated_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                params![key, json, ts],
            )
            .map_err(|_| CacheError::Sqlite)?;
        Ok(())
    }

    pub fn get_json<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>, CacheError> {
        if let Some(row) = self.get(key)? {
            let v = serde_json::from_str(&row.value).map_err(|_| CacheError::Serde)?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }
}
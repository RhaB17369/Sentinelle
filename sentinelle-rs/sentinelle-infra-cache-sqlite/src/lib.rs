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
/// et un journal global d'activité.
pub struct SqliteCache {
    conn: Connection,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheRow {
    pub value: String,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub ts: u64,
    pub module: String,
    pub target: String,
    pub kind: String,
    pub duration_ms: u64,
    pub status: String,
}

impl SqliteCache {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, CacheError> {
        let conn = Connection::open(path).map_err(|_| CacheError::Sqlite)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                kind TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                status TEXT NOT NULL
            );",
        )
        .map_err(|_| CacheError::Sqlite)?;
        Ok(Self { conn })
    }

    fn get(&self, key: &str) -> Result<Option<CacheRow>, CacheError> {
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

    pub fn log_activity(&self, ev: &ActivityEvent) -> Result<(), CacheError> {
        self.conn
            .execute(
                "INSERT INTO activity (ts, module, target, kind, duration_ms, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    ev.ts as i64,
                    ev.module,
                    ev.target,
                    ev.kind,
                    ev.duration_ms as i64,
                    ev.status
                ],
            )
            .map_err(|_| CacheError::Sqlite)?;
        Ok(())
    }

    pub fn recent_activity(&self, limit: usize) -> Result<Vec<ActivityEvent>, CacheError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ts, module, target, kind, duration_ms, status
                 FROM activity
                 ORDER BY id DESC
                 LIMIT ?1",
            )
            .map_err(|_| CacheError::Sqlite)?;

        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok(ActivityEvent {
                    ts: row.get::<_, i64>(0)? as u64,
                    module: row.get(1)?,
                    target: row.get(2)?,
                    kind: row.get(3)?,
                    duration_ms: row.get::<_, i64>(4)? as u64,
                    status: row.get(5)?,
                })
            })
            .map_err(|_| CacheError::Sqlite)?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|_| CacheError::Sqlite)?);
        }
        Ok(out)
    }
}
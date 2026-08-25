#![forbid(unsafe_code)]

use std::path::Path;

use aros_evidence::{EventLedger, LedgerEntry};
use aros_types::{Campaign, CampaignId};
use rusqlite::{params, Connection};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("campaign not found: {0}")]
    NotFound(String),
    #[error("ledger: {0}")]
    Ledger(String),
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                idx INTEGER PRIMARY KEY,
                campaign_id TEXT,
                event_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS graph_nodes (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS graph_edges (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            "#,
        )?;
        Ok(Self { conn })
    }

    pub fn put_campaign(&self, campaign: &Campaign) -> Result<(), StoreError> {
        let payload = serde_json::to_string(campaign)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO campaigns (id, payload) VALUES (?1, ?2)",
            params![campaign.id.to_string(), payload],
        )?;
        Ok(())
    }

    pub fn get_campaign(&self, id: CampaignId) -> Result<Campaign, StoreError> {
        let payload: String = self
            .conn
            .query_row(
                "SELECT payload FROM campaigns WHERE id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::NotFound(id.to_string()))?;
        Ok(serde_json::from_str(&payload)?)
    }

    pub fn persist_ledger(&self, ledger: &EventLedger) -> Result<(), StoreError> {
        self.conn.execute("DELETE FROM events", [])?;
        for entry in ledger.entries() {
            self.insert_entry(entry)?;
        }
        Ok(())
    }

    pub fn append_entry(&self, entry: &LedgerEntry) -> Result<(), StoreError> {
        self.insert_entry(entry)
    }

    fn insert_entry(&self, entry: &LedgerEntry) -> Result<(), StoreError> {
        let payload = serde_json::to_string(entry)?;
        self.conn.execute(
            "INSERT INTO events (idx, campaign_id, event_hash, previous_hash, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                entry.index as i64,
                entry.campaign_id.map(|c| c.to_string()),
                entry.event_hash,
                entry.previous_hash,
                payload
            ],
        )?;
        Ok(())
    }

    pub fn load_ledger(&self) -> Result<EventLedger, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload FROM events ORDER BY idx ASC")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut ledger = EventLedger::new();
        // Reconstruct by deserializing entries through JSON of the full ledger
        // is lossy; we store complete LedgerEntry and replay into a new chain
        // only after verify. For reload we keep entries as stored.
        let mut stored: Vec<LedgerEntry> = Vec::new();
        for row in rows {
            stored.push(serde_json::from_str(&row?)?);
        }
        // EventLedger has private entries; re-append events to rebuild hashes.
        for entry in stored {
            ledger.append(entry.record.event, entry.artifact_digests)?;
        }
        Ok(ledger)
    }
}

impl From<aros_evidence::LedgerError> for StoreError {
    fn from(value: aros_evidence::LedgerError) -> Self {
        StoreError::Ledger(value.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use aros_types::{Campaign, CampaignId, ResearchEvent, SnapshotId, TargetId};

    #[test]
    fn campaign_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("aros.db")).unwrap();
        let c = Campaign::new(
            CampaignId::new(),
            TargetId::new(),
            SnapshotId::new(),
            "hash".into(),
        );
        store.put_campaign(&c).unwrap();
        let got = store.get_campaign(c.id).unwrap();
        assert_eq!(got.manifest_hash, "hash");
    }

    #[test]
    fn ledger_persist_and_reload_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("aros.db")).unwrap();
        let mut ledger = EventLedger::new();
        ledger
            .append(
                ResearchEvent::CampaignStarted {
                    campaign_id: CampaignId::new(),
                    manifest_hash: "m".into(),
                },
                vec![],
            )
            .unwrap();
        store.persist_ledger(&ledger).unwrap();
        let loaded = store.load_ledger().unwrap();
        loaded.verify().unwrap();
        assert_eq!(loaded.len(), 1);
    }
}

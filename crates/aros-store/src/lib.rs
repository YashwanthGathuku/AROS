#![forbid(unsafe_code)]

use std::path::Path;

use aros_evidence::{EventLedger, LedgerEntry};
use aros_types::{Campaign, CampaignId, GraphEdge, GraphNode};
use rusqlite::{params, Connection};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("record not found: {0}")]
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
            -- Compatibility table for pre-hardening workspaces. New evidence is
            -- written to campaign-scoped ledger_events.
            CREATE TABLE IF NOT EXISTS events (
                idx INTEGER PRIMARY KEY,
                campaign_id TEXT,
                event_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ledger_events (
                campaign_id TEXT NOT NULL,
                idx INTEGER NOT NULL,
                event_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (campaign_id, idx)
            );
            CREATE TABLE IF NOT EXISTS graph_nodes (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS graph_nodes_campaign_idx
                ON graph_nodes(campaign_id);
            CREATE TABLE IF NOT EXISTS graph_edges (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS graph_edges_campaign_idx
                ON graph_edges(campaign_id);
            CREATE TABLE IF NOT EXISTS records (
                kind TEXT NOT NULL,
                id TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (kind, id)
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
        let campaign_id = ledger
            .entries()
            .iter()
            .find_map(|entry| entry.campaign_id)
            .ok_or_else(|| StoreError::Ledger("cannot infer campaign id from ledger".into()))?;
        self.persist_ledger_for(campaign_id, ledger)
    }

    pub fn persist_ledger_for(
        &self,
        campaign_id: CampaignId,
        ledger: &EventLedger,
    ) -> Result<(), StoreError> {
        ledger
            .verify()
            .map_err(|error| StoreError::Ledger(error.to_string()))?;
        let campaign = campaign_id.to_string();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM ledger_events WHERE campaign_id = ?1",
            params![campaign],
        )?;
        for entry in ledger.entries() {
            let payload = serde_json::to_string(entry)?;
            tx.execute(
                "INSERT INTO ledger_events
                 (campaign_id, idx, event_hash, previous_hash, payload_digest, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    campaign,
                    entry.index as i64,
                    entry.event_hash,
                    entry.previous_hash,
                    entry.payload_digest,
                    payload
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn append_entry_for(
        &self,
        campaign_id: CampaignId,
        entry: &LedgerEntry,
    ) -> Result<(), StoreError> {
        let payload = serde_json::to_string(entry)?;
        self.conn.execute(
            "INSERT INTO ledger_events
             (campaign_id, idx, event_hash, previous_hash, payload_digest, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                campaign_id.to_string(),
                entry.index as i64,
                entry.event_hash,
                entry.previous_hash,
                entry.payload_digest,
                payload
            ],
        )?;
        Ok(())
    }

    pub fn append_entry(&self, entry: &LedgerEntry) -> Result<(), StoreError> {
        let campaign_id = entry
            .campaign_id
            .ok_or_else(|| StoreError::Ledger("entry has no campaign id".into()))?;
        self.append_entry_for(campaign_id, entry)
    }

    pub fn load_ledger_for(&self, campaign_id: CampaignId) -> Result<EventLedger, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT payload, event_hash, previous_hash, payload_digest
             FROM ledger_events WHERE campaign_id = ?1 ORDER BY idx ASC",
        )?;
        let rows = stmt.query_map(params![campaign_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut stored = Vec::new();
        for row in rows {
            let (payload, event_hash, previous_hash, payload_digest) = row?;
            let entry: LedgerEntry = serde_json::from_str(&payload)?;
            if entry.event_hash != event_hash
                || entry.previous_hash != previous_hash
                || entry.payload_digest != payload_digest
            {
                return Err(StoreError::Ledger(format!(
                    "persisted ledger columns disagree at index {}",
                    entry.index
                )));
            }
            stored.push(entry);
        }
        if stored.is_empty() {
            return Err(StoreError::NotFound(format!("ledger:{campaign_id}")));
        }
        EventLedger::from_stored_entries(stored)
            .map_err(|error| StoreError::Ledger(error.to_string()))
    }

    pub fn load_ledger(&self) -> Result<EventLedger, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT campaign_id FROM ledger_events ORDER BY campaign_id")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let ids: Vec<String> = rows.collect::<Result<_, _>>()?;
        if ids.len() != 1 {
            return Err(StoreError::Ledger(format!(
                "load_ledger requires exactly one persisted campaign; found {}",
                ids.len()
            )));
        }
        let campaign_id: CampaignId =
            serde_json::from_value(serde_json::Value::String(ids[0].clone()))?;
        self.load_ledger_for(campaign_id)
    }

    pub fn put_graph_node(&self, node: &GraphNode) -> Result<(), StoreError> {
        let payload = serde_json::to_string(node)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO graph_nodes (id, campaign_id, payload) VALUES (?1, ?2, ?3)",
            params![node.id.to_string(), node.campaign_id.to_string(), payload],
        )?;
        Ok(())
    }

    pub fn put_graph_edge(&self, edge: &GraphEdge) -> Result<(), StoreError> {
        let payload = serde_json::to_string(edge)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO graph_edges (id, campaign_id, payload) VALUES (?1, ?2, ?3)",
            params![edge.id.to_string(), edge.campaign_id.to_string(), payload],
        )?;
        Ok(())
    }

    pub fn persist_graph(
        &self,
        campaign_id: CampaignId,
        nodes: &[GraphNode],
        edges: &[GraphEdge],
    ) -> Result<(), StoreError> {
        let campaign = campaign_id.to_string();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM graph_edges WHERE campaign_id = ?1",
            params![campaign],
        )?;
        tx.execute(
            "DELETE FROM graph_nodes WHERE campaign_id = ?1",
            params![campaign],
        )?;
        for node in nodes {
            tx.execute(
                "INSERT INTO graph_nodes (id, campaign_id, payload) VALUES (?1, ?2, ?3)",
                params![node.id.to_string(), campaign, serde_json::to_string(node)?],
            )?;
        }
        for edge in edges {
            tx.execute(
                "INSERT INTO graph_edges (id, campaign_id, payload) VALUES (?1, ?2, ?3)",
                params![edge.id.to_string(), campaign, serde_json::to_string(edge)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_graph_nodes(&self, campaign_id: CampaignId) -> Result<Vec<GraphNode>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload FROM graph_nodes WHERE campaign_id = ?1 ORDER BY rowid ASC")?;
        let rows = stmt.query_map(params![campaign_id.to_string()], |row| {
            row.get::<_, String>(0)
        })?;
        let mut nodes = Vec::new();
        for row in rows {
            nodes.push(serde_json::from_str(&row?)?);
        }
        Ok(nodes)
    }

    pub fn load_graph_edges(&self, campaign_id: CampaignId) -> Result<Vec<GraphEdge>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload FROM graph_edges WHERE campaign_id = ?1 ORDER BY rowid ASC")?;
        let rows = stmt.query_map(params![campaign_id.to_string()], |row| {
            row.get::<_, String>(0)
        })?;
        let mut edges = Vec::new();
        for row in rows {
            edges.push(serde_json::from_str(&row?)?);
        }
        Ok(edges)
    }

    pub fn put_record(&self, kind: &str, id: &str, payload: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO records (kind, id, payload) VALUES (?1, ?2, ?3)",
            params![kind, id, payload],
        )?;
        Ok(())
    }

    pub fn get_record(&self, kind: &str, id: &str) -> Result<String, StoreError> {
        self.conn
            .query_row(
                "SELECT payload FROM records WHERE kind = ?1 AND id = ?2",
                params![kind, id],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::NotFound(format!("{kind}:{id}")))
    }

    pub fn list_records(&self, kind: &str) -> Result<Vec<(String, String)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, payload FROM records WHERE kind = ?1 ORDER BY id")?;
        let rows = stmt.query_map(params![kind], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn list_campaigns(&self) -> Result<Vec<Campaign>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT payload FROM campaigns")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
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
    use aros_types::{
        unix_now_ms, Campaign, CampaignId, EpistemicState, GraphEdge, GraphKind, GraphNode, NodeId,
        ResearchEvent, SnapshotId, TargetId,
    };

    fn sample_ledger(campaign_id: CampaignId, summary: &str) -> EventLedger {
        let mut ledger = EventLedger::new();
        ledger
            .append(
                ResearchEvent::AnomalyRecorded {
                    campaign_id,
                    summary: summary.into(),
                },
                vec![],
            )
            .unwrap();
        ledger
    }

    #[test]
    fn campaign_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("aros.db")).unwrap();
        let campaign = Campaign::new(
            CampaignId::new(),
            TargetId::new(),
            SnapshotId::new(),
            "hash".into(),
        );
        store.put_campaign(&campaign).unwrap();
        let got = store.get_campaign(campaign.id).unwrap();
        assert_eq!(got.manifest_hash, "hash");
    }

    #[test]
    fn ledger_persist_and_reload_verifies_stored_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("aros.db");
        let store = Store::open(&db).unwrap();
        let campaign = CampaignId::new();
        let ledger = sample_ledger(campaign, "orig");
        store.persist_ledger_for(campaign, &ledger).unwrap();
        let loaded = store.load_ledger_for(campaign).unwrap();
        loaded.verify().unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn sqlite_payload_tamper_is_detected_after_reload() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("aros.db");
        let store = Store::open(&db).unwrap();
        let campaign = CampaignId::new();
        let ledger = sample_ledger(campaign, "orig");
        store.persist_ledger_for(campaign, &ledger).unwrap();
        drop(store);

        let conn = Connection::open(&db).unwrap();
        let payload: String = conn
            .query_row(
                "SELECT payload FROM ledger_events WHERE campaign_id=?1 AND idx=0",
                params![campaign.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        let tampered = payload.replace("orig", "evil");
        conn.execute(
            "UPDATE ledger_events SET payload=?1 WHERE campaign_id=?2 AND idx=0",
            params![tampered, campaign.to_string()],
        )
        .unwrap();
        drop(conn);

        let reopened = Store::open(&db).unwrap();
        assert!(reopened.load_ledger_for(campaign).is_err());
    }

    #[test]
    fn persisting_second_campaign_does_not_delete_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("aros.db")).unwrap();
        let first = CampaignId::new();
        let second = CampaignId::new();
        store
            .persist_ledger_for(first, &sample_ledger(first, "first"))
            .unwrap();
        store
            .persist_ledger_for(second, &sample_ledger(second, "second"))
            .unwrap();
        assert_eq!(store.load_ledger_for(first).unwrap().len(), 1);
        assert_eq!(store.load_ledger_for(second).unwrap().len(), 1);
        assert!(
            store.load_ledger().is_err(),
            "unscoped load_ledger must fail once a second campaign exists"
        );
    }

    #[test]
    fn graph_nodes_and_edges_roundtrip_per_campaign() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("aros.db")).unwrap();
        let campaign = CampaignId::new();
        let from = NodeId::new();
        let to = NodeId::new();
        let nodes = vec![
            GraphNode {
                id: from,
                campaign_id: campaign,
                graph: GraphKind::Research,
                kind: "hypothesis".into(),
                label: "h".into(),
                epistemic: EpistemicState::Hypothesized,
                payload: serde_json::json!({}),
                provenance: "test".into(),
                artifact_refs: vec![],
                created_unix_ms: unix_now_ms(),
            },
            GraphNode {
                id: to,
                campaign_id: campaign,
                graph: GraphKind::Research,
                kind: "observation".into(),
                label: "o".into(),
                epistemic: EpistemicState::Observed,
                payload: serde_json::json!({}),
                provenance: "test".into(),
                artifact_refs: vec![],
                created_unix_ms: unix_now_ms(),
            },
        ];
        let edges = vec![GraphEdge {
            id: aros_types::EdgeId::new(),
            campaign_id: campaign,
            graph: GraphKind::Research,
            from,
            to,
            kind: "tested_by".into(),
            epistemic: EpistemicState::Observed,
            confidence: None,
            provenance: "test".into(),
            artifact_refs: vec![],
            created_unix_ms: unix_now_ms(),
        }];
        store.persist_graph(campaign, &nodes, &edges).unwrap();
        assert_eq!(store.load_graph_nodes(campaign).unwrap(), nodes);
        assert_eq!(store.load_graph_edges(campaign).unwrap(), edges);
    }
}

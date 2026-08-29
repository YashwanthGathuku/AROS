//! Persistent campaign and worker-research registry for the local daemon.

use std::path::{Path, PathBuf};

use aros_store::Store;
use serde::{Deserialize, Serialize};

use crate::campaign::FixtureCampaignResponse;

const CAMPAIGN_KIND: &str = "fixture_campaign_outcome";
const WORKER_TURN_KIND: &str = "worker_research_turn";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignRecord {
    pub response: FixtureCampaignResponse,
    pub stored_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResearchTurn {
    pub session_id: String,
    pub request_id: String,
    pub capability: String,
    pub path: Option<String>,
    pub host: Option<String>,
    pub port: Option<u32>,
    pub decision: String,
    pub reason: String,
    pub exit_status: Option<i32>,
    pub stdout_digest: Option<String>,
    pub stored_unix_ms: u64,
}

pub struct CampaignRegistry {
    db_path: PathBuf,
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

impl CampaignRegistry {
    pub fn open(data_root: impl AsRef<Path>) -> Result<Self, String> {
        let data_root = data_root.as_ref();
        std::fs::create_dir_all(data_root).map_err(|error| error.to_string())?;
        let db_path = data_root.join("campaigns.db");
        let _ = Store::open(&db_path).map_err(|error| error.to_string())?;
        Ok(Self { db_path })
    }

    fn store(&self) -> Result<Store, String> {
        Store::open(&self.db_path).map_err(|error| error.to_string())
    }

    pub fn put(&self, response: &FixtureCampaignResponse) -> Result<(), String> {
        let record = CampaignRecord {
            response: response.clone(),
            stored_unix_ms: unix_ms(),
        };
        let payload = serde_json::to_string(&record).map_err(|error| error.to_string())?;
        self.store()?
            .put_record(CAMPAIGN_KIND, &response.campaign_id, &payload)
            .map_err(|error| error.to_string())
    }

    pub fn get(&self, campaign_id: &str) -> Result<CampaignRecord, String> {
        let payload = self
            .store()?
            .get_record(CAMPAIGN_KIND, campaign_id)
            .map_err(|error| error.to_string())?;
        serde_json::from_str(&payload).map_err(|error| error.to_string())
    }

    pub fn list(&self) -> Result<Vec<CampaignRecord>, String> {
        let rows = self
            .store()?
            .list_records(CAMPAIGN_KIND)
            .map_err(|error| error.to_string())?;
        let mut out: Vec<CampaignRecord> = Vec::new();
        for (_id, payload) in rows {
            out.push(serde_json::from_str(&payload).map_err(|error| error.to_string())?);
        }
        out.sort_by_key(|record| std::cmp::Reverse(record.stored_unix_ms));
        Ok(out)
    }

    /// Persist the actual proposal/result crossing the untrusted-worker ↔
    /// trusted-broker boundary. The record contains no model chain-of-thought;
    /// it stores only typed action intent, broker decision, and evidence digest.
    pub fn put_worker_turn(&self, turn: &WorkerResearchTurn) -> Result<(), String> {
        let key = format!("{}:{}", turn.session_id, turn.request_id);
        let payload = serde_json::to_string(turn).map_err(|error| error.to_string())?;
        self.store()?
            .put_record(WORKER_TURN_KIND, &key, &payload)
            .map_err(|error| error.to_string())
    }

    pub fn list_worker_turns(&self) -> Result<Vec<WorkerResearchTurn>, String> {
        let rows = self
            .store()?
            .list_records(WORKER_TURN_KIND)
            .map_err(|error| error.to_string())?;
        let mut out = Vec::new();
        for (_id, payload) in rows {
            out.push(serde_json::from_str(&payload).map_err(|error| error.to_string())?);
        }
        out.sort_by_key(|turn: &WorkerResearchTurn| turn.stored_unix_ms);
        Ok(out)
    }

    pub fn new_worker_turn(
        session_id: &str,
        request_id: &str,
        capability: &str,
        path: Option<String>,
        host: Option<String>,
        port: Option<u32>,
        decision: String,
        reason: String,
        exit_status: Option<i32>,
        stdout_digest: Option<String>,
    ) -> WorkerResearchTurn {
        WorkerResearchTurn {
            session_id: session_id.to_string(),
            request_id: request_id.to_string(),
            capability: capability.to_string(),
            path,
            host,
            port,
            decision,
            reason,
            exit_status,
            stdout_digest,
            stored_unix_ms: unix_ms(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::campaign::{
        run_fixture_campaign, seed_fixture, FixtureCampaignRequest, FixtureKindParam,
    };
    use aros_core::FixtureKind;

    #[test]
    fn put_get_list_roundtrip() {
        let fixture = tempfile::tempdir().unwrap();
        seed_fixture(FixtureKind::Authz, fixture.path()).unwrap();
        let work = tempfile::tempdir().unwrap();
        let req = FixtureCampaignRequest {
            fixture_root: fixture.path().to_string_lossy().into_owned(),
            work_root: work.path().to_string_lossy().into_owned(),
            kind: FixtureKindParam::Authz,
            waive_containment: true,
        };
        let resp = run_fixture_campaign(&req).unwrap();
        assert!(resp.live_reattack_confirmed);

        let data = tempfile::tempdir().unwrap();
        let reg = CampaignRegistry::open(data.path()).unwrap();
        reg.put(&resp).unwrap();

        let got = reg.get(&resp.campaign_id).unwrap();
        assert_eq!(got.response.campaign_id, resp.campaign_id);
        assert!(got.response.verified);
        assert!(got.response.live_reattack_confirmed);

        let listed = reg.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].response.campaign_id, resp.campaign_id);
    }

    #[test]
    fn worker_research_turn_roundtrip_preserves_broker_evidence() {
        let data = tempfile::tempdir().unwrap();
        let reg = CampaignRegistry::open(data.path()).unwrap();
        let turn = CampaignRegistry::new_worker_turn(
            "session-a",
            "req-1",
            "read_file",
            Some("/lab/README.md".into()),
            None,
            None,
            "ALLOW".into(),
            "allowlist match".into(),
            Some(0),
            Some("digest-1".into()),
        );
        reg.put_worker_turn(&turn).unwrap();
        let turns = reg.list_worker_turns().unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].session_id, "session-a");
        assert_eq!(turns[0].request_id, "req-1");
        assert_eq!(turns[0].stdout_digest.as_deref(), Some("digest-1"));
    }
}

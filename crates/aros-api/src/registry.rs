//! Persistent campaign outcome registry for arosd.

use std::path::{Path, PathBuf};

use aros_store::Store;
use serde::{Deserialize, Serialize};

use crate::campaign::FixtureCampaignResponse;

const KIND: &str = "fixture_campaign_outcome";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignRecord {
    pub response: FixtureCampaignResponse,
    pub stored_unix_ms: u64,
}

pub struct CampaignRegistry {
    db_path: PathBuf,
}

impl CampaignRegistry {
    pub fn open(data_root: impl AsRef<Path>) -> Result<Self, String> {
        let data_root = data_root.as_ref();
        std::fs::create_dir_all(data_root).map_err(|e| e.to_string())?;
        let db_path = data_root.join("campaigns.db");
        // Ensure schema exists.
        let _ = Store::open(&db_path).map_err(|e| e.to_string())?;
        Ok(Self { db_path })
    }

    fn store(&self) -> Result<Store, String> {
        Store::open(&self.db_path).map_err(|e| e.to_string())
    }

    pub fn put(&self, response: &FixtureCampaignResponse) -> Result<(), String> {
        let record = CampaignRecord {
            response: response.clone(),
            stored_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        };
        let payload = serde_json::to_string(&record).map_err(|e| e.to_string())?;
        self.store()?
            .put_record(KIND, &response.campaign_id, &payload)
            .map_err(|e| e.to_string())
    }

    pub fn get(&self, campaign_id: &str) -> Result<CampaignRecord, String> {
        let payload = self
            .store()?
            .get_record(KIND, campaign_id)
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&payload).map_err(|e| e.to_string())
    }

    pub fn list(&self) -> Result<Vec<CampaignRecord>, String> {
        let rows = self.store()?.list_records(KIND).map_err(|e| e.to_string())?;
        let mut out: Vec<CampaignRecord> = Vec::new();
        for (_id, payload) in rows {
            out.push(serde_json::from_str(&payload).map_err(|e| e.to_string())?);
        }
        // Newest first.
        out.sort_by(|a, b| b.stored_unix_ms.cmp(&a.stored_unix_ms));
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::campaign::{run_fixture_campaign, seed_fixture, FixtureCampaignRequest, FixtureKindParam};
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
}

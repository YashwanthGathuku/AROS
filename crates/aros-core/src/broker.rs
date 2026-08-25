use std::fs;
use std::path::Path;

use aros_evidence::{ContentAddressedStore, EventLedger};
use aros_policy::{evaluate, v0_1_effective_allow, PolicyVerdict, SandboxIdentity};
use aros_types::{
    unix_now_ms, AuthorizationManifest, CampaignId, ExecutionReceipt, ResearchEvent,
    TargetSnapshot, ToolCapability, ToolIntent,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("policy denied: {0}")]
    Denied(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cas: {0}")]
    Cas(#[from] aros_evidence::CasError),
    #[error("ledger: {0}")]
    Ledger(#[from] aros_evidence::LedgerError),
}

pub struct ToolBroker<'a> {
    pub campaign_id: CampaignId,
    pub manifest: &'a AuthorizationManifest,
    pub manifest_hash: String,
    pub snapshot: Option<&'a TargetSnapshot>,
    pub sandbox: &'a SandboxIdentity,
    pub cas: &'a ContentAddressedStore,
    pub ledger: &'a mut EventLedger,
    pub cli_human_override: bool,
}

impl ToolBroker<'_> {
    pub fn execute(&mut self, intent: ToolIntent) -> Result<ExecutionReceipt, BrokerError> {
        self.ledger.append(
            ResearchEvent::ToolRequested {
                campaign_id: self.campaign_id,
                request_id: intent.request_id,
                capability: intent.capability,
            },
            vec![],
        )?;
        let verdict: PolicyVerdict = evaluate(self.manifest, self.snapshot, self.sandbox, &intent);
        if !v0_1_effective_allow(&verdict, self.cli_human_override) {
            self.ledger.append(
                ResearchEvent::ToolDenied {
                    campaign_id: self.campaign_id,
                    request_id: intent.request_id,
                    reason: verdict.reason.clone(),
                },
                vec![],
            )?;
            return Err(BrokerError::Denied(verdict.reason));
        }
        self.ledger.append(
            ResearchEvent::ToolAllowed {
                campaign_id: self.campaign_id,
                request_id: intent.request_id,
            },
            vec![],
        )?;
        let started = unix_now_ms();
        let (exit_status, stdout, stderr) = self.dispatch(&intent)?;
        let stdout_art = self.cas.put(&stdout, "application/octet-stream")?;
        let stderr_art = self.cas.put(&stderr, "application/octet-stream")?;
        let finished = unix_now_ms();
        Ok(ExecutionReceipt {
            request_id: intent.request_id,
            capability: intent.capability,
            decision: verdict.decision,
            executable: intent.argv.first().cloned(),
            argv: intent.argv,
            cwd: intent.cwd,
            sandbox_id: Some(self.sandbox.id.to_string()),
            started_unix_ms: started,
            finished_unix_ms: finished,
            exit_status: Some(exit_status),
            stdout_digest: Some(stdout_art.digest_blake3),
            stderr_digest: Some(stderr_art.digest_blake3),
            manifest_hash: self.manifest_hash.clone(),
            deny_reason: None,
        })
    }

    fn dispatch(&self, intent: &ToolIntent) -> Result<(i32, Vec<u8>, Vec<u8>), BrokerError> {
        match intent.capability {
            ToolCapability::ReadFile | ToolCapability::CollectFile => {
                let path = intent.path.as_deref().unwrap_or("");
                let bytes = fs::read(path)?;
                Ok((0, bytes, Vec::new()))
            }
            ToolCapability::ListTree => {
                let path = intent.path.as_deref().unwrap_or(".");
                let listing = list_tree(Path::new(path), 0)?;
                Ok((0, listing.into_bytes(), Vec::new()))
            }
            ToolCapability::SearchText => {
                let path = intent.path.as_deref().unwrap_or(".");
                let needle = intent.argv.get(1).cloned().unwrap_or_default();
                let hits = search_text(Path::new(path), &needle)?;
                Ok((0, hits.into_bytes(), Vec::new()))
            }
            ToolCapability::HttpRequest => {
                // HTTP is performed by the campaign engine transport, not a host shell.
                Ok((0, b"http-deferred-to-engine".to_vec(), Vec::new()))
            }
            other => Err(BrokerError::Denied(format!(
                "capability {} not implemented in broker dispatch",
                other.as_str()
            ))),
        }
    }
}

fn list_tree(path: &Path, depth: usize) -> Result<String, BrokerError> {
    if depth > 16 {
        return Ok(String::new());
    }
    let mut out = String::new();
    if path.is_file() {
        out.push_str(&path.to_string_lossy());
        out.push('\n');
        return Ok(out);
    }
    let mut entries: Vec<_> = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        out.push_str(&e.path().to_string_lossy());
        out.push('\n');
        if e.path().is_dir() {
            out.push_str(&list_tree(&e.path(), depth + 1)?);
        }
    }
    Ok(out)
}

fn search_text(path: &Path, needle: &str) -> Result<String, BrokerError> {
    if needle.is_empty() {
        return Ok(String::new());
    }
    let mut out = String::new();
    search_walk(path, needle, &mut out, 0)?;
    Ok(out)
}

fn search_walk(
    path: &Path,
    needle: &str,
    out: &mut String,
    depth: usize,
) -> Result<(), BrokerError> {
    if depth > 16 {
        return Ok(());
    }
    if path.is_file() {
        if let Ok(text) = fs::read_to_string(path) {
            for (i, line) in text.lines().enumerate() {
                if line.contains(needle) {
                    out.push_str(&format!("{}:{}:{line}\n", path.display(), i + 1));
                }
            }
        }
        return Ok(());
    }
    if path.is_dir() {
        for e in fs::read_dir(path)? {
            search_walk(&e?.path(), needle, out, depth + 1)?;
        }
    }
    Ok(())
}

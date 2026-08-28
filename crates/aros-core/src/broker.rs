use std::fs;
use std::path::{Path, PathBuf};

use aros_evidence::{ContentAddressedStore, EventLedger};
use aros_policy::{
    evaluate, is_forbidden_host_resource, path_allowed, v0_1_effective_allow, PolicyVerdict,
    SandboxIdentity,
};
use aros_types::{
    unix_now_ms, AuthorizationManifest, CampaignId, ExecutionReceipt, ResearchEvent,
    TargetSnapshot, ToolCapability, ToolIntent,
};
use thiserror::Error;

use crate::http_lab::{http_get, HttpError};

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
    #[error("http: {0}")]
    Http(#[from] HttpError),
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
            sandbox_id: self
                .sandbox
                .containment_demonstrated
                .then(|| self.sandbox.id.to_string()),
            started_unix_ms: started,
            finished_unix_ms: finished,
            exit_status: Some(exit_status),
            stdout_digest: Some(stdout_art.digest_blake3),
            stderr_digest: Some(stderr_art.digest_blake3),
            manifest_hash: self.manifest_hash.clone(),
            deny_reason: None,
        })
    }

    fn canonical_authorized_path(&self, raw: &str) -> Result<PathBuf, BrokerError> {
        if raw.is_empty() || is_forbidden_host_resource(raw) {
            return Err(BrokerError::Denied("filesystem path is forbidden".into()));
        }
        let raw_metadata = fs::symlink_metadata(raw)?;
        if raw_metadata.file_type().is_symlink() {
            return Err(BrokerError::Denied("symlink traversal is forbidden".into()));
        }
        let canonical = fs::canonicalize(raw)?;
        let canonical_string = canonical.to_string_lossy().into_owned();
        if is_forbidden_host_resource(&canonical_string) {
            return Err(BrokerError::Denied(
                "canonical filesystem target is forbidden".into(),
            ));
        }
        let canonical_roots: Vec<String> = self
            .manifest
            .allowed_filesystem_roots
            .iter()
            .filter_map(|root| fs::canonicalize(root).ok())
            .map(|root| root.to_string_lossy().into_owned())
            .collect();
        if canonical_roots.is_empty() || !path_allowed(&canonical_string, &canonical_roots) {
            return Err(BrokerError::Denied(
                "canonical filesystem target escapes authorized roots".into(),
            ));
        }
        Ok(canonical)
    }

    fn dispatch(&self, intent: &ToolIntent) -> Result<(i32, Vec<u8>, Vec<u8>), BrokerError> {
        match intent.capability {
            ToolCapability::ReadFile | ToolCapability::CollectFile => {
                let path = self.canonical_authorized_path(intent.path.as_deref().unwrap_or(""))?;
                reject_symlink(&path)?;
                Ok((0, fs::read(path)?, Vec::new()))
            }
            ToolCapability::ListTree => {
                let path = self.canonical_authorized_path(intent.path.as_deref().unwrap_or("."))?;
                Ok((0, list_tree(&path, 0)?.into_bytes(), Vec::new()))
            }
            ToolCapability::SearchText => {
                let path = self.canonical_authorized_path(intent.path.as_deref().unwrap_or("."))?;
                let needle = intent.argv.get(1).cloned().unwrap_or_default();
                Ok((0, search_text(&path, &needle)?.into_bytes(), Vec::new()))
            }
            ToolCapability::GitInspect => {
                let path = self.canonical_authorized_path(intent.path.as_deref().unwrap_or("."))?;
                let head = path.join(".git").join("HEAD");
                let bytes = match fs::symlink_metadata(&head) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(BrokerError::Denied("git HEAD symlink is forbidden".into()))
                    }
                    _ => fs::read(head).unwrap_or_else(|_| b"not-a-git-repo".to_vec()),
                };
                Ok((0, bytes, Vec::new()))
            }
            ToolCapability::HttpRequest => {
                let network = intent.network.as_ref().ok_or_else(|| {
                    BrokerError::Denied("http_request requires network intent".into())
                })?;
                let path = intent
                    .argv
                    .first()
                    .map(String::as_str)
                    .filter(|value| value.starts_with('/'))
                    .unwrap_or("/");
                let cookie = intent.argv.get(1).map(String::as_str);
                let response = http_get(&network.host, network.port, path, cookie)?;
                let encoded_body =
                    serde_json::to_string(&response.body).unwrap_or_else(|_| "\"\"".to_string());
                let body = format!("{{\"status\":{},\"body\":{encoded_body}}}", response.status);
                Ok((0, body.into_bytes(), Vec::new()))
            }
            other => Err(BrokerError::Denied(format!(
                "capability {} not implemented in broker dispatch",
                other.as_str()
            ))),
        }
    }
}

fn reject_symlink(path: &Path) -> Result<(), BrokerError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(BrokerError::Denied("symlink traversal is forbidden".into()));
    }
    Ok(())
}

fn list_tree(path: &Path, depth: usize) -> Result<String, BrokerError> {
    if depth > 16 {
        return Ok(String::new());
    }
    reject_symlink(path)?;
    let mut output = String::new();
    if path.is_file() {
        output.push_str(&path.to_string_lossy());
        output.push('\n');
        return Ok(output);
    }
    let mut entries: Vec<_> = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let child = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        output.push_str(&child.to_string_lossy());
        output.push('\n');
        if file_type.is_dir() {
            output.push_str(&list_tree(&child, depth + 1)?);
        }
    }
    Ok(output)
}

fn search_text(path: &Path, needle: &str) -> Result<String, BrokerError> {
    if needle.is_empty() {
        return Ok(String::new());
    }
    let mut output = String::new();
    search_walk(path, needle, &mut output, 0)?;
    Ok(output)
}

fn search_walk(
    path: &Path,
    needle: &str,
    output: &mut String,
    depth: usize,
) -> Result<(), BrokerError> {
    if depth > 16 {
        return Ok(());
    }
    reject_symlink(path)?;
    if path.is_file() {
        if let Ok(text) = fs::read_to_string(path) {
            for (index, line) in text.lines().enumerate() {
                if line.contains(needle) {
                    output.push_str(&format!("{}:{}:{line}\n", path.display(), index + 1));
                }
            }
        }
        return Ok(());
    }
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_symlink() {
                continue;
            }
            search_walk(&entry.path(), needle, output, depth + 1)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aros_types::{CampaignId, PolicyDecision, SandboxId, TargetId, ToolCapability};

    fn broker_for<'a>(
        manifest: &'a AuthorizationManifest,
        sandbox: &'a SandboxIdentity,
        cas: &'a ContentAddressedStore,
        ledger: &'a mut EventLedger,
    ) -> ToolBroker<'a> {
        ToolBroker {
            campaign_id: manifest.campaign_id,
            manifest,
            manifest_hash: manifest.manifest_hash().unwrap(),
            snapshot: None,
            sandbox,
            cas,
            ledger,
            cli_human_override: false,
        }
    }

    #[test]
    fn list_tree_executes_and_stores_cas_digest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("note.txt"), "hello").unwrap();
        let cas_dir = tempfile::tempdir().unwrap();
        let cas = ContentAddressedStore::open(cas_dir.path(), 1024 * 1024).unwrap();
        let mut ledger = EventLedger::new();
        let manifest = AuthorizationManifest::default_deny_local(
            CampaignId::new(),
            TargetId::new(),
            dir.path().to_string_lossy().into_owned(),
        );
        let sandbox = SandboxIdentity {
            id: SandboxId::new(),
            containment_demonstrated: true,
        };
        let mut broker = broker_for(&manifest, &sandbox, &cas, &mut ledger);
        let mut intent = ToolIntent::new(ToolCapability::ListTree);
        intent.path = Some(dir.path().to_string_lossy().into_owned());
        let receipt = broker.execute(intent).unwrap();
        assert_eq!(receipt.decision, PolicyDecision::Allow);
        assert_eq!(receipt.exit_status, Some(0));
        let bytes = cas.get(&receipt.stdout_digest.unwrap()).unwrap();
        assert!(String::from_utf8(bytes).unwrap().contains("note.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_outside_root_is_not_read_or_walked() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, "TOP-SECRET").unwrap();
        symlink(&secret, root.path().join("link.txt")).unwrap();
        let cas_dir = tempfile::tempdir().unwrap();
        let cas = ContentAddressedStore::open(cas_dir.path(), 1024 * 1024).unwrap();
        let mut ledger = EventLedger::new();
        let manifest = AuthorizationManifest::default_deny_local(
            CampaignId::new(),
            TargetId::new(),
            root.path().to_string_lossy().into_owned(),
        );
        let sandbox = SandboxIdentity {
            id: SandboxId::new(),
            containment_demonstrated: true,
        };
        let mut broker = broker_for(&manifest, &sandbox, &cas, &mut ledger);
        let mut read = ToolIntent::new(ToolCapability::ReadFile);
        read.path = Some(root.path().join("link.txt").to_string_lossy().into_owned());
        assert!(broker.execute(read).is_err());
        let mut list = ToolIntent::new(ToolCapability::ListTree);
        list.path = Some(root.path().to_string_lossy().into_owned());
        let receipt = broker.execute(list).unwrap();
        let output = String::from_utf8(cas.get(&receipt.stdout_digest.unwrap()).unwrap()).unwrap();
        assert!(!output.contains("TOP-SECRET"));
    }

    #[test]
    fn uncontained_receipt_never_claims_sandbox_id() {
        let dir = tempfile::tempdir().unwrap();
        let cas = ContentAddressedStore::open(dir.path().join("cas"), 1024 * 1024).unwrap();
        let mut ledger = EventLedger::new();
        let mut manifest = AuthorizationManifest::default_deny_local(
            CampaignId::new(),
            TargetId::new(),
            dir.path().to_string_lossy().into_owned(),
        );
        manifest.require_containment = false;
        let sandbox = SandboxIdentity {
            id: SandboxId::new(),
            containment_demonstrated: false,
        };
        let mut broker = broker_for(&manifest, &sandbox, &cas, &mut ledger);
        let mut intent = ToolIntent::new(ToolCapability::ListTree);
        intent.path = Some(dir.path().to_string_lossy().into_owned());
        let receipt = broker.execute(intent).unwrap();
        assert!(receipt.sandbox_id.is_none());
    }

    #[test]
    fn denied_capability_does_not_execute() {
        let dir = tempfile::tempdir().unwrap();
        let cas = ContentAddressedStore::open(dir.path().join("cas"), 1024).unwrap();
        let mut ledger = EventLedger::new();
        let manifest = AuthorizationManifest::default_deny_local(
            CampaignId::new(),
            TargetId::new(),
            dir.path().to_string_lossy().into_owned(),
        );
        let sandbox = SandboxIdentity {
            id: SandboxId::new(),
            containment_demonstrated: true,
        };
        let mut broker = broker_for(&manifest, &sandbox, &cas, &mut ledger);
        let intent = ToolIntent::new(ToolCapability::FuzzAdapter);
        let error = broker.execute(intent).unwrap_err();
        assert!(matches!(error, BrokerError::Denied(_)));
    }
}

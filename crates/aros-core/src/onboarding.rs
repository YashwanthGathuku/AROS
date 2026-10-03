//! End-to-end trusted onboarding of a foreign project after acquisition.
//!
//! Network acquisition is intentionally a separate authority phase. Once a
//! checkout exists, this module creates an immutable copy without .git,
//! snapshots it, profiles it, maps its declared surface, and derives a plan.

use std::fs;
use std::path::{Path, PathBuf};

use aros_types::{TargetId, TargetSnapshot};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    facts_from_profile, map_http_surface, plan_campaigns, profile_target, CampaignPlan, SurfaceMap,
    TargetProfile, ForeignProjectIntegrations, foreign_project_integrations,
};
use crate::snapshot::{snapshot_tree, SnapshotError};

#[derive(Debug, Error)]
pub enum OnboardingError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("snapshot: {0}")]
    Snapshot(#[from] SnapshotError),
    #[error("surface: {0}")]
    Surface(String),
    #[error("source checkout must be a directory")]
    InvalidSource,
    #[error("destination already exists: {0}")]
    DestinationExists(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnboardedProject {
    pub target_id: TargetId,
    pub source_checkout: PathBuf,
    pub immutable_root: PathBuf,
    pub snapshot: TargetSnapshot,
    pub profile: TargetProfile,
    pub surface: SurfaceMap,
    pub plan: CampaignPlan,
    pub integrations: ForeignProjectIntegrations,
    pub network_authority_retained: bool,
}

pub fn onboard_acquired_project(
    source_checkout: &Path,
    snapshots_root: &Path,
    work_root: &Path,
    pack: &str,
) -> Result<OnboardedProject, OnboardingError> {
    if !source_checkout.is_dir() {
        return Err(OnboardingError::InvalidSource);
    }
    let target_id = TargetId::new();
    let immutable_root = snapshots_root.join(target_id.to_string());
    if immutable_root.exists() {
        return Err(OnboardingError::DestinationExists(
            immutable_root.display().to_string(),
        ));
    }
    fs::create_dir_all(&immutable_root)?;
    copy_tree_without_git(source_checkout, &immutable_root)?;

    let mut snapshot = snapshot_tree(target_id, &immutable_root)?;
    // Snapshot copy deliberately excludes .git. Resolve the acquisition commit
    // from the trusted checkout and bind it onto the immutable snapshot.
    snapshot.git_commit = resolve_git_commit(source_checkout);

    let profile = profile_target(&immutable_root)?;
    let surface = map_http_surface(&immutable_root, None)
        .map_err(|error| OnboardingError::Surface(error.to_string()))?;
    let facts = facts_from_profile(&immutable_root, &surface, Some(&profile));
    let plan = plan_campaigns(&facts, pack, Some(work_root));
    let integrations = foreign_project_integrations(&immutable_root);

    Ok(OnboardedProject {
        target_id,
        source_checkout: source_checkout.to_path_buf(),
        immutable_root,
        snapshot,
        profile,
        surface,
        plan,
        integrations,
        network_authority_retained: false,
    })
}

fn copy_tree_without_git(source: &Path, destination: &Path) -> Result<(), OnboardingError> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".git" || name == "target" || name == "node_modules" || name == "__pycache__" {
            continue;
        }
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = destination.join(&name);
        if ty.is_symlink() {
            return Err(SnapshotError::Symlink(from.display().to_string()).into());
        }
        if ty.is_dir() {
            fs::create_dir_all(&to)?;
            copy_tree_without_git(&from, &to)?;
        } else if ty.is_file() {
            fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

fn resolve_git_commit(root: &Path) -> Option<String> {
    let git = root.join(".git");
    let head = fs::read_to_string(git.join("HEAD")).ok()?;
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref: ") {
        return fs::read_to_string(git.join(reference))
            .ok()
            .map(|v| v.trim().to_string());
    }
    (!head.is_empty()).then(|| head.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onboarding_copies_then_profiles_without_git_authority() {
        let source = tempfile::tempdir().expect("source");
        let snapshots = tempfile::tempdir().expect("snapshots");
        let work = tempfile::tempdir().expect("work");
        fs::create_dir_all(source.path().join(".git/refs/heads")).expect("git");
        fs::write(source.path().join(".git/HEAD"), "ref: refs/heads/main\n").expect("head");
        fs::write(
            source.path().join(".git/refs/heads/main"),
            "0123456789012345678901234567890123456789\n",
        )
        .expect("ref");
        fs::write(source.path().join("requirements.txt"), "flask==3\n").expect("req");
        fs::write(source.path().join("app.py"), "print('app')\n").expect("app");
        fs::write(source.path().join("openapi.yml"), "openapi: 3.0.0\npaths:\n  /users/{id}:\n    get: {}\n").expect("spec");

        let result = onboard_acquired_project(
            source.path(),
            snapshots.path(),
            work.path(),
            "http",
        )
        .expect("onboard");

        assert!(!result.immutable_root.join(".git").exists());
        assert_eq!(
            result.snapshot.git_commit.as_deref(),
            Some("0123456789012345678901234567890123456789")
        );
        assert!(!result.network_authority_retained);
        assert!(result.profile.ecosystems.contains("python"));
        assert!(result.surface.source_paths.iter().any(|p| p.contains("/users")));
        assert!(!result.plan.campaigns.is_empty());
        assert_eq!(result.integrations.bumblebee.role, crate::IntegrationRole::PassiveInventory);
        assert!(!result.integrations.grok_build.may_authorize_actions);
        assert!(!result.integrations.numbat.may_verify_findings);
    }
}

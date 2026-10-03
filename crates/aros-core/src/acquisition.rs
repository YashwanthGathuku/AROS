//! Trusted acquisition planning for foreign Git repositories.
//!
//! Acquisition is deliberately separate from research execution. This module
//! validates a supported GitHub URL and constructs argv for a host-side Git
//! process. It never invokes a shell and never accepts credentials in the URL.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubRepository {
    pub owner: String,
    pub repo: String,
    pub canonical_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionPlan {
    pub repository: GitHubRepository,
    pub destination: PathBuf,
    pub clone_argv: Vec<String>,
    pub requested_ref: Option<String>,
}

pub fn parse_github_repository(input: &str) -> Result<GitHubRepository, String> {
    let trimmed = input.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://github.com/")
        .ok_or_else(|| "only https://github.com/OWNER/REPO URLs are accepted".to_string())?;
    if rest.contains('@') || rest.contains('?') || rest.contains('#') {
        return Err("credentials, query strings, and fragments are not accepted".into());
    }
    let mut parts = rest.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default().trim_end_matches(".git");
    if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
        return Err("expected https://github.com/OWNER/REPO".into());
    }
    if !safe_slug(owner) || !safe_slug(repo) {
        return Err("owner/repository contains unsupported characters".into());
    }
    Ok(GitHubRepository {
        owner: owner.to_string(),
        repo: repo.to_string(),
        canonical_url: format!("https://github.com/{owner}/{repo}.git"),
    })
}

pub fn acquisition_plan(
    url: &str,
    destination_root: &Path,
    requested_ref: Option<&str>,
) -> Result<AcquisitionPlan, String> {
    let repository = parse_github_repository(url)?;
    let destination = destination_root.join(format!("{}--{}", repository.owner, repository.repo));
    let mut clone_argv = vec![
        "clone".into(),
        "--filter=blob:none".into(),
        "--no-tags".into(),
        repository.canonical_url.clone(),
        destination.display().to_string(),
    ];
    if let Some(reference) = requested_ref {
        if !safe_ref(reference) {
            return Err("requested ref contains unsupported characters".into());
        }
        clone_argv.splice(1..1, ["--branch".into(), reference.to_string()]);
    }
    Ok(AcquisitionPlan {
        repository,
        destination,
        clone_argv,
        requested_ref: requested_ref.map(str::to_string),
    })
}

fn safe_slug(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn safe_ref(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.contains("..")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_public_github_url() {
        let repo = parse_github_repository("https://github.com/erev0s/VAmPI").expect("valid");
        assert_eq!(repo.owner, "erev0s");
        assert_eq!(repo.repo, "VAmPI");
        assert_eq!(repo.canonical_url, "https://github.com/erev0s/VAmPI.git");
    }

    #[test]
    fn rejects_embedded_credentials_and_non_github_hosts() {
        assert!(parse_github_repository("https://token@github.com/a/b").is_err());
        assert!(parse_github_repository("https://example.com/a/b").is_err());
    }

    #[test]
    fn builds_argv_without_a_shell() {
        let plan = acquisition_plan(
            "https://github.com/erev0s/VAmPI",
            Path::new("/tmp/targets"),
            Some("master"),
        )
        .expect("plan");
        assert_eq!(plan.clone_argv[0], "clone");
        assert!(plan.clone_argv.contains(&"--branch".to_string()));
        assert!(plan.destination.ends_with("erev0s--VAmPI"));
    }

    #[test]
    fn rejects_ref_option_smuggling() {
        assert!(acquisition_plan(
            "https://github.com/a/b",
            Path::new("/tmp"),
            Some("--upload-pack=evil")
        )
        .is_err());
    }
}

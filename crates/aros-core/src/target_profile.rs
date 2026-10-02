//! Deterministic profiling of an authorized source checkout.
//!
//! This module answers a deliberately narrower question than vulnerability
//! discovery: "what kind of project is this, and which execution/research
//! capabilities can AROS justify from files that actually exist?"  The result
//! is evidence for planning, never evidence that a vulnerability exists.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const SKIP_DIRS: &[&str] = &[
    ".git", ".aros", "node_modules", "target", "dist", "build", ".venv",
    "venv", "__pycache__",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetProfile {
    pub root: PathBuf,
    pub ecosystems: BTreeSet<String>,
    pub manifests: Vec<String>,
    pub source_extensions: BTreeSet<String>,
    pub entrypoints: Vec<String>,
    pub test_markers: Vec<String>,
    pub container_markers: Vec<String>,
    pub ci_markers: Vec<String>,
    pub api_spec_markers: Vec<String>,
    pub capabilities: BTreeSet<TargetCapabilityHint>,
    pub files_scanned: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetCapabilityHint {
    SourceInspection,
    Buildable,
    Testable,
    HttpCandidate,
    CliCandidate,
    LibraryCandidate,
    ContainerBuild,
    ComposeTopology,
    CiConfiguration,
    ApiSpecification,
    Rust,
    Python,
    Node,
    Go,
    Java,
}

pub fn profile_target(root: &Path) -> io::Result<TargetProfile> {
    let root = root.canonicalize()?;
    let mut profile = TargetProfile {
        root: root.clone(),
        ecosystems: BTreeSet::new(),
        manifests: Vec::new(),
        source_extensions: BTreeSet::new(),
        entrypoints: Vec::new(),
        test_markers: Vec::new(),
        container_markers: Vec::new(),
        ci_markers: Vec::new(),
        api_spec_markers: Vec::new(),
        capabilities: BTreeSet::from([TargetCapabilityHint::SourceInspection]),
        files_scanned: 0,
    };
    visit(&root, &root, &mut profile, 0)?;
    derive_capabilities(&mut profile);
    profile.manifests.sort();
    profile.entrypoints.sort();
    profile.test_markers.sort();
    profile.container_markers.sort();
    profile.ci_markers.sort();
    profile.api_spec_markers.sort();
    Ok(profile)
}

fn visit(root: &Path, dir: &Path, profile: &mut TargetProfile, depth: usize) -> io::Result<()> {
    if depth > 12 || profile.files_scanned >= 10_000 {
        return Ok(());
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let ty = entry.file_type()?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if ty.is_symlink() {
            continue;
        }
        if ty.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            visit(root, &path, profile, depth + 1)?;
            continue;
        }
        if !ty.is_file() {
            continue;
        }
        profile.files_scanned += 1;
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        classify(&name, &rel, profile);
    }
    Ok(())
}

fn classify(name: &str, rel: &str, p: &mut TargetProfile) {
    if let Some(ext) = Path::new(name).extension().and_then(|v| v.to_str()) {
        if matches!(ext, "rs" | "py" | "js" | "ts" | "tsx" | "go" | "java" | "kt" | "c" | "cc" | "cpp" | "h" | "hpp") {
            p.source_extensions.insert(ext.to_string());
        }
    }

    match name {
        "Cargo.toml" => manifest(p, rel, "rust"),
        "pyproject.toml" | "requirements.txt" | "setup.py" | "setup.cfg" => manifest(p, rel, "python"),
        "package.json" | "pnpm-lock.yaml" | "yarn.lock" => manifest(p, rel, "node"),
        "go.mod" => manifest(p, rel, "go"),
        "pom.xml" | "build.gradle" | "build.gradle.kts" => manifest(p, rel, "java"),
        "Dockerfile" => p.container_markers.push(rel.to_string()),
        "compose.yaml" | "compose.yml" | "docker-compose.yml" | "docker-compose.yaml" => {
            p.container_markers.push(rel.to_string())
        }
        _ => {}
    }

    if rel.starts_with(".github/workflows/") || name == ".gitlab-ci.yml" || name == "Jenkinsfile" {
        p.ci_markers.push(rel.to_string());
    }
    let lower = name.to_ascii_lowercase();
    if (lower.contains("openapi") || lower.contains("swagger"))
        && matches!(Path::new(name).extension().and_then(|v| v.to_str()), Some("yml" | "yaml" | "json"))
    {
        p.api_spec_markers.push(rel.to_string());
    }
    if is_test_marker(name, rel) {
        p.test_markers.push(rel.to_string());
    }
    if is_entrypoint(name, rel) {
        p.entrypoints.push(rel.to_string());
    }
}

fn manifest(p: &mut TargetProfile, rel: &str, ecosystem: &str) {
    p.manifests.push(rel.to_string());
    p.ecosystems.insert(ecosystem.to_string());
}

fn is_test_marker(name: &str, rel: &str) -> bool {
    name.starts_with("test_")
        || name.ends_with("_test.py")
        || name.ends_with(".test.js")
        || name.ends_with(".test.ts")
        || name.ends_with(".spec.js")
        || name.ends_with(".spec.ts")
        || name.ends_with("_test.go")
        || rel.contains("/tests/")
        || rel.starts_with("tests/")
}

fn is_entrypoint(name: &str, rel: &str) -> bool {
    matches!(name, "main.py" | "app.py" | "server.py" | "manage.py" | "main.rs" | "main.go")
        || rel.ends_with("/src/main.rs")
        || rel.ends_with("/cmd/main.go")
}

fn derive_capabilities(p: &mut TargetProfile) {
    for ecosystem in p.ecosystems.clone() {
        match ecosystem.as_str() {
            "rust" => { p.capabilities.insert(TargetCapabilityHint::Rust); }
            "python" => { p.capabilities.insert(TargetCapabilityHint::Python); }
            "node" => { p.capabilities.insert(TargetCapabilityHint::Node); }
            "go" => { p.capabilities.insert(TargetCapabilityHint::Go); }
            "java" => { p.capabilities.insert(TargetCapabilityHint::Java); }
            _ => {}
        };
    }
    if !p.manifests.is_empty() {
        p.capabilities.insert(TargetCapabilityHint::Buildable);
        p.capabilities.insert(TargetCapabilityHint::LibraryCandidate);
    }
    if !p.test_markers.is_empty() {
        p.capabilities.insert(TargetCapabilityHint::Testable);
    }
    if !p.entrypoints.is_empty() {
        p.capabilities.insert(TargetCapabilityHint::CliCandidate);
    }
    if p.entrypoints.iter().any(|v| {
        v.ends_with("server.py") || v.ends_with("app.py") || v.ends_with("manage.py")
    }) || p.container_markers.iter().any(|v| v.contains("compose")) {
        p.capabilities.insert(TargetCapabilityHint::HttpCandidate);
    }
    if p.container_markers.iter().any(|v| v.ends_with("Dockerfile")) {
        p.capabilities.insert(TargetCapabilityHint::ContainerBuild);
    }
    if p.container_markers.iter().any(|v| v.contains("compose")) {
        p.capabilities.insert(TargetCapabilityHint::ComposeTopology);
    }
    if !p.ci_markers.is_empty() {
        p.capabilities.insert(TargetCapabilityHint::CiConfiguration);
    }
    if !p.api_spec_markers.is_empty() {
        p.capabilities.insert(TargetCapabilityHint::ApiSpecification);
        p.capabilities.insert(TargetCapabilityHint::HttpCandidate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_a_foreign_rust_cli_without_aros_fixture_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src");
        fs::create_dir_all(dir.path().join("tests")).expect("tests");
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname='foreign'\nversion='0.1.0'\n").expect("manifest");
        fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").expect("main");
        fs::write(dir.path().join("tests/integration.rs"), "#[test] fn ok() {}\n").expect("test");

        let p = profile_target(dir.path()).expect("profile");
        assert!(p.ecosystems.contains("rust"));
        assert!(p.capabilities.contains(&TargetCapabilityHint::Buildable));
        assert!(p.capabilities.contains(&TargetCapabilityHint::CliCandidate));
        assert!(p.capabilities.contains(&TargetCapabilityHint::Testable));
        assert!(!p.capabilities.contains(&TargetCapabilityHint::HttpCandidate));
    }

    #[test]
    fn profiles_vampi_shaped_python_openapi_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("openapi_specs")).expect("spec dir");
        fs::write(dir.path().join("requirements.txt"), "flask==2.2.2\n").expect("requirements");
        fs::write(dir.path().join("app.py"), "print('service')\n").expect("app");
        fs::write(dir.path().join("Dockerfile"), "FROM python:3.11-alpine\n").expect("dockerfile");
        fs::write(
            dir.path().join("docker-compose.yaml"),
            "services:\n  api:\n    build: .\n",
        )
        .expect("compose");
        fs::write(
            dir.path().join("openapi_specs/openapi3.yml"),
            "openapi: 3.0.1\npaths: {}\n",
        )
        .expect("openapi");

        let p = profile_target(dir.path()).expect("profile");
        assert!(p.ecosystems.contains("python"));
        assert!(p.capabilities.contains(&TargetCapabilityHint::Python));
        assert!(p.capabilities.contains(&TargetCapabilityHint::HttpCandidate));
        assert!(p.capabilities.contains(&TargetCapabilityHint::ContainerBuild));
        assert!(p.capabilities.contains(&TargetCapabilityHint::ComposeTopology));
        assert!(p.capabilities.contains(&TargetCapabilityHint::ApiSpecification));
        assert_eq!(p.api_spec_markers, vec!["openapi_specs/openapi3.yml"]);
    }

    #[test]
    fn symlink_is_not_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("pyproject.toml"), "[project]\nname='x'\nversion='0.1'\n").expect("manifest");
        let p = profile_target(dir.path()).expect("profile");
        assert!(p.capabilities.contains(&TargetCapabilityHint::Python));
    }
}

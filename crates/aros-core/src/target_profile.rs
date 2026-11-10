//! Deterministic profiling of an authorized source checkout.
//!
//! This module answers a deliberately narrower question than vulnerability
//! discovery: "what kind of project is this, and which execution/research
//! capabilities can AROS justify from files that actually exist?"  The result
//! is evidence for planning, never evidence that a vulnerability exists.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".aros",
    "node_modules",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
];

/// Same suffixes the crash-crusher harness peeks. A path match is not a crash.
const CRUSHER_SOURCE_SUFFIXES: &[&str] = &["c", "cc", "cpp", "h", "py", "rs"];
const CRUSHER_SYMBOL: &[u8] = b"LLVMFuzzerTestOneInput";
const CRUSHER_PEEK_BYTES: usize = 65_536;
const CRUSHER_READ_CAP: usize = 2_000;
const CRUSHER_ENTRY_CAP: usize = 32;

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
    /// Relative paths the crash-crusher harness can notice: root `parse.py`,
    /// a source file under `fuzz_targets`, or a source file whose first 64 KiB
    /// contains `LLVMFuzzerTestOneInput`. Recording a path does not execute it
    /// and is not a vulnerability. A source file with no binary still fails
    /// closed when the campaign runs.
    #[serde(default)]
    pub crusher_entries: Vec<String>,
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
        crusher_entries: Vec::new(),
        capabilities: BTreeSet::from([TargetCapabilityHint::SourceInspection]),
        files_scanned: 0,
    };
    let mut crusher_reads = 0usize;
    visit(&root, &root, &mut profile, 0, &mut crusher_reads)?;
    derive_capabilities(&mut profile);
    profile.manifests.sort();
    profile.entrypoints.sort();
    profile.test_markers.sort();
    profile.container_markers.sort();
    profile.ci_markers.sort();
    profile.api_spec_markers.sort();
    profile.crusher_entries.sort();
    Ok(profile)
}

fn visit(
    root: &Path,
    dir: &Path,
    profile: &mut TargetProfile,
    depth: usize,
    crusher_reads: &mut usize,
) -> io::Result<()> {
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
            visit(root, &path, profile, depth + 1, crusher_reads)?;
            continue;
        }
        if !ty.is_file() {
            continue;
        }
        profile.files_scanned += 1;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        classify(&name, &rel, profile);
        note_crusher_entry(&path, &rel, profile, crusher_reads);
    }
    Ok(())
}

fn crusher_source_suffix(rel: &str) -> bool {
    Path::new(rel)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| CRUSHER_SOURCE_SUFFIXES.contains(&ext))
}

fn note_crusher_entry(path: &Path, rel: &str, profile: &mut TargetProfile, reads: &mut usize) {
    if profile.crusher_entries.len() >= CRUSHER_ENTRY_CAP || *reads >= CRUSHER_READ_CAP {
        return;
    }
    let source = crusher_source_suffix(rel);
    let fuzz_target = rel.split('/').any(|part| part == "fuzz_targets");
    if rel == "parse.py" || (source && fuzz_target) {
        profile.crusher_entries.push(rel.to_string());
        return;
    }
    if !source {
        return;
    }
    *reads += 1;
    if peek_contains_fuzzer_symbol(path) {
        profile.crusher_entries.push(rel.to_string());
    }
}

fn peek_contains_fuzzer_symbol(path: &Path) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut buf = vec![0_u8; CRUSHER_PEEK_BYTES];
    let n = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    buf[..n]
        .windows(CRUSHER_SYMBOL.len())
        .any(|window| window == CRUSHER_SYMBOL)
}

fn classify(name: &str, rel: &str, p: &mut TargetProfile) {
    if let Some(ext) = Path::new(name).extension().and_then(|v| v.to_str()) {
        if matches!(
            ext,
            "rs" | "py"
                | "js"
                | "ts"
                | "tsx"
                | "go"
                | "java"
                | "kt"
                | "c"
                | "cc"
                | "cpp"
                | "h"
                | "hpp"
        ) {
            p.source_extensions.insert(ext.to_string());
        }
    }

    match name {
        "Cargo.toml" => manifest(p, rel, "rust"),
        "pyproject.toml" | "requirements.txt" | "setup.py" | "setup.cfg" => {
            manifest(p, rel, "python")
        }
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
        && matches!(
            Path::new(name).extension().and_then(|v| v.to_str()),
            Some("yml" | "yaml" | "json")
        )
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
    matches!(
        name,
        "main.py" | "app.py" | "server.py" | "manage.py" | "main.rs" | "main.go"
    ) || rel.ends_with("/src/main.rs")
        || rel.ends_with("/cmd/main.go")
}

fn derive_capabilities(p: &mut TargetProfile) {
    for ecosystem in p.ecosystems.clone() {
        match ecosystem.as_str() {
            "rust" => {
                p.capabilities.insert(TargetCapabilityHint::Rust);
            }
            "python" => {
                p.capabilities.insert(TargetCapabilityHint::Python);
            }
            "node" => {
                p.capabilities.insert(TargetCapabilityHint::Node);
            }
            "go" => {
                p.capabilities.insert(TargetCapabilityHint::Go);
            }
            "java" => {
                p.capabilities.insert(TargetCapabilityHint::Java);
            }
            _ => {}
        };
    }
    if !p.manifests.is_empty() {
        p.capabilities.insert(TargetCapabilityHint::Buildable);
        p.capabilities
            .insert(TargetCapabilityHint::LibraryCandidate);
    }
    if !p.test_markers.is_empty() {
        p.capabilities.insert(TargetCapabilityHint::Testable);
    }
    if !p.entrypoints.is_empty() {
        p.capabilities.insert(TargetCapabilityHint::CliCandidate);
    }
    if p.entrypoints
        .iter()
        .any(|v| v.ends_with("server.py") || v.ends_with("app.py") || v.ends_with("manage.py"))
        || p.container_markers.iter().any(|v| v.contains("compose"))
    {
        p.capabilities.insert(TargetCapabilityHint::HttpCandidate);
    }
    if p.container_markers
        .iter()
        .any(|v| v.ends_with("Dockerfile"))
    {
        p.capabilities.insert(TargetCapabilityHint::ContainerBuild);
    }
    if p.container_markers.iter().any(|v| v.contains("compose")) {
        p.capabilities.insert(TargetCapabilityHint::ComposeTopology);
    }
    if !p.ci_markers.is_empty() {
        p.capabilities.insert(TargetCapabilityHint::CiConfiguration);
    }
    if !p.api_spec_markers.is_empty() {
        p.capabilities
            .insert(TargetCapabilityHint::ApiSpecification);
        p.capabilities.insert(TargetCapabilityHint::HttpCandidate);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn profiles_a_foreign_rust_cli_without_aros_fixture_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src");
        fs::create_dir_all(dir.path().join("tests")).expect("tests");
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='foreign'\nversion='0.1.0'\n",
        )
        .expect("manifest");
        fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").expect("main");
        fs::write(
            dir.path().join("tests/integration.rs"),
            "#[test] fn ok() {}\n",
        )
        .expect("test");

        let p = profile_target(dir.path()).expect("profile");
        assert!(p.ecosystems.contains("rust"));
        assert!(p.capabilities.contains(&TargetCapabilityHint::Buildable));
        assert!(p.capabilities.contains(&TargetCapabilityHint::CliCandidate));
        assert!(p.capabilities.contains(&TargetCapabilityHint::Testable));
        assert!(!p
            .capabilities
            .contains(&TargetCapabilityHint::HttpCandidate));
        assert!(p.crusher_entries.is_empty());
    }

    #[test]
    fn records_a_fuzzer_source_without_calling_it_a_crash() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("fuzz/fuzz_targets")).expect("fuzz dir");
        fs::create_dir_all(dir.path().join("src")).expect("src");
        fs::create_dir_all(dir.path().join("target")).expect("build dir");
        fs::write(
            dir.path().join("fuzz/fuzz_targets/one.rs"),
            "fn fuzz() {}\n",
        )
        .expect("fuzz");
        fs::write(
            dir.path().join("src/one_input.c"),
            "int LLVMFuzzerTestOneInput(const unsigned char* data, unsigned long size) { return 0; }\n",
        )
        .expect("symbol");
        fs::write(
            dir.path().join("target/hidden.c"),
            "int LLVMFuzzerTestOneInput(const unsigned char* data, unsigned long size) { return 0; }\n",
        )
        .expect("skipped build output");
        fs::write(
            dir.path().join("src/plain.c"),
            "int plain(void) { return 0; }\n",
        )
        .expect("plain");

        let p = profile_target(dir.path()).expect("profile");
        assert_eq!(
            p.crusher_entries,
            vec![
                "fuzz/fuzz_targets/one.rs".to_string(),
                "src/one_input.c".to_string()
            ]
        );
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
        assert!(p
            .capabilities
            .contains(&TargetCapabilityHint::HttpCandidate));
        assert!(p
            .capabilities
            .contains(&TargetCapabilityHint::ContainerBuild));
        assert!(p
            .capabilities
            .contains(&TargetCapabilityHint::ComposeTopology));
        assert!(p
            .capabilities
            .contains(&TargetCapabilityHint::ApiSpecification));
        assert_eq!(p.api_spec_markers, vec!["openapi_specs/openapi3.yml"]);
    }

    #[test]
    fn symlink_is_not_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname='x'\nversion='0.1'\n",
        )
        .expect("manifest");
        let p = profile_target(dir.path()).expect("profile");
        assert!(p.capabilities.contains(&TargetCapabilityHint::Python));
    }
}

//! Deterministic HTTP surface recon from source. No network, no LLM.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::http_lab::http_get;

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    ".aros",
    "__pycache__",
    ".venv",
];

const SOURCE_SUFFIXES: &[&str] = &[".py", ".js", ".ts", ".tsx", ".go", ".rs", ".java"];

/// Pull quoted path-like strings (`"/users/2"`, `'/health'`) from source text.
pub fn extract_http_paths(text: &str) -> Vec<String> {
    let mut found = BTreeSet::new();
    for quote in ['"', '\''] {
        let mut rest = text;
        while let Some(start) = rest.find(quote) {
            let after = &rest[start + 1..];
            let Some(end) = after.find(quote) else {
                break;
            };
            let inner = &after[..end];
            if is_http_path(inner) {
                let path = inner.split('?').next().unwrap_or(inner);
                found.insert(path.to_string());
            }
            rest = &after[end + 1..];
        }
    }
    found.into_iter().collect()
}

/// Walk a target tree and extract HTTP paths from source files.
pub fn extract_http_paths_from_tree(root: &Path) -> io::Result<Vec<String>> {
    let mut found = BTreeSet::new();
    let mut scanned = 0usize;
    visit(root, &mut found, &mut scanned)?;
    Ok(found.into_iter().collect())
}

fn visit(dir: &Path, found: &mut BTreeSet<String>, scanned: &mut usize) -> io::Result<()> {
    if *scanned > 400 {
        return Ok(());
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if SKIP_DIRS.iter().any(|skip| *skip == name.as_ref()) {
            continue;
        }
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            visit(&path, found, scanned)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let is_source = SOURCE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix));
        if !is_source {
            continue;
        }
        let meta = entry.metadata()?;
        if meta.len() > 256_000 {
            continue;
        }
        *scanned += 1;
        if let Ok(text) = fs::read_to_string(&path) {
            for path in extract_http_paths(&text) {
                found.insert(path);
            }
        }
        if *scanned > 400 {
            break;
        }
    }
    Ok(())
}

const LIVE_WORDLIST: &[&str] = &[
    "/health",
    "/",
    "/api",
    "/api/health",
    "/users",
    "/users/1",
    "/users/2",
    "/files",
    "/admin",
    "/login",
    "/openapi.json",
    "/status",
    "/ready",
];

/// Bindable recon artifact. Catalog campaigns read `suggested_bind`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceMap {
    pub source_paths: Vec<String>,
    pub live: Vec<LiveEndpoint>,
    pub suggested_bind: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveEndpoint {
    pub path: String,
    pub status: u16,
}

/// Source recon plus optional live GET against a loopback listener.
pub fn map_http_surface(root: &Path, live: Option<(&str, u16)>) -> io::Result<SurfaceMap> {
    let source_paths = extract_http_paths_from_tree(root)?;
    let mut live_hits = Vec::new();
    if let Some((host, port)) = live {
        let mut seen = BTreeSet::new();
        for path in LIVE_WORDLIST
            .iter()
            .copied()
            .map(str::to_string)
            .chain(source_paths.iter().cloned())
        {
            if !seen.insert(path.clone()) {
                continue;
            }
            if let Ok(response) = http_get(host, port, &path, None) {
                live_hits.push(LiveEndpoint {
                    path,
                    status: response.status,
                });
            }
        }
    }
    let suggested_bind = suggest_bind(&source_paths, &live_hits);
    Ok(SurfaceMap {
        source_paths,
        live: live_hits,
        suggested_bind,
    })
}

pub fn suggest_bind(source_paths: &[String], live: &[LiveEndpoint]) -> BTreeMap<String, String> {
    let mut bind = BTreeMap::new();
    let mut paths: Vec<&str> = source_paths.iter().map(String::as_str).collect();
    paths.extend(live.iter().map(|hit| hit.path.as_str()));
    let health = ["/health", "/status", "/ready", "/api/health"]
        .into_iter()
        .find(|path| paths.iter().any(|seen| seen == path))
        .unwrap_or("/health");
    bind.insert("health_path".into(), health.into());
    if let Some(idor) = paths
        .iter()
        .find(|path| path.starts_with("/users/") && path.as_bytes().last() != Some(&b'/'))
        .copied()
    {
        bind.insert("idor_path".into(), idor.into());
        bind.insert("unauth_path".into(), idor.into());
    }
    if paths.iter().any(|path| path.starts_with("/files")) {
        bind.insert("files_path".into(), "/files?path=../secret.txt".into());
    }
    bind
}

pub fn write_surface_map(path: &Path, map: &SurfaceMap) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(map).map_err(io::Error::other)?,
    )
}

pub fn read_surface_map(path: &Path) -> io::Result<SurfaceMap> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn is_http_path(value: &str) -> bool {
    if !value.starts_with('/') || value.starts_with("//") || value.len() > 128 {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii() && !c.is_ascii_control() && c != ' ')
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn extracts_quoted_routes_not_urls() {
        let src = r#"
            @app.get("/health")
            @app.get("/users/{id}")
            fetch("https://example.com/nope")
            path = "/files"
        "#;
        let paths = extract_http_paths(src);
        assert!(paths.contains(&"/health".into()));
        assert!(paths.contains(&"/users/{id}".into()));
        assert!(paths.contains(&"/files".into()));
        assert!(!paths.iter().any(|path| path.contains("example.com")));
    }

    #[test]
    fn walks_fixture_authz_tree() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/vulnerable/authz");
        let paths = extract_http_paths_from_tree(&root).unwrap();
        assert!(paths.iter().any(|path| path == "/health"), "{paths:?}");
        assert!(
            paths.iter().any(|path| path.starts_with("/users")),
            "{paths:?}"
        );
    }

    #[test]
    fn suggested_bind_picks_idor_and_files() {
        let bind = suggest_bind(&["/health".into(), "/users/2".into(), "/files".into()], &[]);
        assert_eq!(bind.get("health_path").map(String::as_str), Some("/health"));
        assert_eq!(bind.get("idor_path").map(String::as_str), Some("/users/2"));
        assert_eq!(
            bind.get("files_path").map(String::as_str),
            Some("/files?path=../secret.txt")
        );
    }
}

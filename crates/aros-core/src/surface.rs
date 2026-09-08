//! Deterministic HTTP surface recon from source. No network, no LLM.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

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
}

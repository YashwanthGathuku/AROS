use std::fs;
use std::io::Read;
use std::path::Path;

use aros_types::{blake3_hex, unix_now_ms, SnapshotId, TargetId, TargetSnapshot};
use rayon::prelude::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("target path is not a directory: {0}")]
    NotDir(String),
    #[error("symlink is not allowed in exact-target snapshot: {0}")]
    Symlink(String),
}

/// Walk a target tree and hash file contents on a Rayon pool.
///
/// Exact-target evidence rejects symlinks rather than following them. That
/// makes the digest a statement about the authorized tree itself, not about a
/// mutable or out-of-scope object reachable through a filesystem alias.
pub fn snapshot_tree(target_id: TargetId, root: &Path) -> Result<TargetSnapshot, SnapshotError> {
    if !root.is_dir() {
        return Err(SnapshotError::NotDir(root.display().to_string()));
    }
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(SnapshotError::Symlink(root.display().to_string()));
    }
    let mut files = Vec::new();
    collect_files(root, &mut files)?;
    files.sort();
    let hashes: Vec<String> = files
        .par_iter()
        .map(|path| hash_file(path))
        .collect::<Result<Vec<_>, _>>()?;
    let mut joined = String::new();
    for (path, hash) in files.iter().zip(hashes.iter()) {
        let relative = path.strip_prefix(root).unwrap_or(path);
        joined.push_str(&relative.to_string_lossy());
        joined.push('\0');
        joined.push_str(hash);
        joined.push('\n');
    }
    let digest = blake3_hex(joined.as_bytes());
    Ok(TargetSnapshot {
        id: SnapshotId::new(),
        target_id,
        git_commit: read_git_head(root),
        dirty_tree_hash: Some(digest.clone()),
        submodule_shas: Vec::new(),
        source_tree_digest: digest,
        lockfile_hashes: hash_lockfiles(root, &files)?,
        container_image_digest: None,
        compiler_runtime_versions: Vec::new(),
        build_flags: Vec::new(),
        feature_flags: Vec::new(),
        runtime_description: format!("aros-snapshot:{}", root.display()),
        captured_unix_ms: unix_now_ms(),
    })
}

fn collect_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), SnapshotError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if name == ".git" || name == "__pycache__" || name == "target" {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(SnapshotError::Symlink(path.display().to_string()));
        }
        if file_type.is_dir() {
            collect_files(&path, out)?;
        } else if file_type.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, SnapshotError> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(SnapshotError::Symlink(path.display().to_string()));
    }
    let mut file = fs::File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(blake3_hex(&buffer))
}

fn hash_lockfiles(root: &Path, files: &[std::path::PathBuf]) -> Result<Vec<String>, SnapshotError> {
    const LOCKS: &[&str] = &[
        "Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
        "poetry.lock", "Pipfile.lock", "uv.lock", "go.sum", "gradle.lockfile",
    ];
    let mut out = Vec::new();
    for path in files {
        let Some(name) = path.file_name().and_then(|v| v.to_str()) else { continue };
        if !LOCKS.contains(&name) { continue; }
        let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy();
        out.push(format!("{rel}:{}", hash_file(path)?));
    }
    out.sort();
    Ok(out)
}

fn read_git_head(root: &Path) -> Option<String> {
    let git = root.join(".git");
    let head = fs::read_to_string(git.join("HEAD")).ok()?;
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref: ") {
        return fs::read_to_string(git.join(reference))
            .ok()
            .map(|value| value.trim().to_string());
    }
    (!head.is_empty()).then(|| head.to_string())
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_hashes_lockfiles() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("Cargo.lock"), "version = 4\n").unwrap();
        fs::write(root.path().join("src.txt"), "hello").unwrap();
        let snapshot = snapshot_tree(TargetId::new(), root.path()).unwrap();
        assert_eq!(snapshot.lockfile_hashes.len(), 1);
        assert!(snapshot.lockfile_hashes[0].starts_with("Cargo.lock:"));
    }

    #[test]
    fn exact_snapshot_refuses_symlinked_target_content() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, "secret").unwrap();
        symlink(&secret, root.path().join("alias.txt")).unwrap();
        assert!(matches!(
            snapshot_tree(TargetId::new(), root.path()),
            Err(SnapshotError::Symlink(_))
        ));
    }
}

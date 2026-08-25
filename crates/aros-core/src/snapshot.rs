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
}

/// Walk a target tree and hash file contents on a Rayon pool (CPU class B).
pub fn snapshot_tree(target_id: TargetId, root: &Path) -> Result<TargetSnapshot, SnapshotError> {
    if !root.is_dir() {
        return Err(SnapshotError::NotDir(root.display().to_string()));
    }
    let mut files = Vec::new();
    collect_files(root, &mut files)?;
    files.sort();
    let hashes: Vec<String> = files
        .par_iter()
        .map(|path| hash_file(path))
        .collect::<Result<Vec<_>, _>>()?;
    let mut joined = String::new();
    for (path, h) in files.iter().zip(hashes.iter()) {
        let rel = path.strip_prefix(root).unwrap_or(path);
        joined.push_str(&rel.to_string_lossy());
        joined.push('\0');
        joined.push_str(h);
        joined.push('\n');
    }
    let digest = blake3_hex(joined.as_bytes());
    Ok(TargetSnapshot {
        id: SnapshotId::new(),
        target_id,
        git_commit: read_git_head(root),
        dirty_tree_hash: Some(digest.clone()),
        source_tree_digest: digest,
        lockfile_hashes: Vec::new(),
        container_image_digest: None,
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
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, SnapshotError> {
    let mut file = fs::File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(blake3_hex(&buf))
}

fn read_git_head(root: &Path) -> Option<String> {
    let p = root.join(".git").join("HEAD");
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

//! Optional specialist engines. Absence must not break the core.

use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectedTool {
    pub name: &'static str,
    pub path: PathBuf,
    pub category: &'static str,
}

fn which(bin: &str) -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        format!("{bin}.exe")
    } else {
        bin.to_string()
    };
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let p = dir.join(&exe);
            if p.is_file() {
                Some(p)
            } else {
                let alt = dir.join(bin);
                alt.is_file().then_some(alt)
            }
        })
    })
}

pub fn detect_optional_engines() -> Vec<DetectedTool> {
    let mut out = Vec::new();
    let catalog = [
        ("git", "git_inspect"),
        ("clang", "sanitizer_adapter"),
        ("semgrep", "static_analysis_adapter"),
        ("codeql", "static_analysis_adapter"),
        ("afl-fuzz", "fuzz_adapter"),
        ("grok", "harness"),
    ];
    for (bin, cat) in catalog {
        if let Some(path) = which(bin) {
            out.push(DetectedTool {
                name: bin,
                path,
                category: cat,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_is_detected_on_this_host() {
        let found = detect_optional_engines();
        assert!(
            found.iter().any(|t| t.name == "git"),
            "git is required for snapshot identity and was missing: {found:?}"
        );
    }
}

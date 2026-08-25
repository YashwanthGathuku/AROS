/// Path-scope matching for authorized filesystem roots.
///
/// `..` and NUL are rejected before any prefix comparison. Matching is
/// string-prefix on a normalized `/`-separated path.
pub fn normalize_path(path: &str) -> Option<String> {
    if path.is_empty() || path.contains('\0') {
        return None;
    }
    let replaced = path.replace('\\', "/");
    let mut out: Vec<&str> = Vec::new();
    for part in replaced.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return None;
        }
        out.push(part);
    }
    if out.is_empty() {
        return Some("/".to_string());
    }
    let mut s = String::from("/");
    s.push_str(&out.join("/"));
    Some(s)
}

/// Host resources that must never be reachable even if a root were misconfigured.
pub fn is_forbidden_host_resource(path: &str) -> bool {
    let n = path.replace('\\', "/").to_ascii_lowercase();
    [
        "/mnt/c",
        "docker.sock",
        "podman.sock",
        "/.ssh/",
        "id_rsa",
        "id_ed25519",
        ".git-credentials",
        ".aws/credentials",
        "google/chrome/user data",
        "mozilla/firefox",
    ]
    .iter()
    .any(|needle| n.contains(needle))
}

pub fn path_allowed(path: &str, allowed_roots: &[String]) -> bool {
    if is_forbidden_host_resource(path) {
        return false;
    }
    let Some(normalized) = normalize_path(path) else {
        return false;
    };
    allowed_roots.iter().any(|root| {
        let Some(root_n) = normalize_path(root) else {
            return false;
        };
        if normalized == root_n {
            return true;
        }
        let prefix = if root_n == "/" {
            "/"
        } else {
            // prefix must be root + '/'
            return normalized.starts_with(&root_n)
                && (normalized.len() == root_n.len()
                    || normalized.as_bytes().get(root_n.len()) == Some(&b'/'));
        };
        normalized.starts_with(prefix)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_escape() {
        assert!(normalize_path("/tmp/target/../etc/passwd").is_none());
        assert!(!path_allowed(
            "/tmp/target/../etc/passwd",
            &["/tmp/target".into()]
        ));
    }

    #[test]
    fn allows_prefix_inside_root() {
        assert!(path_allowed(
            "/tmp/target/src/main.rs",
            &["/tmp/target".into()]
        ));
        assert!(!path_allowed(
            "/tmp/target-other/x",
            &["/tmp/target".into()]
        ));
    }

    #[test]
    fn rejects_null() {
        assert!(normalize_path("/tmp/target/\0x").is_none());
    }
}

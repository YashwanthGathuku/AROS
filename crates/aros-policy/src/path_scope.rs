/// Path-scope matching for authorized filesystem roots.
///
/// This is the lexical first gate. The trusted broker additionally canonicalizes
/// real filesystem targets and rejects symlink escapes before I/O.
pub fn normalize_path(path: &str) -> Option<String> {
    if path.is_empty() || path.contains('\0') {
        return None;
    }
    let stripped = path
        .strip_prefix(r"\\?\")
        .or_else(|| path.strip_prefix("//?/"))
        .unwrap_or(path);
    let replaced = stripped.replace('\\', "/");
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
    Some(format!("/{}", out.join("/")))
}

pub fn is_forbidden_host_resource(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
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
    .any(|needle| normalized.contains(needle))
}

pub fn path_allowed(path: &str, allowed_roots: &[String]) -> bool {
    if is_forbidden_host_resource(path) {
        return false;
    }
    let Some(normalized) = normalize_path(path) else {
        return false;
    };
    allowed_roots.iter().any(|root| {
        let Some(root_normalized) = normalize_path(root) else {
            return false;
        };
        if normalized == root_normalized {
            return true;
        }
        if root_normalized == "/" {
            return normalized.starts_with('/');
        }
        normalized.starts_with(&root_normalized)
            && normalized.as_bytes().get(root_normalized.len()) == Some(&b'/')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rejects_parent_escape() {
        assert!(normalize_path("/tmp/target/../etc/passwd").is_none());
        assert!(!path_allowed(
            "/tmp/target/../etc/passwd",
            &["/tmp/target".into()]
        ));
    }

    #[test]
    fn allows_prefix_inside_root_but_not_sibling_prefix() {
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
    fn windows_verbatim_prefix_matches_plain_path() {
        assert_eq!(
            normalize_path(r"\\?\C:\Users\lab"),
            normalize_path(r"C:\Users\lab")
        );
    }

    proptest! {
        #[test]
        fn arbitrary_parent_component_is_never_accepted(
            root in "[a-zA-Z0-9_-]{1,16}",
            child in "[a-zA-Z0-9_.-]{1,16}",
            escape in "[a-zA-Z0-9_.-]{1,16}"
        ) {
            let allowed = format!("/sandbox/{root}");
            let candidate = format!("{allowed}/{child}/../{escape}");
            prop_assert!(!path_allowed(&candidate, &[allowed]));
        }

        #[test]
        fn sibling_prefix_never_inherits_root_authority(
            root in "[a-zA-Z0-9_-]{1,16}",
            suffix in "[a-zA-Z0-9_-]{1,16}",
            file in "[a-zA-Z0-9_.-]{1,16}"
        ) {
            let allowed = format!("/sandbox/{root}");
            let candidate = format!("/sandbox/{root}-{suffix}/{file}");
            prop_assert!(!path_allowed(&candidate, &[allowed]));
        }

        #[test]
        fn nul_is_always_rejected(prefix in ".{0,32}", suffix in ".{0,32}") {
            let with_nul = format!("{}\0{}", prefix, suffix);
            let rejected = normalize_path(&with_nul).is_none();
            prop_assert!(rejected);
        }
    }
}

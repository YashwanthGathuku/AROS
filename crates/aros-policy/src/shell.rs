const METACHARACTERS: &[char] = &[
    ';', '|', '&', '$', '`', '\n', '\r', '(', ')', '<', '>', '*', '?', '[', ']', '{', '}',
];

/// Reject argv smuggling that would be meaningful if a shell were interposed.
pub fn argv_contains_shell_metacharacters(argv: &[String]) -> bool {
    argv.iter()
        .any(|arg| arg.chars().any(|c| METACHARACTERS.contains(&c)))
}

pub fn executable_is_shell(name: &str) -> bool {
    let lower = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "csh"
            | "tcsh"
            | "fish"
            | "cmd.exe"
            | "cmd"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
    )
}

/// HTTP request lines never traverse a shell, so shell metacharacters are not
/// the relevant threat: request smuggling and header injection are. Reject
/// control characters, whitespace and non-absolute paths instead.
pub fn http_request_target_is_safe(target: &str) -> bool {
    target.starts_with('/')
        && !target.is_empty()
        && target
            .chars()
            .all(|c| !c.is_control() && !c.is_whitespace())
}

/// Cookie values share the header-injection threat model.
pub fn http_cookie_is_safe(cookie: &str) -> bool {
    !cookie.is_empty()
        && cookie
            .chars()
            .all(|c| !c.is_control() && c != '\n' && c != '\r')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_command_substitution() {
        assert!(argv_contains_shell_metacharacters(&[
            "echo".into(),
            "$(id)".into()
        ]));
        assert!(!argv_contains_shell_metacharacters(&[
            "rg".into(),
            "TODO".into()
        ]));
    }

    #[test]
    fn flags_shells() {
        assert!(executable_is_shell("/bin/bash"));
        assert!(executable_is_shell("cmd.exe"));
        assert!(!executable_is_shell("rg"));
    }
}

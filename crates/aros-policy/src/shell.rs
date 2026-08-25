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

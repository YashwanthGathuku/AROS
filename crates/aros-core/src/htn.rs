//! Hierarchical task network over class campaigns. No LLM.

use std::path::Path;

use crate::surface::SurfaceMap;

/// Observable facts compiled from a surface map and the target tree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HtnFacts {
    pub has_http_paths: bool,
    pub has_users: bool,
    pub has_files: bool,
    pub has_server: bool,
    pub has_parse: bool,
    pub has_once: bool,
}

pub fn facts_from(target: &Path, surface: &SurfaceMap) -> HtnFacts {
    let mut paths: Vec<&str> = surface.source_paths.iter().map(String::as_str).collect();
    paths.extend(surface.live.iter().map(|hit| hit.path.as_str()));
    paths.extend(surface.suggested_bind.values().map(String::as_str));
    let joined = paths.join(" ");
    HtnFacts {
        has_http_paths: !paths.is_empty(),
        has_users: joined.contains("/users"),
        has_files: joined.contains("/files"),
        has_server: target.join("server.py").is_file(),
        has_parse: target.join("parse.py").is_file(),
        has_once: target.join("once.py").is_file(),
    }
}

/// Compile skills + facts into an ordered campaign list (HTN / STRIPS-lite).
///
/// Skill mapping (deterministic, no model):
/// - reachability_boundary_mapping → http-surface-map
/// - negative_control_design → http-mr-cookie-drop
/// - trust_boundary_mapping → http-unauth
/// - assumption_attack → http-idor
/// - hidden_component_inference → http-cookie-confusion
/// - differential_experiment → http-mr-method
/// - parser_interpretation_disagreement → http-path-traversal, cli-crash
/// - fast_falsification → mutate-fuzz
/// - primitive_composition → lib-call-twice
pub fn htn_plan(facts: &HtnFacts, pack: &str) -> Vec<String> {
    let http = pack == "http" || pack == "all";
    let cli = pack == "cli" || pack == "all";
    let mut plan = Vec::new();
    if http && (facts.has_http_paths || facts.has_server) {
        plan.push("http-surface-map".into());
    }
    if http && facts.has_users {
        plan.push("http-mr-cookie-drop".into());
        plan.push("http-unauth".into());
        plan.push("http-idor".into());
        plan.push("http-cookie-confusion".into());
        plan.push("http-mr-method".into());
    }
    if http && facts.has_files {
        plan.push("http-path-traversal".into());
    }
    if cli && facts.has_parse {
        plan.push("cli-crash".into());
        plan.push("mutate-fuzz".into());
    }
    if cli && facts.has_once {
        plan.push("lib-call-twice".into());
    }
    plan
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::surface::SurfaceMap;
    use std::path::PathBuf;

    #[test]
    fn users_surface_plans_idor_not_path() {
        let surface = SurfaceMap {
            source_paths: vec!["/health".into(), "/users/2".into()],
            ..SurfaceMap::default()
        };
        let facts = facts_from(Path::new("."), &surface);
        let plan = htn_plan(&facts, "http");
        assert!(plan.contains(&"http-idor".into()), "{plan:?}");
        assert!(plan.contains(&"http-mr-cookie-drop".into()), "{plan:?}");
        assert!(!plan.contains(&"http-path-traversal".into()), "{plan:?}");
        assert!(!plan.contains(&"cli-crash".into()), "{plan:?}");
    }

    #[test]
    fn parser_tree_plans_cli_pack() {
        let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/vulnerable/parser");
        let facts = facts_from(&target, &SurfaceMap::default());
        let plan = htn_plan(&facts, "cli");
        assert_eq!(
            plan,
            vec!["cli-crash".to_string(), "mutate-fuzz".to_string()]
        );
    }
}

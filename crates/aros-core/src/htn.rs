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

/// One research skill mapped onto one or more catalog campaigns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkillTask {
    pub skill: &'static str,
    pub campaigns: &'static [&'static str],
}

/// Completeness table: every builtin JSON skill has at least one HTN task.
pub const SKILL_TASKS: &[SkillTask] = &[
    SkillTask {
        skill: "reachability_boundary_mapping",
        campaigns: &["http-surface-map"],
    },
    SkillTask {
        skill: "breadth_depth_context",
        campaigns: &["http-surface-map"],
    },
    SkillTask {
        skill: "negative_control_design",
        campaigns: &["http-mr-cookie-drop"],
    },
    SkillTask {
        skill: "trust_boundary_mapping",
        campaigns: &["http-unauth"],
    },
    SkillTask {
        skill: "assumption_attack",
        campaigns: &["http-idor"],
    },
    SkillTask {
        skill: "hidden_component_inference",
        campaigns: &["http-cookie-confusion"],
    },
    SkillTask {
        skill: "differential_experiment",
        campaigns: &["http-mr-method"],
    },
    SkillTask {
        skill: "attack_chain_reasoning",
        campaigns: &["http-mr-cross-user"],
    },
    SkillTask {
        skill: "anomaly_investigation",
        campaigns: &["http-mr-header-noise"],
    },
    SkillTask {
        skill: "discovery_cascade",
        campaigns: &["http-mr-query-noise"],
    },
    SkillTask {
        skill: "variant_analysis",
        campaigns: &["http-mr-query-noise", "http-mr-encoded-dotdot"],
    },
    SkillTask {
        skill: "incomplete_fix_search",
        campaigns: &["http-mr-method", "http-mr-encoded-dotdot"],
    },
    SkillTask {
        skill: "parser_interpretation_disagreement",
        campaigns: &["http-path-traversal", "cli-crash"],
    },
    SkillTask {
        skill: "representation_transformation_analysis",
        campaigns: &["http-mr-encoded-dotdot"],
    },
    SkillTask {
        skill: "source_to_sink",
        campaigns: &["http-path-traversal"],
    },
    SkillTask {
        skill: "sink_to_source",
        campaigns: &["http-path-traversal"],
    },
    SkillTask {
        skill: "fast_falsification",
        campaigns: &["mutate-fuzz"],
    },
    SkillTask {
        skill: "missed_bug_analysis",
        campaigns: &["mutate-fuzz"],
    },
    SkillTask {
        skill: "patch_archaeology",
        campaigns: &["klee-run"],
    },
    SkillTask {
        skill: "primitive_composition",
        campaigns: &["lib-call-twice"],
    },
];

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
        plan.push("http-mr-cross-user".into());
        plan.push("http-mr-header-noise".into());
        plan.push("http-mr-query-noise".into());
    }
    if http && facts.has_files {
        plan.push("http-path-traversal".into());
        plan.push("http-mr-encoded-dotdot".into());
    }
    if cli && facts.has_parse {
        plan.push("cli-crash".into());
        plan.push("mutate-fuzz".into());
        plan.push("klee-run".into());
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
    use std::collections::BTreeSet;
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
        assert!(plan.contains(&"http-mr-cross-user".into()), "{plan:?}");
        assert!(!plan.contains(&"http-path-traversal".into()), "{plan:?}");
        assert!(!plan.contains(&"cli-crash".into()), "{plan:?}");
    }

    #[test]
    fn files_surface_plans_encoded_dotdot() {
        let surface = SurfaceMap {
            source_paths: vec!["/health".into(), "/files".into()],
            ..SurfaceMap::default()
        };
        let facts = facts_from(Path::new("."), &surface);
        let plan = htn_plan(&facts, "http");
        assert!(plan.contains(&"http-path-traversal".into()), "{plan:?}");
        assert!(plan.contains(&"http-mr-encoded-dotdot".into()), "{plan:?}");
        assert!(!plan.contains(&"http-idor".into()), "{plan:?}");
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
            vec![
                "cli-crash".to_string(),
                "mutate-fuzz".to_string(),
                "klee-run".to_string()
            ]
        );
    }

    #[test]
    fn every_builtin_skill_has_an_htn_task() {
        let skills_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("skills/builtin");
        let mut disk = BTreeSet::new();
        for entry in std::fs::read_dir(&skills_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path).unwrap();
            let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
            let id = value["id"].as_str().unwrap();
            disk.insert(id.to_string());
        }
        let mapped: BTreeSet<&str> = SKILL_TASKS.iter().map(|task| task.skill).collect();
        for id in &disk {
            assert!(mapped.contains(id.as_str()), "unmapped skill {id}");
        }
        assert_eq!(disk.len(), 20, "expected 20 builtin skills, got {disk:?}");
    }
}

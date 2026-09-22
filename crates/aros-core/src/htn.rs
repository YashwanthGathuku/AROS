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
        campaigns: &["http-unauth", "http-mr-auth-header"],
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
        campaigns: &["http-mr-header-noise", "http-mr-xff"],
    },
    SkillTask {
        skill: "discovery_cascade",
        campaigns: &["http-mr-query-noise"],
    },
    SkillTask {
        skill: "variant_analysis",
        campaigns: &[
            "http-mr-query-noise",
            "http-mr-encoded-dotdot",
            "http-mr-dot-segment",
            "http-mr-encoded-dot",
            "http-mr-nested-dotdot",
            "http-mr-double-slash",
        ],
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
        campaigns: &[
            "http-mr-encoded-dotdot",
            "http-mr-dot-segment",
            "http-mr-encoded-dot",
            "http-mr-nested-dotdot",
            "http-mr-double-slash",
        ],
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
        campaigns: &["mutate-fuzz", "prop-ascii"],
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

pub const HTTP_USER_CAMPAIGNS: &[&str] = &[
    "http-mr-cookie-drop",
    "http-unauth",
    "http-idor",
    "http-cookie-confusion",
    "http-mr-method",
    "http-mr-cross-user",
    "http-mr-header-noise",
    "http-mr-query-noise",
    "http-mr-xff",
    "http-mr-auth-header",
];

pub const HTTP_FILE_CAMPAIGNS: &[&str] = &[
    "http-path-traversal",
    "http-mr-encoded-dotdot",
    "http-mr-dot-segment",
    "http-mr-encoded-dot",
    "http-mr-nested-dotdot",
    "http-mr-double-slash",
];

pub const CLI_PARSE_CAMPAIGNS: &[&str] = &["cli-crash", "mutate-fuzz", "prop-ascii", "klee-run"];

pub const CLI_ONCE_CAMPAIGNS: &[&str] = &["lib-call-twice"];

/// One recorded failure the planner is allowed to read. `spec_id` is a catalog
/// campaign id. Categories other than `TOOL_GAP` and `EXPERIMENT_INADEQUATE`
/// do not change the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureMemory {
    pub spec_id: String,
    pub category: String,
}

/// Result of applying failure memory. Skipped campaigns are not replaced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureReplan {
    pub campaigns: Vec<String>,
    pub skipped: Vec<String>,
    pub promoted: Vec<String>,
}

/// `TOOL_GAP` removes that campaign. `EXPERIMENT_INADEQUATE` moves it to the
/// front if it is still in the plan. Nothing is added that the facts did not
/// already justify.
pub fn apply_failure_memory(plan: &[String], memory: &[FailureMemory]) -> FailureReplan {
    let mut skipped = Vec::new();
    for item in memory {
        if item.category == "TOOL_GAP"
            && plan.iter().any(|id| id == &item.spec_id)
            && !skipped.contains(&item.spec_id)
        {
            skipped.push(item.spec_id.clone());
        }
    }
    let mut campaigns: Vec<String> = plan
        .iter()
        .filter(|id| !skipped.iter().any(|skip| skip == *id))
        .cloned()
        .collect();
    let mut promoted = Vec::new();
    for item in memory {
        if item.category != "EXPERIMENT_INADEQUATE" {
            continue;
        }
        if skipped.iter().any(|skip| skip == &item.spec_id) {
            continue;
        }
        if let Some(index) = campaigns.iter().position(|id| id == &item.spec_id) {
            if !promoted.contains(&item.spec_id) {
                let id = campaigns.remove(index);
                promoted.push(id);
            }
        }
    }
    for (offset, id) in promoted.iter().enumerate() {
        campaigns.insert(offset, id.clone());
    }
    FailureReplan {
        campaigns,
        skipped,
        promoted,
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
        plan.extend(HTTP_USER_CAMPAIGNS.iter().map(|id| (*id).to_string()));
    }
    if http && facts.has_files {
        plan.extend(HTTP_FILE_CAMPAIGNS.iter().map(|id| (*id).to_string()));
    }
    if cli && facts.has_parse {
        plan.extend(CLI_PARSE_CAMPAIGNS.iter().map(|id| (*id).to_string()));
    }
    if cli && facts.has_once {
        plan.extend(CLI_ONCE_CAMPAIGNS.iter().map(|id| (*id).to_string()));
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
    fn tool_gap_drops_a_campaign_without_inventing_a_replacement() {
        let plan = vec!["cli-crash".into(), "klee-run".into(), "mutate-fuzz".into()];
        let memory = vec![FailureMemory {
            spec_id: "klee-run".into(),
            category: "TOOL_GAP".into(),
        }];
        let replanned = apply_failure_memory(&plan, &memory);
        assert_eq!(replanned.skipped, vec!["klee-run".to_string()]);
        assert_eq!(
            replanned.campaigns,
            vec!["cli-crash".to_string(), "mutate-fuzz".to_string()]
        );
        assert!(replanned.promoted.is_empty());
    }

    #[test]
    fn missed_poc_is_planned_first_and_unknown_ids_are_not_added() {
        let plan = vec![
            "http-surface-map".into(),
            "http-unauth".into(),
            "http-idor".into(),
        ];
        let memory = vec![
            FailureMemory {
                spec_id: "not-a-real-campaign".into(),
                category: "EXPERIMENT_INADEQUATE".into(),
            },
            FailureMemory {
                spec_id: "http-idor".into(),
                category: "EXPERIMENT_INADEQUATE".into(),
            },
            FailureMemory {
                spec_id: "http-unauth".into(),
                category: "VERIFICATION_FAILURE".into(),
            },
        ];
        let replanned = apply_failure_memory(&plan, &memory);
        assert_eq!(replanned.promoted, vec!["http-idor".to_string()]);
        assert_eq!(replanned.campaigns[0], "http-idor");
        assert!(replanned.campaigns.contains(&"http-unauth".into()));
        assert!(!replanned
            .campaigns
            .iter()
            .any(|id| id == "not-a-real-campaign"));
        assert!(replanned.skipped.is_empty());
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
        assert!(plan.contains(&"http-mr-dot-segment".into()), "{plan:?}");
        assert!(plan.contains(&"http-mr-encoded-dot".into()), "{plan:?}");
        assert!(plan.contains(&"http-mr-nested-dotdot".into()), "{plan:?}");
        assert!(plan.contains(&"http-mr-double-slash".into()), "{plan:?}");
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
                "prop-ascii".to_string(),
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

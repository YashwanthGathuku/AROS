//! Classical planner over class campaigns. Fast Downward if present; else STRIPS.
//! No LLM. Absence of Fast Downward is not a security result.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::htn::{
    htn_plan, HtnFacts, CLI_ONCE_CAMPAIGNS, CLI_PARSE_CAMPAIGNS, HTTP_FILE_CAMPAIGNS,
    HTTP_USER_CAMPAIGNS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanSource {
    Strips,
    FastDownward,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignPlan {
    pub source: PlanSource,
    pub campaigns: Vec<String>,
    pub domain: String,
    pub problem: String,
}

#[derive(Clone, Copy, Debug)]
struct Action {
    id: &'static str,
    needs_mapped: bool,
    needs_users: bool,
    needs_files: bool,
    needs_parse: bool,
    needs_once: bool,
}

fn catalog() -> Vec<Action> {
    let mut out = vec![Action {
        id: "http-surface-map",
        needs_mapped: false,
        needs_users: false,
        needs_files: false,
        needs_parse: false,
        needs_once: false,
    }];
    for id in HTTP_USER_CAMPAIGNS {
        out.push(Action {
            id,
            needs_mapped: true,
            needs_users: true,
            needs_files: false,
            needs_parse: false,
            needs_once: false,
        });
    }
    for id in HTTP_FILE_CAMPAIGNS {
        out.push(Action {
            id,
            needs_mapped: true,
            needs_users: false,
            needs_files: true,
            needs_parse: false,
            needs_once: false,
        });
    }
    for id in CLI_PARSE_CAMPAIGNS {
        out.push(Action {
            id,
            needs_mapped: false,
            needs_users: false,
            needs_files: false,
            needs_parse: true,
            needs_once: false,
        });
    }
    for id in CLI_ONCE_CAMPAIGNS {
        out.push(Action {
            id,
            needs_mapped: false,
            needs_users: false,
            needs_files: false,
            needs_parse: false,
            needs_once: true,
        });
    }
    out
}

fn applicable(facts: &HtnFacts, pack: &str) -> Vec<Action> {
    let http = pack == "http" || pack == "all";
    let cli = pack == "cli" || pack == "all";
    catalog()
        .into_iter()
        .filter(|action| {
            if action.id.starts_with("http-") && !http {
                return false;
            }
            if (action.needs_parse || action.needs_once) && !cli {
                return false;
            }
            if action.id == "http-surface-map" {
                return facts.has_http_paths || facts.has_server;
            }
            if action.needs_users && !facts.has_users {
                return false;
            }
            if action.needs_files && !facts.has_files {
                return false;
            }
            if action.needs_parse && !facts.has_parse {
                return false;
            }
            if action.needs_once && !facts.has_once {
                return false;
            }
            true
        })
        .collect()
}

/// Forward STRIPS search. Action order is the HTN catalog (heuristic in code, then search).
pub fn strips_plan(facts: &HtnFacts, pack: &str) -> Vec<String> {
    let actions = applicable(facts, pack);
    let goal: BTreeSet<&str> = actions.iter().map(|action| action.id).collect();
    if goal.is_empty() {
        return Vec::new();
    }
    let start_mapped = !actions.iter().any(|action| action.id == "http-surface-map");
    let start: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<(bool, BTreeSet<String>, Vec<String>)> = VecDeque::new();
    queue.push_back((start_mapped, start, Vec::new()));
    let mut seen: BTreeSet<(bool, Vec<String>)> = BTreeSet::new();
    while let Some((mapped, ran, path)) = queue.pop_front() {
        let mut ran_keys: Vec<String> = ran.iter().cloned().collect();
        ran_keys.sort();
        if !seen.insert((mapped, ran_keys)) {
            continue;
        }
        if goal.iter().all(|id| ran.contains(*id)) {
            return path;
        }
        for action in &actions {
            if ran.contains(action.id) {
                continue;
            }
            if action.needs_mapped && !mapped {
                continue;
            }
            let mut next_ran = ran.clone();
            next_ran.insert(action.id.to_string());
            let mut next_path = path.clone();
            next_path.push(action.id.to_string());
            let next_mapped = mapped || action.id == "http-surface-map";
            queue.push_back((next_mapped, next_ran, next_path));
        }
    }
    htn_plan(facts, pack)
}

fn pddl_pred(id: &str) -> String {
    format!("ran-{id}")
}

pub fn emit_domain() -> String {
    let mut body = String::from(
        "(define (domain aros-gate)\n  (:requirements :strips)\n  (:predicates\n    (mapped)\n    (has-users)\n    (has-files)\n    (has-parse)\n    (has-once)\n",
    );
    for action in catalog() {
        body.push_str(&format!("    ({})\n", pddl_pred(action.id)));
    }
    body.push_str("  )\n");
    for action in catalog() {
        let mut pre = Vec::new();
        if action.needs_mapped {
            pre.push("(mapped)".to_string());
        }
        if action.needs_users {
            pre.push("(has-users)".to_string());
        }
        if action.needs_files {
            pre.push("(has-files)".to_string());
        }
        if action.needs_parse {
            pre.push("(has-parse)".to_string());
        }
        if action.needs_once {
            pre.push("(has-once)".to_string());
        }
        let precond = if pre.is_empty() {
            "(and)".to_string()
        } else {
            format!("(and {})", pre.join(" "))
        };
        let mut effect = vec![format!("({})", pddl_pred(action.id))];
        if action.id == "http-surface-map" {
            effect.push("(mapped)".into());
        }
        body.push_str(&format!(
            "  (:action {}\n    :parameters ()\n    :precondition {}\n    :effect (and {}))\n",
            action.id,
            precond,
            effect.join(" ")
        ));
    }
    body.push_str(")\n");
    body
}

pub fn emit_problem(facts: &HtnFacts, pack: &str) -> String {
    let mut init = Vec::new();
    let needs_map = (pack == "http" || pack == "all") && (facts.has_http_paths || facts.has_server);
    if !needs_map {
        init.push("(mapped)".to_string());
    }
    if facts.has_users {
        init.push("(has-users)".into());
    }
    if facts.has_files {
        init.push("(has-files)".into());
    }
    if facts.has_parse {
        init.push("(has-parse)".into());
    }
    if facts.has_once {
        init.push("(has-once)".into());
    }
    let init_s = if init.is_empty() {
        "(and)".to_string()
    } else {
        format!("(and {})", init.join(" "))
    };
    let goal: Vec<String> = applicable(facts, pack)
        .iter()
        .map(|action| format!("({})", pddl_pred(action.id)))
        .collect();
    let goal_s = if goal.is_empty() {
        "(and)".to_string()
    } else {
        format!("(and {})", goal.join(" "))
    };
    format!(
        "(define (problem aros-target)\n  (:domain aros-gate)\n  (:init {init_s})\n  (:goal {goal_s})\n)\n"
    )
}

fn which_fast_downward() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("AROS_FAST_DOWNWARD") {
        let path = PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
    }
    let names = ["fast-downward", "fast-downward.py"];
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            names.iter().find_map(|name| {
                let p = dir.join(name);
                p.is_file().then_some(p)
            })
        })
    })
}

fn parse_sas_plan(raw: &str, allowed: &BTreeSet<String>) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with("cost") {
            continue;
        }
        let name = line.trim_start_matches('(').trim_end_matches(')').trim();
        let id = name.split_whitespace().next().unwrap_or("");
        if allowed.contains(id) {
            out.push(id.to_string());
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn try_fast_downward(facts: &HtnFacts, pack: &str, work: Option<&Path>) -> Option<Vec<String>> {
    let engine = which_fast_downward()?;
    let allowed: BTreeSet<String> = applicable(facts, pack)
        .iter()
        .map(|action| action.id.to_string())
        .collect();
    let dir = match work {
        Some(path) => path.to_path_buf(),
        None => return None,
    };
    let domain_path = dir.join("domain.pddl");
    let problem_path = dir.join("problem.pddl");
    fs::write(&domain_path, emit_domain()).ok()?;
    fs::write(&problem_path, emit_problem(facts, pack)).ok()?;
    let mut argv = if engine.extension().and_then(|ext| ext.to_str()) == Some("py") {
        vec!["python".to_string(), engine.to_string_lossy().into_owned()]
    } else {
        vec![engine.to_string_lossy().into_owned()]
    };
    argv.push(domain_path.to_string_lossy().into_owned());
    argv.push(problem_path.to_string_lossy().into_owned());
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd.output().ok()?;
    let sas = dir.join("sas_plan");
    let raw = if sas.is_file() {
        fs::read_to_string(sas).ok()?
    } else {
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let plan = parse_sas_plan(&raw, &allowed)?;
    let missing = allowed.iter().any(|id| !plan.contains(id));
    if missing {
        None
    } else {
        Some(plan)
    }
}

/// Plan class campaigns. Fast Downward when present and complete; otherwise STRIPS.
pub fn plan_campaigns(facts: &HtnFacts, pack: &str, work: Option<&Path>) -> CampaignPlan {
    let domain = emit_domain();
    let problem = emit_problem(facts, pack);
    if let Some(campaigns) = try_fast_downward(facts, pack, work) {
        return CampaignPlan {
            source: PlanSource::FastDownward,
            campaigns,
            domain,
            problem,
        };
    }
    CampaignPlan {
        source: PlanSource::Strips,
        campaigns: strips_plan(facts, pack),
        domain,
        problem,
    }
}

pub fn write_pddl(work: &Path, plan: &CampaignPlan) -> std::io::Result<()> {
    fs::create_dir_all(work)?;
    fs::write(work.join("domain.pddl"), &plan.domain)?;
    fs::write(work.join("problem.pddl"), &plan.problem)?;
    fs::write(work.join("plan.txt"), plan.campaigns.join("\n") + "\n")?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::htn::facts_from;
    use crate::surface::SurfaceMap;
    use std::path::Path;

    #[test]
    fn strips_matches_htn_on_users_surface() {
        let surface = SurfaceMap {
            source_paths: vec!["/health".into(), "/users/2".into()],
            ..SurfaceMap::default()
        };
        let facts = facts_from(Path::new("."), &surface);
        assert_eq!(strips_plan(&facts, "http"), htn_plan(&facts, "http"));
        assert!(strips_plan(&facts, "http").contains(&"http-idor".into()));
        assert!(strips_plan(&facts, "http").contains(&"http-mr-xff".into()));
    }

    #[test]
    fn domain_declares_idor_action() {
        let domain = emit_domain();
        assert!(domain.contains("(:action http-idor"), "{domain}");
        assert!(domain.contains("(mapped)"), "{domain}");
    }

    #[test]
    fn missing_work_dir_does_not_invent_fast_downward() {
        let facts = HtnFacts {
            has_http_paths: true,
            has_users: true,
            ..HtnFacts::default()
        };
        let plan = plan_campaigns(&facts, "http", None);
        assert_eq!(plan.source, PlanSource::Strips);
        assert!(!plan.campaigns.is_empty());
    }

    #[test]
    fn parse_sas_plan_reads_campaign_ids() {
        let allowed = ["http-surface-map", "http-idor"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let parsed =
            parse_sas_plan("(http-surface-map)\n(http-idor)\n; cost = 2\n", &allowed).unwrap();
        assert_eq!(
            parsed,
            vec!["http-surface-map".to_string(), "http-idor".to_string()]
        );
    }
}

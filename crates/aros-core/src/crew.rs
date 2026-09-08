//! Deterministic multi-agent crew. Roles propose and record; none is an LLM.

use std::path::Path;

use crate::engine::EngineError;
use crate::gate::{run_release_gate, GateResult};
use crate::htn::{facts_from, htn_plan};
use crate::surface::{map_http_surface, write_surface_map, SurfaceMap};

/// Named roles. Execution is still `run_release_gate` / campaign oracles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrewRole {
    Mapper,
    Planner,
    Runner,
    Shrinker,
    Scribe,
}

#[derive(Clone, Debug)]
pub struct CrewReport {
    pub roles: Vec<&'static str>,
    pub plan: Vec<String>,
    pub surface: SurfaceMap,
    pub gate: GateResult,
}

/// Mapper → Planner (HTN) → Runner (class campaigns) → Scribe.
/// Shrinker is applied inside mutate-fuzz/cli-crash harnesses, not here.
pub fn run_deterministic_crew(
    target: &Path,
    work: &Path,
    pack: &str,
    waive_containment: bool,
) -> Result<CrewReport, EngineError> {
    let surface = map_http_surface(target, None)?;
    write_surface_map(&work.join("surface.json"), &surface)?;
    let facts = facts_from(target, &surface);
    let plan = htn_plan(&facts, pack);
    let gate = run_release_gate(target, work, pack, waive_containment)?;
    Ok(CrewReport {
        roles: vec!["mapper", "planner", "runner", "shrinker", "scribe"],
        plan,
        surface,
        gate,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn crew_plans_http_classes_for_authz_fixture() {
        let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/vulnerable/authz");
        let work = tempfile::tempdir().unwrap();
        let report = run_deterministic_crew(&target, work.path(), "http", true).unwrap();
        assert!(
            report.plan.iter().any(|id| id == "http-idor"),
            "{:?}",
            report.plan
        );
        assert!(report.roles.contains(&"planner"));
        assert!(
            report.gate.verified.iter().any(|id| id == "http-idor"),
            "{:?}",
            report.gate.verified
        );
    }
}

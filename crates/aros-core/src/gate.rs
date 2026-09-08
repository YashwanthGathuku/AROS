//! Release gate: map surface, run class campaigns, fail on verified bugs or missing containment.

use std::fs;
use std::path::{Path, PathBuf};

use aros_sandbox::RootlessOciSandboxProvider;

use crate::campaign_loader::{
    class_campaign_dir, default_declared_manifest, load_campaign_file, overlay_surface_bind,
};
use crate::engine::{CampaignEngine, EngineError};
use crate::htn::facts_from;
use crate::pddl::{plan_campaigns, write_pddl};
use crate::surface::{map_http_surface, write_surface_map, SurfaceMap};

#[derive(Clone, Debug)]
pub struct GateResult {
    pub contained: bool,
    pub live_oci: bool,
    pub containment_blocked: bool,
    pub verified: Vec<String>,
    pub held: Vec<String>,
    pub errors: Vec<String>,
    pub report_path: PathBuf,
    pub surface_path: PathBuf,
}

pub fn run_release_gate(
    target: &Path,
    work: &Path,
    pack: &str,
    waive_containment: bool,
) -> Result<GateResult, EngineError> {
    fs::create_dir_all(work)?;
    let live_oci = RootlessOciSandboxProvider::detect()
        .probe_containment()
        .live_oci_claimable();
    let contained = !waive_containment && live_oci;
    if !waive_containment && !live_oci {
        let report_path = work.join("gate-report.html");
        fs::write(
            &report_path,
            "<!DOCTYPE html><html><body><p>containment cannot be shown; gate fail-closed</p></body></html>",
        )?;
        return Ok(GateResult {
            contained: false,
            live_oci: false,
            containment_blocked: true,
            verified: Vec::new(),
            held: Vec::new(),
            errors: vec!["containment cannot be shown".into()],
            report_path,
            surface_path: work.join("surface.json"),
        });
    }

    let surface = map_http_surface(target, None)?;
    let surface_path = work.join("surface.json");
    write_surface_map(&surface_path, &surface)?;

    let class_dir = class_campaign_dir().ok_or_else(|| {
        EngineError::FailClosed("campaign-loader/classes is not available".into())
    })?;
    let engine = CampaignEngine::new(waive_containment);
    let mut verified = Vec::new();
    let mut held = Vec::new();
    let mut errors = Vec::new();
    let facts = facts_from(target, &surface);
    let planned = plan_campaigns(&facts, pack, Some(work));
    let _ = write_pddl(work, &planned);
    let planned = planned.campaigns;
    for spec_path in class_files(&class_dir, pack, &planned)? {
        let mut spec = load_campaign_file(&spec_path)?;
        overlay_surface_bind(&mut spec, &surface);
        let run_work = work.join(&spec.id);
        let manifest = default_declared_manifest(target);
        match engine.run_declared_campaign(&spec, target, &run_work, manifest) {
            Ok(out) => {
                let verified_finding = out.finding.as_ref().is_some_and(|finding| finding.verified);
                if verified_finding {
                    verified.push(spec.id);
                } else {
                    held.push(spec.id);
                }
            }
            Err(error) => errors.push(format!("{}: {error}", spec.id)),
        }
    }

    let report_path = work.join("gate-report.html");
    fs::write(
        &report_path,
        gate_html(&surface, &verified, &held, &errors, contained, live_oci),
    )?;
    Ok(GateResult {
        contained,
        live_oci,
        containment_blocked: false,
        verified,
        held,
        errors,
        report_path,
        surface_path,
    })
}

fn class_files(dir: &Path, pack: &str, planned: &[String]) -> Result<Vec<PathBuf>, EngineError> {
    if !planned.is_empty() {
        return Ok(planned
            .iter()
            .map(|id| dir.join(format!("{id}.campaign.json")))
            .filter(|path| path.is_file())
            .collect());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let include = match pack {
            "http" => name.starts_with("http-"),
            "cli" => {
                name.starts_with("cli-")
                    || name.starts_with("lib-")
                    || name.starts_with("mutate-")
                    || name.starts_with("klee-")
                    || name.starts_with("prop-")
            }
            "all" => true,
            _ => name.starts_with(pack),
        };
        if include {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn gate_html(
    surface: &SurfaceMap,
    verified: &[String],
    held: &[String],
    errors: &[String],
    contained: bool,
    live_oci: bool,
) -> String {
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>AROS release gate</title></head><body>\
         <h1>AROS release gate</h1>\
         <p><b>contained</b> {contained} <b>live_oci</b> {live_oci}</p>\
         <p><b>verified (block ship)</b> {}</p>\
         <p><b>held</b> {}</p>\
         <p><b>errors</b> {}</p>\
         <p><b>source paths</b> {}</p>\
         </body></html>",
        html(&verified.join(", ")),
        html(&held.join(", ")),
        html(&errors.join("; ")),
        html(&surface.source_paths.join(" ")),
    )
}

fn html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(parts: &[&str]) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        for part in parts {
            path.push(part);
        }
        path
    }

    #[test]
    fn gate_without_containment_fails_closed() {
        let work = tempfile::tempdir().unwrap();
        let result = run_release_gate(
            &fixture(&["fixtures", "patched", "authz"]),
            work.path(),
            "http",
            false,
        )
        .unwrap();
        assert!(result.containment_blocked);
        assert!(!result.contained);
    }

    #[test]
    fn waived_gate_blocks_vulnerable_authz() {
        let work = tempfile::tempdir().unwrap();
        let result = run_release_gate(
            &fixture(&["fixtures", "vulnerable", "authz"]),
            work.path(),
            "http",
            true,
        )
        .unwrap();
        assert!(!result.containment_blocked);
        assert!(
            result.verified.iter().any(|id| id == "http-idor"),
            "{:?}",
            result.verified
        );
    }

    #[test]
    fn waived_gate_allows_patched_authz_http_pack() {
        let work = tempfile::tempdir().unwrap();
        let result = run_release_gate(
            &fixture(&["fixtures", "patched", "authz"]),
            work.path(),
            "http",
            true,
        )
        .unwrap();
        assert!(!result.containment_blocked);
        assert!(
            result.verified.is_empty(),
            "patched authz must not verify http classes: {:?}",
            result.verified
        );
    }
}

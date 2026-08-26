//! Independent verifier. Must not receive attacker hidden reasoning.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use aros_evidence::{BuiltinEvidenceAuthority, EvidenceAuthority};
use aros_types::{AuthorityResult, EvidenceBundle, EvidenceLevel, Finding, TargetId, VerifierMode, VerifierRun};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierReplaySpec {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub cookie: Option<String>,
    pub expected_substring: String,
    /// Read-only target tree whose digest must match the attacker's original snapshot.
    pub snapshot_root: String,
    pub expected_tree_digest: String,
}

/// Minimal payload given to the independent verifier. It contains a reproduction
/// recipe and immutable target identity, never the attacker's observation or a
/// precomputed oracle-hit boolean.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierInput {
    pub claim: String,
    pub snapshot_id: String,
    pub candidate_reproduction: Option<String>,
    pub oracle_contract: String,
    pub invariant: String,
    pub replay: VerifierReplaySpec,
    pub attacker_hidden_reasoning: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierProcessResult {
    pub result: String,
    pub accepted: bool,
    pub reason: String,
    pub fresh_snapshot_matched: bool,
    pub replay_executed: bool,
    pub oracle_observed: bool,
}

pub fn reduced_input(
    finding: &Finding,
    bundle: &EvidenceBundle,
    mode: VerifierMode,
    oracle: &str,
    invariant: &str,
    replay: VerifierReplaySpec,
) -> VerifierInput {
    VerifierInput {
        claim: finding.claim.clone(),
        snapshot_id: bundle.snapshot_id.to_string(),
        candidate_reproduction: match mode {
            VerifierMode::ReproduceCandidate => bundle.artifact_digests.first().cloned(),
            VerifierMode::Blindish => None,
        },
        oracle_contract: oracle.to_string(),
        invariant: invariant.to_string(),
        replay,
        attacker_hidden_reasoning: false,
    }
}

pub fn adjudicate(bundle: &EvidenceBundle, run: &VerifierRun) -> AuthorityResult {
    BuiltinEvidenceAuthority.adjudicate(bundle, run)
}

pub fn accepts_true_finding(level: EvidenceLevel, result: AuthorityResult) -> bool {
    result == AuthorityResult::Verified && level >= EvidenceLevel::E4IndependentReproduction
}

fn rejected(reason: impl Into<String>) -> VerifierProcessResult {
    VerifierProcessResult { result: "Rejected".into(), accepted: false, reason: reason.into(), fresh_snapshot_matched: false, replay_executed: false, oracle_observed: false }
}

/// Pure adjudication helper for tests/non-production reasoning. This helper can
/// never by itself establish E4; production E4 must come from verify_in_subprocess.
pub fn adjudicate_from_input(input: &VerifierInput, observed_oracle_hit: bool) -> VerifierProcessResult {
    if input.attacker_hidden_reasoning { return rejected("attacker_hidden_reasoning must not be supplied to independent verifier"); }
    if input.claim.is_empty() || input.oracle_contract.is_empty() { return rejected("claim and oracle_contract are required"); }
    VerifierProcessResult {
        result: if observed_oracle_hit { "Verified" } else { "NonReproducible" }.into(),
        accepted: observed_oracle_hit,
        reason: if observed_oracle_hit { "oracle contract matched supplied test observation" } else { "oracle contract did not match supplied test observation" }.into(),
        fresh_snapshot_matched: false,
        replay_executed: false,
        oracle_observed: observed_oracle_hit,
    }
}

pub fn verifier_bin_present() -> bool { resolve_verifier_bin().is_some() }

fn resolve_verifier_bin() -> Option<std::path::PathBuf> {
    if let Ok(explicit) = std::env::var("AROS_VERIFIER") { let p=std::path::PathBuf::from(explicit); if p.is_file() { return Some(p); } }
    if let Ok(current)=std::env::current_exe() {
        let mut dirs=Vec::new(); if let Some(dir)=current.parent() { dirs.push(dir.to_path_buf()); if let Some(parent)=dir.parent(){dirs.push(parent.to_path_buf());} }
        for dir in dirs { for name in ["aros-verifier","aros-verifier.exe"] { let p=dir.join(name); if p.is_file(){return Some(p);} } }
    }
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).find_map(|dir| { let p=dir.join("aros-verifier"); if p.is_file(){return Some(p);} let exe=p.with_extension("exe"); exe.is_file().then_some(exe) }))
}

/// Production independent verification. No in-process fallback is permitted:
/// absence/failure of the verifier process is INSUFFICIENT_EVIDENCE at the caller.
pub fn verify_in_subprocess(input: &VerifierInput) -> Result<VerifierProcessResult, String> {
    if input.attacker_hidden_reasoning { return Err("independent verifier input contains attacker hidden reasoning".into()); }
    let bin = resolve_verifier_bin().ok_or_else(|| "INDEPENDENT_VERIFIER_UNAVAILABLE: aros-verifier binary not found".to_string())?;
    let mut child=Command::new(&bin).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e|format!("spawn aros-verifier: {e}"))?;
    { let mut stdin=child.stdin.take().ok_or_else(||"missing stdin".to_string())?; let payload=serde_json::to_vec(input).map_err(|e|e.to_string())?; stdin.write_all(&payload).map_err(|e|e.to_string())?; }
    let mut stdout=child.stdout.take().ok_or_else(||"missing stdout".to_string())?; let mut out=Vec::new(); stdout.read_to_end(&mut out).map_err(|e|e.to_string())?;
    let status=child.wait().map_err(|e|e.to_string())?;
    if !status.success(){ return Err(format!("aros-verifier exited {:?}: {}",status.code(),String::from_utf8_lossy(&out))); }
    serde_json::from_slice(&out).map_err(|e|e.to_string())
}

/// Executed only in the dedicated verifier process. It creates a fresh snapshot
/// of the authorized target tree, requires exact digest equality, performs the
/// replay itself, and evaluates the oracle from its own observation.
pub fn verify_input_independently(input: &VerifierInput) -> VerifierProcessResult {
    if input.attacker_hidden_reasoning { return rejected("attacker hidden reasoning supplied"); }
    if input.claim.is_empty() || input.oracle_contract.is_empty() || input.replay.expected_substring.is_empty() { return rejected("incomplete verifier input"); }

    let root=std::path::Path::new(&input.replay.snapshot_root);
    let snapshot=match crate::snapshot::snapshot_tree(TargetId::new(),root) { Ok(s)=>s, Err(e)=>return rejected(format!("fresh verifier snapshot failed: {e}")) };
    if snapshot.source_tree_digest != input.replay.expected_tree_digest {
        return VerifierProcessResult { result:"Rejected".into(), accepted:false, reason:"exact target digest differs from attacker snapshot".into(), fresh_snapshot_matched:false, replay_executed:false, oracle_observed:false };
    }

    let response=match crate::http_lab::http_get(&input.replay.host,input.replay.port,&input.replay.path,input.replay.cookie.as_deref()) {
        Ok(r)=>r,
        Err(e)=>return VerifierProcessResult { result:"NonReproducible".into(), accepted:false, reason:format!("independent replay failed: {e}"), fresh_snapshot_matched:true, replay_executed:false, oracle_observed:false },
    };
    let hit=response.body.contains(&input.replay.expected_substring);
    VerifierProcessResult { result:if hit{"Verified"}else{"NonReproducible"}.into(), accepted:hit, reason:if hit{"oracle contract matched on verifier-owned replay"}else{"oracle contract did not match on verifier-owned replay"}.into(), fresh_snapshot_matched:true, replay_executed:true, oracle_observed:hit }
}

pub fn run_verifier_child_main(_args: &[String]) -> i32 {
    let mut buf=Vec::new(); if std::io::stdin().read_to_end(&mut buf).is_err(){return 2;}
    let input:VerifierInput=match serde_json::from_slice(&buf){Ok(v)=>v,Err(_)=>return 3};
    let result=verify_input_independently(&input);
    if let Ok(bytes)=serde_json::to_vec(&result){let _=std::io::stdout().write_all(&bytes);0}else{4}
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aros_types::{CampaignId, FindingId, HypothesisId, SnapshotId};

    fn replay() -> VerifierReplaySpec { VerifierReplaySpec { host:"127.0.0.1".into(), port:1, path:"/".into(), cookie:None, expected_substring:"secret".into(), snapshot_root:".".into(), expected_tree_digest:"digest".into() } }

    #[test] fn verifier_does_not_include_attacker_notes() {
        let finding=Finding{id:FindingId::new(),campaign_id:CampaignId::new(),hypothesis_id:HypothesisId::new(),claim:"idor".into(),evidence_level:EvidenceLevel::E3InvariantViolation,manifest_hash:"h".into(),verified:false};
        let bundle=EvidenceBundle{finding_id:finding.id,campaign_id:finding.campaign_id,manifest_hash:"h".into(),snapshot_id:SnapshotId::new(),sandbox_id:None,claim:finding.claim.clone(),artifact_digests:vec!["abc".into()],level:EvidenceLevel::E3InvariantViolation};
        let input=reduced_input(&finding,&bundle,VerifierMode::Blindish,"secret-not-returned","tenant isolation",replay()); assert!(!input.attacker_hidden_reasoning); assert!(input.candidate_reproduction.is_none());
    }
    #[test] fn pure_helper_cannot_claim_fresh_reproduction() { let input=VerifierInput{claim:"x".into(),snapshot_id:"s".into(),candidate_reproduction:None,oracle_contract:"o".into(),invariant:"i".into(),replay:replay(),attacker_hidden_reasoning:false}; let r=adjudicate_from_input(&input,true); assert!(r.accepted); assert!(!r.fresh_snapshot_matched); assert!(!r.replay_executed); }
    #[test] fn rejects_attacker_hidden_reasoning_flag() { let input=VerifierInput{claim:"x".into(),snapshot_id:"s".into(),candidate_reproduction:None,oracle_contract:"o".into(),invariant:"i".into(),replay:replay(),attacker_hidden_reasoning:true}; assert!(!adjudicate_from_input(&input,true).accepted); }
}

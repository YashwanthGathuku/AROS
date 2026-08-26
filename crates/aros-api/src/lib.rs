#![forbid(unsafe_code)]

pub mod campaign;
pub mod lab;
pub mod registry;

pub use campaign::{
    run_fixture_campaign, seed_fixture, spawn_fixture_server, FixtureCampaignRequest,
    FixtureCampaignResponse, FixtureKindParam,
};
pub use lab::{
    canonicalize_lab_root, capability_from_str, decision_str, intent_from_request, lab_manifest,
    lab_manifest_from_root, LabRuntime, ToolIntentRequest, ToolIntentResponse,
};
pub use registry::{CampaignRecord, CampaignRegistry};

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::RequestId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCapability {
    ReadFile,
    ListTree,
    SearchText,
    GitInspect,
    RunTests,
    RunLanguageTool,
    HttpRequest,
    BrowserRequest,
    ExecuteAllowlistedBinary,
    CollectLogs,
    CollectFile,
    CollectProcessState,
    FuzzAdapter,
    SanitizerAdapter,
    StaticAnalysisAdapter,
}

impl ToolCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadFile => "read_file",
            Self::ListTree => "list_tree",
            Self::SearchText => "search_text",
            Self::GitInspect => "git_inspect",
            Self::RunTests => "run_tests",
            Self::RunLanguageTool => "run_language_tool",
            Self::HttpRequest => "http_request",
            Self::BrowserRequest => "browser_request",
            Self::ExecuteAllowlistedBinary => "execute_allowlisted_binary",
            Self::CollectLogs => "collect_logs",
            Self::CollectFile => "collect_file",
            Self::CollectProcessState => "collect_process_state",
            Self::FuzzAdapter => "fuzz_adapter",
            Self::SanitizerAdapter => "sanitizer_adapter",
            Self::StaticAnalysisAdapter => "static_analysis_adapter",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkIntent {
    pub host: String,
    pub port: u16,
    pub protocol: crate::enums::ProtocolKind,
}

/// Unvalidated worker request. Policy must convert this to an authorized intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolIntent {
    pub request_id: RequestId,
    pub capability: ToolCapability,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub path: Option<String>,
    pub content_glob: Option<String>,
    pub network: Option<NetworkIntent>,
    /// HTTP request-target. Not argv. Query strings are valid here.
    pub http_target: Option<String>,
    /// Optional Cookie header value. Not argv.
    pub http_cookie: Option<String>,
    pub timeout_ms: u64,
}

impl ToolIntent {
    pub fn new(capability: ToolCapability) -> Self {
        Self {
            request_id: RequestId::new(),
            capability,
            argv: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            path: None,
            content_glob: None,
            network: None,
            http_target: None,
            http_cookie: None,
            timeout_ms: 30_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub request_id: RequestId,
    pub capability: ToolCapability,
    pub decision: crate::enums::PolicyDecision,
    pub executable: Option<String>,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub sandbox_id: Option<String>,
    pub started_unix_ms: u64,
    pub finished_unix_ms: u64,
    pub exit_status: Option<i32>,
    pub stdout_digest: Option<String>,
    pub stderr_digest: Option<String>,
    pub manifest_hash: String,
    pub deny_reason: Option<String>,
}

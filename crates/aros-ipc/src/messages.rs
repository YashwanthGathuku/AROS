use prost::Message;

pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;

#[derive(Clone, PartialEq, Message)]
pub struct Envelope {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub request_id: String,
    #[prost(oneof = "envelope::Kind", tags = "10, 11, 12, 13, 14, 15, 16")]
    pub kind: Option<envelope::Kind>,
}

pub mod envelope {
    use prost::Oneof;

    #[derive(Clone, PartialEq, Oneof)]
    pub enum Kind {
        #[prost(message, tag = "10")]
        Hello(super::Hello),
        #[prost(message, tag = "11")]
        HelloAck(super::HelloAck),
        #[prost(message, tag = "12")]
        ToolIntent(super::ToolIntentMsg),
        #[prost(message, tag = "13")]
        IntentResult(super::IntentResult),
        #[prost(message, tag = "14")]
        Heartbeat(super::Heartbeat),
        #[prost(message, tag = "15")]
        Error(super::ErrorMsg),
        #[prost(message, tag = "16")]
        Shutdown(super::Shutdown),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Hello {
    #[prost(string, tag = "1")]
    pub worker_kind: String,
    #[prost(string, tag = "2")]
    pub python_version: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct HelloAck {
    #[prost(string, tag = "1")]
    pub daemon_version: String,
    #[prost(uint32, tag = "2")]
    pub max_frame_bytes: u32,
    #[prost(string, tag = "3")]
    pub campaign_id: String,
    #[prost(string, tag = "4")]
    pub manifest_hash: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ToolIntentMsg {
    #[prost(string, tag = "1")]
    pub capability: String,
    #[prost(string, repeated, tag = "2")]
    pub argv: Vec<String>,
    #[prost(string, optional, tag = "3")]
    pub cwd: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub path: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub host: Option<String>,
    #[prost(uint32, optional, tag = "6")]
    pub port: Option<u32>,
    #[prost(string, optional, tag = "7")]
    pub protocol: Option<String>,
    #[prost(uint64, tag = "8")]
    pub timeout_ms: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct IntentResult {
    #[prost(string, tag = "1")]
    pub decision: String,
    #[prost(string, tag = "2")]
    pub reason: String,
    #[prost(int32, optional, tag = "3")]
    pub exit_status: Option<i32>,
    #[prost(string, optional, tag = "4")]
    pub stdout_digest: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Heartbeat {
    #[prost(uint64, tag = "1")]
    pub unix_ms: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct ErrorMsg {
    #[prost(string, tag = "1")]
    pub code: String,
    #[prost(string, tag = "2")]
    pub message: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Shutdown {
    #[prost(string, tag = "1")]
    pub reason: String,
}

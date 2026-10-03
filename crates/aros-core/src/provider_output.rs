//! Bounded parsing of external-provider output.
//!
//! Provider output is data, never instructions or an AROS verdict.

use serde::{Deserialize, Serialize};

const MAX_PROVIDER_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 20_000;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProviderRecord {
    pub provider: String,
    pub record_type: String,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderParseSummary {
    pub provider: String,
    pub records: usize,
    pub rejected_lines: usize,
    pub truncated: bool,
}

pub fn parse_ndjson(
    provider: &str,
    bytes: &[u8],
) -> Result<(Vec<ProviderRecord>, ProviderParseSummary), String> {
    if bytes.len() > MAX_PROVIDER_BYTES {
        return Err(format!(
            "{provider} output exceeds {} byte ingestion limit",
            MAX_PROVIDER_BYTES
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{provider} output is not UTF-8"))?;
    let mut records = Vec::new();
    let mut rejected = 0usize;
    let mut truncated = false;

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if records.len() >= MAX_RECORDS {
            truncated = true;
            break;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(payload) if payload.is_object() => {
                let record_type = payload
                    .get("record_type")
                    .and_then(|v| v.as_str())
                    .or_else(|| payload.get("type").and_then(|v| v.as_str()))
                    .unwrap_or("record")
                    .to_string();
                records.push(ProviderRecord {
                    provider: provider.to_string(),
                    record_type,
                    payload,
                });
            }
            _ => rejected += 1,
        }
    }

    Ok((
        records,
        ProviderParseSummary {
            provider: provider.to_string(),
            records: records.len(),
            rejected_lines: rejected,
            truncated,
        },
    ))
}

pub fn parse_grok_json(bytes: &[u8]) -> Result<ProviderRecord, String> {
    if bytes.len() > MAX_PROVIDER_BYTES {
        return Err("grok-build output exceeds ingestion limit".into());
    }
    let payload: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid Grok JSON: {e}"))?;
    Ok(ProviderRecord {
        provider: "grok-build".into(),
        record_type: "research_harness_output".into(),
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bumblebee_style_ndjson_without_promoting_meaning() {
        let input = br#"{"record_type":"component","ecosystem":"npm","name":"x","version":"1"}
{"record_type":"finding","id":"lead-1"}
not-json
"#;
        let (records, summary) = parse_ndjson("bumblebee", input).expect("parse");
        assert_eq!(records.len(), 2);
        assert_eq!(summary.rejected_lines, 1);
        assert_eq!(records[1].record_type, "finding");
        assert_eq!(records[1].provider, "bumblebee");
    }

    #[test]
    fn parses_numbat_event_as_telemetry_data() {
        let input = br#"{"schema_version":"0.3.0","record_type":"event","run_id":"r1"}"#;
        let (records, _) = parse_ndjson("numbat", input).expect("parse");
        assert_eq!(records[0].record_type, "event");
    }

    #[test]
    fn grok_output_remains_provider_record() {
        let record = parse_grok_json(br#"{"result":"candidate hypothesis"}"#).expect("json");
        assert_eq!(record.record_type, "research_harness_output");
        assert_eq!(record.provider, "grok-build");
    }

    #[test]
    fn rejects_unbounded_provider_output() {
        let bytes = vec![b'x'; MAX_PROVIDER_BYTES + 1];
        assert!(parse_ndjson("bumblebee", &bytes).is_err());
        assert!(parse_grok_json(&bytes).is_err());
    }
}

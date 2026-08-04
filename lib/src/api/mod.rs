pub mod envelopes;
pub mod file_chunk;
pub mod protocol_version;
mod user_agent_header;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct StartTaskRequest {
    #[serde(rename = "script")]
    pub script_name: String,
    #[serde(rename = "args")]
    pub arguments: Vec<String>,
    #[serde(rename = "file")]
    pub file: Option<FileAttachment>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileAttachment {
    #[serde(rename = "hash")]
    pub hash: Vec<u8>,
    #[serde(rename = "size")]
    pub size: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TaskLaunchStatus {
    #[serde(rename = "awaiting_files")]
    AwaitingFiles { offset: usize },
    #[serde(rename = "launched")]
    Launched { started_on: DateTime<Utc> },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ServerErrorResponse {
    #[serde(rename = "cannot_launch_script")]
    CannotLaunchScript,
    #[serde(rename = "script_not_found")]
    ScriptNotFound,
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ServerTaskNotification<O, E> {
    #[serde(rename = "output")]
    Output(O),
    #[serde(rename = "exit_code")]
    ExitCode(E),
}

pub struct UserAgentHeader {
    pub version: String,
}

/// Declares the wire-protocol version a client speaks — independent of
/// `UserAgentHeader`, which is just product/implementation identification.
/// `orosu-server` reads `protocol_version::PROTOCOL_VERSION` from this same
/// crate; the JS action (client/src/protocolVersion.js), the only client
/// left now that the Rust CLI client has been dropped, keeps its own
/// hardcoded copy in sync by hand since it can't share a Rust constant.
pub struct ProtocolVersionHeader {
    pub version: u32,
}

// These lock in the exact wire-format contract a JS reimplementation of the
// client (client/src/*.js) depends on byte-for-byte: externally-tagged
// enums, `Vec<u8>` as plain JSON int arrays (not base64), and the specific
// renamed field names. A change here that breaks one of these assertions is
// a wire-protocol breaking change, not just a refactor.
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn start_task_request_serializes_with_renamed_fields() {
        let request = StartTaskRequest {
            script_name: "deploy".to_string(),
            arguments: vec!["a".to_string(), "b".to_string()],
            file: None,
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            value,
            json!({"script": "deploy", "args": ["a", "b"], "file": null})
        );
    }

    #[test]
    fn start_task_request_with_file_attachment_serializes_hash_as_int_array_not_base64() {
        let request = StartTaskRequest {
            script_name: "deploy".to_string(),
            arguments: vec![],
            file: Some(FileAttachment {
                hash: vec![1, 2, 3],
                size: 42,
            }),
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            value,
            json!({"script": "deploy", "args": [], "file": {"hash": [1, 2, 3], "size": 42}})
        );
    }

    #[test]
    fn task_launch_status_awaiting_files_is_externally_tagged() {
        let status = TaskLaunchStatus::AwaitingFiles { offset: 128 };
        let value = serde_json::to_value(&status).unwrap();
        assert_eq!(value, json!({"awaiting_files": {"offset": 128}}));
    }

    #[test]
    fn task_launch_status_launched_is_externally_tagged() {
        let started_on: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        let status = TaskLaunchStatus::Launched { started_on };
        let value = serde_json::to_value(&status).unwrap();
        assert_eq!(
            value,
            json!({"launched": {"started_on": "2026-01-01T00:00:00Z"}})
        );
    }

    #[test]
    fn server_error_response_serializes_as_bare_strings_not_objects() {
        assert_eq!(
            serde_json::to_value(ServerErrorResponse::CannotLaunchScript).unwrap(),
            json!("cannot_launch_script")
        );
        assert_eq!(
            serde_json::to_value(ServerErrorResponse::ScriptNotFound).unwrap(),
            json!("script_not_found")
        );
        assert_eq!(
            serde_json::to_value(ServerErrorResponse::Unknown).unwrap(),
            json!("unknown")
        );
    }

    #[test]
    fn server_task_notification_output_wraps_the_inner_value_directly_not_nested() {
        let notification: ServerTaskNotification<&str, i32> = ServerTaskNotification::Output("hi");
        let value = serde_json::to_value(&notification).unwrap();
        assert_eq!(value, json!({"output": "hi"}));
    }

    #[test]
    fn server_task_notification_exit_code_wraps_the_bare_integer() {
        let notification: ServerTaskNotification<&str, i32> = ServerTaskNotification::ExitCode(7);
        let value = serde_json::to_value(&notification).unwrap();
        assert_eq!(value, json!({"exit_code": 7}));
    }

    #[test]
    fn start_task_request_deserializes_from_wire_shape() {
        let json_text = r#"{"script":"deploy","args":["x"],"file":null}"#;
        let request: StartTaskRequest = serde_json::from_str(json_text).unwrap();
        assert_eq!(request.script_name, "deploy");
        assert_eq!(request.arguments, vec!["x".to_string()]);
        assert!(request.file.is_none());
    }

    #[test]
    fn task_launch_status_deserializes_from_wire_shape() {
        let json_text = r#"{"awaiting_files":{"offset":64}}"#;
        let status: TaskLaunchStatus = serde_json::from_str(json_text).unwrap();
        let TaskLaunchStatus::AwaitingFiles { offset } = status else {
            panic!("expected AwaitingFiles");
        };
        assert_eq!(offset, 64);
    }
}

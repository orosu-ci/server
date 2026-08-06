use crate::api::file_chunk::FileChunk;
use crate::api::{ServerErrorResponse, ServerTaskNotification, StartTaskRequest, TaskLaunchStatus};
use crate::tasks::{TaskOutput, Timestamped};
use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestEnvelope<T> {
    #[serde(rename = "body")]
    pub body: T,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ResponseEnvelope<T, E> {
    #[serde(rename = "success")]
    Success {
        #[serde(rename = "body")]
        body: T,
    },
    #[serde(rename = "failure")]
    Failure {
        #[serde(rename = "error")]
        error: E,
    },
}

impl<T> From<RequestEnvelope<T>> for Bytes
where
    T: Serialize,
{
    fn from(value: RequestEnvelope<T>) -> Self {
        serde_json::to_vec(&value).unwrap().into()
    }
}

impl<T, E> From<ResponseEnvelope<T, E>> for Bytes
where
    T: Serialize,
    E: Serialize,
{
    fn from(value: ResponseEnvelope<T, E>) -> Self {
        serde_json::to_vec(&value).unwrap().into()
    }
}

impl<T> From<Bytes> for RequestEnvelope<T>
where
    T: DeserializeOwned,
{
    fn from(value: Bytes) -> Self {
        serde_json::from_slice(&value).unwrap()
    }
}

impl<T, E> From<Bytes> for ResponseEnvelope<T, E>
where
    T: DeserializeOwned,
    E: DeserializeOwned,
{
    fn from(value: Bytes) -> Self {
        serde_json::from_slice(&value).unwrap()
    }
}

pub type FileChunkRequestEnvelope = RequestEnvelope<FileChunk>;
pub type TaskLaunchStatusResponseEnvelope = ResponseEnvelope<TaskLaunchStatus, ServerErrorResponse>;
pub type TaskEventResponseEnvelope =
    ResponseEnvelope<ServerTaskNotification<Timestamped<TaskOutput>, i32>, ServerErrorResponse>;
pub type TaskLaunchRequestEnvelope = RequestEnvelope<StartTaskRequest>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_envelope_wraps_body_and_round_trips_through_bytes() {
        let envelope = RequestEnvelope {
            body: "hello".to_string(),
        };
        let bytes: Bytes = envelope.into();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            json!({"body": "hello"})
        );

        let round_tripped: RequestEnvelope<String> = bytes.into();
        assert_eq!(round_tripped.body, "hello");
    }

    #[test]
    fn response_envelope_success_round_trips_through_bytes() {
        let envelope: ResponseEnvelope<i32, String> = ResponseEnvelope::Success { body: 42 };
        let bytes: Bytes = envelope.into();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            json!({"success": {"body": 42}})
        );

        let round_tripped: ResponseEnvelope<i32, String> = bytes.into();
        match round_tripped {
            ResponseEnvelope::Success { body } => assert_eq!(body, 42),
            ResponseEnvelope::Failure { .. } => panic!("expected Success"),
        }
    }

    #[test]
    fn response_envelope_failure_round_trips_through_bytes() {
        let envelope: ResponseEnvelope<i32, String> = ResponseEnvelope::Failure {
            error: "oops".to_string(),
        };
        let bytes: Bytes = envelope.into();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            json!({"failure": {"error": "oops"}})
        );
    }

    // Documents current, deliberate behavior: these Bytes<->Envelope
    // conversions panic on malformed input rather than returning an error.
    // That's safe today because nothing in this crate calls them on
    // untrusted, network-received bytes — the live WS client is
    // client/src/*.js (a separate codebase), and the server instead
    // hand-parses untrusted client bytes with graceful Ok/Err handling
    // (server/handler/tasks.rs), never going through this conversion for
    // anything client-supplied. (An earlier Rust CLI client did call these
    // client-side to trust server responses; it's since been discontinued
    // in favor of the JS action.) If a future Rust caller ever feeds
    // network-received bytes through this conversion, this test should
    // fail and prompt reconsidering the choice.
    #[test]
    #[should_panic]
    fn malformed_bytes_panics_rather_than_returning_an_error() {
        let bytes = Bytes::from_static(b"not json");
        let _: RequestEnvelope<String> = bytes.into();
    }

    #[test]
    fn file_chunk_request_envelope_type_alias_round_trips() {
        let chunk = FileChunk {
            offset: 16,
            data: vec![1, 2, 3],
        };
        let envelope = FileChunkRequestEnvelope { body: chunk };
        let bytes: Bytes = envelope.into();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value, json!({"body": {"offset": 16, "data": [1, 2, 3]}}));
    }
}

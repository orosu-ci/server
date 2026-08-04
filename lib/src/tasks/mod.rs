pub(crate) use crate::tasks::timestamped::Timestamped;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

pub(crate) mod task;
mod timestamped;

pub struct TaskLaunchResult {
    pub(crate) created_on: chrono::DateTime<chrono::Utc>,
    pub(crate) handler: JoinHandle<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskOutput {
    #[serde(rename = "stdout")]
    Stdout(String),
    #[serde(rename = "stderr")]
    Stderr(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn task_output_stdout_serializes_as_a_tagged_object() {
        let output = TaskOutput::Stdout("hello".to_string());
        assert_eq!(
            serde_json::to_value(&output).unwrap(),
            json!({"stdout": "hello"})
        );
    }

    #[test]
    fn task_output_stderr_serializes_as_a_tagged_object() {
        let output = TaskOutput::Stderr("oops".to_string());
        assert_eq!(
            serde_json::to_value(&output).unwrap(),
            json!({"stderr": "oops"})
        );
    }

    #[test]
    fn task_output_deserializes_from_wire_shape() {
        let output: TaskOutput = serde_json::from_str(r#"{"stdout":"hi"}"#).unwrap();
        let TaskOutput::Stdout(line) = output else {
            panic!("expected Stdout");
        };
        assert_eq!(line, "hi");
    }
}

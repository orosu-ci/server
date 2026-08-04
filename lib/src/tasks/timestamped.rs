use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Timestamped<T> {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub value: T,
}

impl<T> Timestamped<T> {
    pub fn now(value: T) -> Self {
        Self {
            timestamp: chrono::Utc::now(),
            value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_captures_the_value_and_a_timestamp_bounded_by_the_call() {
        let before = chrono::Utc::now();
        let timestamped = Timestamped::now(42);
        let after = chrono::Utc::now();

        assert_eq!(timestamped.value, 42);
        assert!(timestamped.timestamp >= before);
        assert!(timestamped.timestamp <= after);
    }

    #[test]
    fn serializes_with_timestamp_and_value_fields() {
        let timestamped = Timestamped::now("hi".to_string());
        let value = serde_json::to_value(&timestamped).unwrap();
        assert!(value.get("timestamp").is_some());
        assert_eq!(value.get("value").unwrap(), "hi");
    }
}

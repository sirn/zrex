use serde::Deserialize;
use serde_json::{Value, json};

pub const API_REVISION: u64 = 8;

#[derive(Debug, Deserialize)]
pub struct Welcome {
    #[serde(default)]
    pub api_revision: Option<u64>,
    #[serde(default)]
    pub client: Option<WelcomeClient>,
}

#[derive(Debug, Deserialize)]
pub struct WelcomeClient {
    pub reconnect_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub status: i64,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} ({})", self.code, self.message, self.status)
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Incoming {
    Welcome(Welcome),
    Response {
        id: String,
        #[serde(default)]
        payload: Value,
        #[serde(default)]
        error: Option<ApiError>,
    },
    /// The event kind is in `payload`, not on the outer envelope.
    Event {
        #[serde(default)]
        payload: Value,
    },
    #[serde(other)]
    Unknown,
}

pub fn hello(reconnect_token: Option<&str>) -> Value {
    let mut msg = json!({
        "type": "hello",
        "api_revision": API_REVISION,
        "api_min_revision": API_REVISION,
        "client": {
            "kind": "cli",
            "platform": std::env::consts::OS,
            "name": "zrex",
            "version": env!("CARGO_PKG_VERSION"),
        },
    });
    if let Some(token) = reconnect_token {
        msg["reconnect_token"] = json!(token);
    }
    msg
}

pub fn request(id: &str, method: &str, payload: Value) -> Value {
    json!({"type": "request", "id": id, "method": method, "payload": payload})
}

/// Session events arrive nested inside `session_event` with `session_id` on
/// the outer payload; server events carry their fields directly in `payload`.
pub fn unwrap_event(payload: &Value) -> Option<(String, Value)> {
    let name = payload.get("type").and_then(Value::as_str)?;
    let inner = payload.get("payload").cloned().unwrap_or(Value::Null);
    if name != "session_event" {
        return Some((name.to_owned(), inner));
    }
    let event = inner.get("event")?;
    let event_name = event.get("type").and_then(Value::as_str)?.to_owned();
    let mut body = event.get("payload").cloned().unwrap_or(Value::Null);
    if let Some(session_id) = inner.get("session_id") {
        body["session_id"] = session_id.clone();
    }
    Some((event_name, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_hello_and_request_messages() {
        let msg = hello(None);
        assert_eq!(msg["type"], "hello");
        assert_eq!(msg["api_revision"], API_REVISION);
        assert!(msg.get("reconnect_token").is_none());

        let resumed = hello(Some("secret-token"));
        assert_eq!(resumed["reconnect_token"], "secret-token");

        let req = request("7", "session.list", Value::Null);
        assert_eq!(
            req,
            json!({"type": "request", "id": "7", "method": "session.list", "payload": null})
        );
    }

    #[test]
    fn unwraps_session_and_server_events() {
        let wrapped = json!({
            "type": "session_event",
            "payload": {
                "session_id": "session:1",
                "event": {
                    "type": "block_closed",
                    "payload": {"block_id": "block:2"}
                }
            }
        });
        let (name, body) = unwrap_event(&wrapped).unwrap();
        assert_eq!(name, "block_closed");
        assert_eq!(body["session_id"], "session:1");
        assert_eq!(body["block_id"], "block:2");

        let server_event = json!({
            "type": "session_destroyed",
            "payload": {
                "session_id": "session:other"
            }
        });
        let (name, body) = unwrap_event(&server_event).unwrap();
        assert_eq!(name, "session_destroyed");
        assert_eq!(body["session_id"], "session:other");
    }
}

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use crate::rex::control::Control;

pub async fn list(ctrl: &mut Control) -> Result<Vec<Value>> {
    let reply = ctrl.call("session.list", Value::Null).await?;
    Ok(sessions_of(&reply))
}

/// `session.attach_all` lets the client read every session's view without
/// joining or mutating any session.
pub async fn list_all(ctrl: &mut Control) -> Result<Vec<Value>> {
    let reply = ctrl
        .call("session.attach_all", json!({"event_scope": "session"}))
        .await?;
    Ok(sessions_of(&reply))
}

fn sessions_of(reply: &Value) -> Vec<Value> {
    reply
        .get("sessions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

pub async fn view(ctrl: &mut Control, session_id: &str) -> Result<Value> {
    ctrl.call("session.view", json!({"session_id": session_id}))
        .await
}

pub async fn destroy(ctrl: &mut Control, session_id: &str) -> Result<()> {
    ctrl.call("session.attach", json!({"session_id": session_id}))
        .await?;
    ctrl.call("session.destroy", json!({"session_id": session_id}))
        .await?;
    Ok(())
}

pub async fn ensure_window(
    ctrl: &mut Control,
    session_id: &str,
    selector: &str,
    block: Option<&str>,
) -> Result<(String, Option<String>)> {
    if selector == "-" {
        let window_id = new_window(ctrl, session_id, None).await?;
        return Ok((window_id, block.map(str::to_owned)));
    }
    let view = view(ctrl, session_id).await?;
    if let Some(window_id) = find_window(&view, selector) {
        return Ok((window_id, block.map(str::to_owned)));
    }
    if block.is_none()
        && let Some((win_sel, blk_sel)) = split_window_block(selector)
    {
        if let Some(window_id) = find_window(&view, win_sel) {
            return Ok((window_id, Some(blk_sel.to_owned())));
        }
        if win_sel.parse::<usize>().is_ok() {
            bail!("the session has no window {win_sel}");
        }
    }
    if selector.parse::<usize>().is_ok() {
        bail!("the session has no window {selector}");
    }
    let window_id = new_window(ctrl, session_id, Some(selector)).await?;
    Ok((window_id, block.map(str::to_owned)))
}

/// `"focus": false` keeps `Rex.app` on the window it is already showing.
pub async fn new_window(
    ctrl: &mut Control,
    session_id: &str,
    label: Option<&str>,
) -> Result<String> {
    let mut payload = json!({
        "session_id": session_id,
        "focus": false,
        "layout": {"block": {"flavor": "com.superlogical.terminal.shell"}},
    });
    if let Some(label) = label {
        payload["window_label"] = json!(label);
    }
    let reply = ctrl.call("session.new_window", payload).await?;
    reply
        .get("window_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("session.new_window returned no window"))
}

fn names(session: &Value, target: &str) -> bool {
    let id = id_of(session);
    id == target
        || label_of(session).eq_ignore_ascii_case(target)
        || (target.len() >= 4 && id.ends_with(target))
}

pub async fn find_or_create(ctrl: &mut Control, target: &str) -> Result<String> {
    let sessions = list(ctrl).await?;
    match sessions.iter().find(|session| names(session, target)) {
        Some(session) => Ok(id_of(session)),
        None => create(ctrl, Some(target)).await,
    }
}

pub async fn pick(ctrl: &mut Control, target: Option<&str>) -> Result<String> {
    let sessions = list(ctrl).await?;
    if sessions.is_empty() {
        bail!("the server has no sessions");
    }
    let Some(target) = target else {
        return Ok(id_of(&sessions[0]));
    };
    if let Some(session) = sessions.iter().find(|session| names(session, target)) {
        return Ok(id_of(session));
    }
    let known = sessions
        .iter()
        .map(|session| format!("  {} ({})", label_of(session), id_of(session)))
        .collect::<Vec<_>>()
        .join("\n");
    bail!("no session matches {target}. The server has:\n{known}")
}

pub async fn create(ctrl: &mut Control, label: Option<&str>) -> Result<String> {
    let mut payload = json!({
        "initial_windows": [{
            "layout": {"block": {"flavor": "com.superlogical.terminal.shell"}},
        }],
    });
    if let Some(label) = label {
        payload["label"] = json!(label);
    }
    let reply = ctrl.call("session.create", payload).await?;
    reply
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("session.create returned no session"))
}

pub fn id_of(session: &Value) -> String {
    session
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

pub fn label_of(session: &Value) -> &str {
    session.get("label").and_then(Value::as_str).unwrap_or("")
}

pub fn active_window_id(view: &Value) -> Option<&str> {
    view.get("active_window_id").and_then(Value::as_str)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowSummary {
    pub id: String,
    pub label: String,
    pub active_block_id: Option<String>,
    pub blocks: Vec<BlockSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSummary {
    pub id: String,
    pub label: String,
}

pub fn block_of(
    view: &Value,
    window_selector: Option<&str>,
    block_selector: Option<&str>,
) -> Option<String> {
    let (window_id, block_sel) = match window_selector {
        Some(selector) => {
            if let Some(id) = find_window(view, selector) {
                (id, block_selector)
            } else if block_selector.is_none()
                && let Some((win_sel, blk_sel)) = split_window_block(selector)
                && let Some(id) = find_window(view, win_sel)
            {
                (id, Some(blk_sel))
            } else {
                return None;
            }
        }
        None => (active_window_id(view)?.to_owned(), block_selector),
    };
    let window = windows(view)
        .into_iter()
        .find(|window| window.id == window_id)?;
    match block_sel {
        Some(selector) => find_block(&window, selector),
        None => window
            .active_block_id
            .or_else(|| window.blocks.into_iter().next().map(|block| block.id)),
    }
}

pub fn windows(view: &Value) -> Vec<WindowSummary> {
    let Some(windows) = view.get("windows").and_then(Value::as_array) else {
        return Vec::new();
    };
    windows
        .iter()
        .filter_map(|window| {
            let id = window.get("window_id").and_then(Value::as_str)?.to_owned();
            let label = window
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let active_block_id = window
                .get("zoomed_block_id")
                .and_then(Value::as_str)
                .or_else(|| window.get("focused_block_id").and_then(Value::as_str))
                .map(str::to_owned);
            let mut blocks = Vec::new();
            if let Some(layers) = window.get("layers").and_then(Value::as_array) {
                for layer in layers {
                    if let Some(layer_blocks) = layer.get("blocks").and_then(Value::as_array) {
                        for block in layer_blocks {
                            if let Some(block_id) = block.get("block_id").and_then(Value::as_str) {
                                let block_label = block
                                    .get("label")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default();
                                blocks.push(BlockSummary {
                                    id: block_id.to_owned(),
                                    label: block_label.to_owned(),
                                });
                            }
                        }
                    }
                }
            }
            if blocks.is_empty()
                && let Some(active_id) = &active_block_id
            {
                blocks.push(BlockSummary {
                    id: active_id.clone(),
                    label: String::new(),
                });
            }
            Some(WindowSummary {
                id,
                label,
                active_block_id,
                blocks,
            })
        })
        .collect()
}

pub fn has_block(view: &Value, block_id: &str) -> bool {
    let Some(windows) = view.get("windows").and_then(Value::as_array) else {
        return false;
    };
    windows.iter().any(|window| {
        let focused = window
            .get("focused_block_id")
            .and_then(Value::as_str)
            .is_some_and(|id| id == block_id);
        let zoomed = window
            .get("zoomed_block_id")
            .and_then(Value::as_str)
            .is_some_and(|id| id == block_id);
        focused
            || zoomed
            || window
                .get("layers")
                .and_then(Value::as_array)
                .is_some_and(|layers| layers.iter().any(|layer| layer_holds(layer, block_id)))
    })
}

fn layer_holds(layer: &Value, block_id: &str) -> bool {
    let listed = layer
        .get("blocks")
        .and_then(Value::as_array)
        .is_some_and(|blocks| {
            blocks.iter().any(|block| {
                block
                    .get("block_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id == block_id)
            })
        });
    let drawn = layer
        .get("layout")
        .and_then(|layout| layout.get("block_id"))
        .and_then(Value::as_str)
        .is_some_and(|id| id == block_id);
    listed || drawn
}

pub fn find_window(view: &Value, selector: &str) -> Option<String> {
    let windows = windows(view);
    if let Some(window) = windows.iter().find(|window| window.id == selector) {
        return Some(window.id.clone());
    }
    if let Ok(number) = selector.parse::<usize>()
        && let Some(window) = number.checked_sub(1).and_then(|idx| windows.get(idx))
    {
        return Some(window.id.clone());
    }
    if let Some(window) = windows.iter().find(|window| window.label == selector) {
        return Some(window.id.clone());
    }
    only(
        windows
            .iter()
            .filter(|window| window.label.starts_with(selector)),
    )
    .map(|window| window.id.clone())
}

pub fn find_block(window: &WindowSummary, selector: &str) -> Option<String> {
    if let Some(block) = window.blocks.iter().find(|block| block.id == selector) {
        return Some(block.id.clone());
    }
    if let Ok(number) = selector.parse::<usize>()
        && let Some(block) = number.checked_sub(1).and_then(|idx| window.blocks.get(idx))
    {
        return Some(block.id.clone());
    }
    if let Some(block) = window
        .blocks
        .iter()
        .find(|block| block.label.eq_ignore_ascii_case(selector))
    {
        return Some(block.id.clone());
    }
    if let Some(block) = only(
        window
            .blocks
            .iter()
            .filter(|block| !block.label.is_empty() && block.label.starts_with(selector)),
    ) {
        return Some(block.id.clone());
    }
    if selector.len() >= 4
        && let Some(block) = only(
            window
                .blocks
                .iter()
                .filter(|block| block.id.ends_with(selector)),
        )
    {
        return Some(block.id.clone());
    }
    None
}

fn split_window_block(selector: &str) -> Option<(&str, &str)> {
    let (win, blk) = selector.split_once('.')?;
    (!win.is_empty() && !blk.is_empty()).then_some((win, blk))
}

fn only<T>(mut iter: impl Iterator<Item = T>) -> Option<T> {
    match (iter.next(), iter.next()) {
        (Some(item), None) => Some(item),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    fn session(id: &str, label: &str) -> Value {
        json!({"session_id": id, "label": label})
    }

    fn sample_view(labels: &[&str], active: &str) -> Value {
        json!({
            "active_window_id": format!("window:{active}"),
            "windows": labels
                .iter()
                .map(|label| json!({
                    "window_id": format!("window:{label}"),
                    "label": label,
                    "focused_block_id": format!("block:{label}"),
                }))
                .collect::<Vec<_>>(),
        })
    }

    #[test]
    fn names_match_a_label_an_id_or_the_tail_of_an_id() {
        let work = session("session:01a1a9ff-0560", "work");
        assert!(names(&work, "work"));
        assert!(names(&work, "WORK"));
        assert!(names(&work, "session:01a1a9ff-0560"));
        assert!(names(&work, "0560"));
        assert!(!names(&work, "056"));
        assert!(!names(&work, "rest"));
    }

    #[test]
    fn reads_windows_in_order() {
        let read = windows(&sample_view(&["one", "two"], "one"));
        assert_eq!(read.len(), 2);
        assert_eq!(read[1].id, "window:two");
        assert_eq!(read[1].label, "two");
    }

    #[test]
    fn finds_a_window_by_number_or_label() {
        let view = sample_view(&["build", "logs", "logs-old"], "build");
        assert_eq!(find_window(&view, "2").as_deref(), Some("window:logs"));
        assert_eq!(find_window(&view, "0"), None);
        assert_eq!(find_window(&view, "4"), None);
        assert_eq!(find_window(&view, "logs").as_deref(), Some("window:logs"));
        assert_eq!(find_window(&view, "log"), None);
        assert_eq!(find_window(&view, "build").as_deref(), Some("window:build"));
        assert_eq!(find_window(&view, "nope"), None);
    }

    #[test]
    fn shows_the_block_of_the_named_window_and_split() {
        let view = json!({
            "active_window_id": "window:build",
            "windows": [
                {
                    "window_id": "window:build",
                    "label": "build",
                    "focused_block_id": "block:1111",
                    "layers": [{
                        "layer_id": "layer:1",
                        "blocks": [
                            {"block_id": "block:1111", "label": "shell"},
                            {"block_id": "block:2222", "label": "watch"},
                        ]
                    }]
                },
                {
                    "window_id": "window:logs",
                    "label": "logs",
                    "focused_block_id": "block:3333",
                    "zoomed_block_id": "block:zoomed",
                }
            ]
        });
        assert_eq!(block_of(&view, None, None).as_deref(), Some("block:1111"));
        assert_eq!(
            block_of(&view, Some("1.2"), None).as_deref(),
            Some("block:2222")
        );
        assert_eq!(
            block_of(&view, Some("build.watch"), None).as_deref(),
            Some("block:2222")
        );
        assert_eq!(
            block_of(&view, Some("1"), Some("2")).as_deref(),
            Some("block:2222")
        );
        assert_eq!(
            block_of(&view, None, Some("2")).as_deref(),
            Some("block:2222")
        );
        assert_eq!(
            block_of(&view, None, Some("2222")).as_deref(),
            Some("block:2222")
        );
        assert_eq!(
            block_of(&view, Some("2"), None).as_deref(),
            Some("block:zoomed")
        );
        assert_eq!(
            block_of(&view, Some("logs"), None).as_deref(),
            Some("block:zoomed")
        );
        assert_eq!(block_of(&view, Some("1.3"), None), None);
        assert_eq!(block_of(&view, Some("nope"), None), None);
    }

    #[test]
    fn finds_a_block_in_any_window_or_layer() {
        let view = json!({
            "windows": [{
                "window_id": "window:one",
                "label": "one",
                "focused_block_id": "block:one",
                "layers": [{
                    "layer_id": "layer:one",
                    "blocks": [{"block_id": "block:one"}, {"block_id": "block:two"}],
                }],
            }],
        });
        assert!(has_block(&view, "block:two"));
        assert!(!has_block(&view, "block:three"));
        assert!(!has_block(&json!({}), "block:one"));
    }

    #[tokio::test]
    async fn picks_creates_and_ensures_windows() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_hdr_async(stream, |req: &Request, mut res: Response| {
                if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                    res.headers_mut()
                        .insert("Sec-WebSocket-Protocol", proto.clone());
                }
                Ok(res)
            })
            .await
            .unwrap();

            let _ = ws.next().await;
            ws.send(Message::text(
                json!({"type": "welcome", "api_revision": 8}).to_string(),
            ))
            .await
            .unwrap();

            while let Some(Ok(Message::Text(text))) = ws.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap();
                let method = req["method"].as_str().unwrap();
                let payload = match method {
                    "session.list" => json!({
                        "sessions": [{"session_id": "session:1111-aaaa", "label": "work"}]
                    }),
                    "session.create" => json!({"session_id": "session:2222-bbbb"}),
                    "session.view" => json!({
                        "active_window_id": "window:1",
                        "windows": [{"window_id": "window:1", "label": "editor", "focused_block_id": "block:1"}]
                    }),
                    "session.new_window" => json!({"window_id": "window:2"}),
                    other => panic!("unexpected method {other}"),
                };
                ws.send(Message::text(
                    json!({"type": "response", "id": id, "seq": 0, "payload": payload}).to_string(),
                ))
                .await
                .unwrap();
            }
        });

        let server = format!("http://{addr}");
        let (mut ctrl, _events) = Control::connect(&server, None).await.unwrap();

        assert_eq!(pick(&mut ctrl, None).await.unwrap(), "session:1111-aaaa");
        assert_eq!(
            pick(&mut ctrl, Some("aaaa")).await.unwrap(),
            "session:1111-aaaa"
        );
        assert!(pick(&mut ctrl, Some("missing")).await.is_err());

        assert_eq!(
            find_or_create(&mut ctrl, "work").await.unwrap(),
            "session:1111-aaaa"
        );
        assert_eq!(
            find_or_create(&mut ctrl, "fresh").await.unwrap(),
            "session:2222-bbbb"
        );

        assert_eq!(
            ensure_window(&mut ctrl, "session:1111-aaaa", "1", None)
                .await
                .unwrap(),
            ("window:1".to_owned(), None)
        );
        assert_eq!(
            ensure_window(&mut ctrl, "session:1111-aaaa", "1.2", None)
                .await
                .unwrap(),
            ("window:1".to_owned(), Some("2".to_owned()))
        );
        assert_eq!(
            ensure_window(&mut ctrl, "session:1111-aaaa", "1", Some("2"))
                .await
                .unwrap(),
            ("window:1".to_owned(), Some("2".to_owned()))
        );
        assert!(
            ensure_window(&mut ctrl, "session:1111-aaaa", "2", None)
                .await
                .is_err()
        );
        assert!(
            ensure_window(&mut ctrl, "session:1111-aaaa", "2.1", None)
                .await
                .is_err()
        );
        assert_eq!(
            ensure_window(&mut ctrl, "session:1111-aaaa", "logs", None)
                .await
                .unwrap(),
            ("window:2".to_owned(), None)
        );
        assert_eq!(
            ensure_window(&mut ctrl, "session:1111-aaaa", "-", None)
                .await
                .unwrap(),
            ("window:2".to_owned(), None)
        );
    }
}

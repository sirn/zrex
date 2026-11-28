use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tokio::time::{Instant, timeout_at};

use crate::rex::BlockRef;
use crate::rex::control::Control;
use crate::text::{clean_one_line, clean_truncated, percent_decode, shorten_home};

pub type PendingCall = oneshot::Receiver<Result<Value>>;

pub async fn optional_reply(call: Result<PendingCall>, deadline: Instant) -> Option<Value> {
    let rx = call.ok()?;
    timeout_at(deadline, rx).await.ok()?.ok()?.ok()
}

/// Attaches the control connection to `session_id`. Mutating session, window,
/// or block RPCs require prior `attach` (or `session.bootstrap`).
pub async fn attach(ctrl: &mut Control, session_id: &str) -> Result<()> {
    ctrl.call("session.attach", json!({"session_id": session_id}))
        .await?;
    Ok(())
}

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

pub fn start_view(ctrl: &mut Control, session_id: &str) -> Result<PendingCall> {
    ctrl.start_call("session.view", json!({"session_id": session_id}))
}

pub fn start_terminal_title(ctrl: &mut Control, block: BlockRef<'_>) -> Result<PendingCall> {
    ctrl.start_call(
        "com.superlogical.terminal.title",
        json!({"session_id": block.session_id, "block_id": block.block_id}),
    )
}

pub fn start_terminal_process(ctrl: &mut Control, block: BlockRef<'_>) -> Result<PendingCall> {
    ctrl.start_call(
        "com.superlogical.terminal.process",
        json!({"session_id": block.session_id, "block_id": block.block_id}),
    )
}

pub fn terminal_title_of(reply: &Value) -> Option<&str> {
    reply
        .get("title")
        .and_then(Value::as_str)
        .filter(|title| !title.is_empty())
}

/// Returns the terminal title unless its `owner` is known to have exited from
/// the pane's live process tree.
pub fn live_terminal_title<'a>(
    title_reply: &'a Value,
    process_reply: Option<&Value>,
) -> Option<&'a str> {
    let title = terminal_title_of(title_reply)?;
    let Some(owner) = title_reply.get("owner").and_then(process_identity) else {
        return Some(title);
    };
    let Some(process_reply) = process_reply else {
        return Some(title);
    };

    let mut saw_live = false;
    let live = [process_reply.get("foreground"), process_reply.get("child")]
        .into_iter()
        .flatten()
        .chain(
            process_reply
                .get("ancestors")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .filter_map(process_identity);
    for identity in live {
        saw_live = true;
        if identity == owner {
            return Some(title);
        }
    }

    let exited = process_reply
        .get("last_exit")
        .is_some_and(|value| !value.is_null());
    if saw_live || exited {
        None
    } else {
        Some(title)
    }
}

fn process_identity(value: &Value) -> Option<(i64, &str)> {
    let pid = value.get("pid")?.as_i64()?;
    let name = value.get("name")?.as_str()?;
    Some((pid, name))
}

/// Follows Rex's `com.superlogical.terminal.process` guidance: prefer `script`,
/// then `argv0`, then `name`, reduced to a short display name.
pub fn process_name(reply: &Value) -> Option<String> {
    reply
        .get("foreground")
        .and_then(label_for_process)
        .or_else(|| reply.get("child").and_then(label_for_process))
}

fn label_for_process(process: &Value) -> Option<String> {
    if process.is_null() {
        return None;
    }
    for (key, strip_login_dash) in [("script", false), ("argv0", true), ("name", false)] {
        let Some(raw) = process.get(key).and_then(Value::as_str) else {
            continue;
        };
        let cleaned = clean_one_line(raw);
        let candidate = if strip_login_dash {
            cleaned.strip_prefix('-').unwrap_or(&cleaned)
        } else {
            &cleaned
        };
        let base = basename(candidate);
        let base = if strip_login_dash {
            base.strip_prefix('-').unwrap_or(base)
        } else {
            base
        };
        let short = clean_truncated(base, 24);
        if !short.is_empty() {
            return Some(short);
        }
    }
    None
}

fn basename(value: &str) -> &str {
    let trimmed = value.trim_end_matches(['/', '\\']);
    trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed)
}

pub fn is_known_agent_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let stem = lower
        .strip_suffix(".js")
        .or_else(|| lower.strip_suffix(".mjs"))
        .or_else(|| lower.strip_suffix(".cjs"))
        .or_else(|| lower.strip_suffix(".py"))
        .or_else(|| lower.strip_suffix(".sh"))
        .unwrap_or(&lower);
    matches!(
        stem,
        "agy"
            | "antigravity"
            | "claude"
            | "claude-code"
            | "codex"
            | "gemini"
            | "opencode"
            | "aider"
            | "amp"
            | "goose"
            | "copilot"
            | "pi"
            | "cursor-agent"
            | "kiro"
            | "kiro-cli"
            | "droid"
            | "crush"
            | "cline"
            | "qwen"
    )
}

/// Returns true when the terminal's live process tree includes a known coding
/// agent (checking `foreground`, `child`, and `ancestors`).
pub fn has_agent_process(reply: &Value) -> bool {
    if reply.get("last_exit").is_some_and(|value| !value.is_null()) {
        return false;
    }
    [reply.get("foreground"), reply.get("child")]
        .into_iter()
        .flatten()
        .chain(
            reply
                .get("ancestors")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .any(process_entry_is_agent)
}

fn process_entry_is_agent(process: &Value) -> bool {
    if process.is_null() {
        return false;
    }
    for (key, strip_login_dash) in [
        ("script", false),
        ("argv0", true),
        ("invoked_path", false),
        ("name", false),
    ] {
        let Some(raw) = process.get(key).and_then(Value::as_str) else {
            continue;
        };
        let cleaned = clean_one_line(raw);
        let candidate = if strip_login_dash {
            cleaned.strip_prefix('-').unwrap_or(&cleaned)
        } else {
            &cleaned
        };
        let base = basename(candidate);
        let base = if strip_login_dash {
            base.strip_prefix('-').unwrap_or(base)
        } else {
            base
        };
        if !base.is_empty() && is_known_agent_name(base) {
            return true;
        }
    }
    false
}

/// Derives a pane's display title from its live terminal title, falling back
/// to the foreground process name (and OSC 7 working directory when a VT
/// snapshot is available).
pub fn resolved_terminal_title(
    title_reply: Option<&Value>,
    process_reply: Option<&Value>,
    screen: Option<&[u8]>,
) -> Option<String> {
    title_reply
        .and_then(|reply| live_terminal_title(reply, process_reply))
        .map(clean_one_line)
        .filter(|title| !title.is_empty())
        .or_else(|| process_pwd_title(process_reply, screen))
}

pub fn process_pwd_title(process_reply: Option<&Value>, screen: Option<&[u8]>) -> Option<String> {
    let process = process_reply.and_then(process_name);
    let pwd = screen.and_then(extract_osc_pwd);
    match (process, pwd) {
        (Some(proc_name), Some(dir)) => Some(format!("{proc_name} {dir}")),
        (Some(proc_name), None) => Some(proc_name),
        (None, Some(dir)) => Some(dir),
        (None, None) => None,
    }
}

fn extract_osc_pwd(bytes: &[u8]) -> Option<String> {
    let start = bytes.windows(4).rposition(|w| w == b"\x1b]7;")?;
    let rest = &bytes[start + 4..];
    let end = rest
        .iter()
        .position(|&b| b == 0x07)
        .into_iter()
        .chain(rest.windows(2).position(|w| w == b"\x1b\\"))
        .min()?;
    let raw = std::str::from_utf8(&rest[..end]).ok()?;
    let path = if let Some(after_scheme) = raw.strip_prefix("file://") {
        let slash = after_scheme.find('/')?;
        &after_scheme[slash..]
    } else if raw.starts_with('/') {
        raw
    } else {
        return None;
    };
    let decoded = clean_one_line(&percent_decode(path));
    if decoded.is_empty() {
        return None;
    }
    Some(shorten_home(&decoded))
}

pub fn fallback_title_for(bootstrap: &Value, view: &Value, block_id: &str) -> Option<String> {
    let window_label = windows(view)
        .into_iter()
        .find(|window| window.blocks.iter().any(|block| block.id == block_id))
        .map(|window| clean_one_line(&window.label))
        .filter(|label| !label.is_empty() && !is_default_window_label(label));
    if window_label.is_some() {
        return window_label;
    }
    bootstrap
        .get("selected_session")
        .map(label_of)
        .map(clean_one_line)
        .filter(|label| !label.is_empty())
}

pub fn is_default_window_label(label: &str) -> bool {
    label
        .strip_prefix("Window ")
        .is_some_and(|hex| hex.len() == 8 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Destroys a session. Requires prior `session::attach` (or `session.bootstrap`).
pub async fn destroy(ctrl: &mut Control, session_id: &str) -> Result<()> {
    ctrl.call("session.destroy", json!({"session_id": session_id}))
        .await?;
    Ok(())
}

/// Renames a session. Requires prior `session::attach` (or `session.bootstrap`).
pub async fn set_label(ctrl: &mut Control, session_id: &str, label: &str) -> Result<()> {
    ctrl.call(
        "session.set_label",
        json!({"session_id": session_id, "label": label}),
    )
    .await?;
    Ok(())
}

/// Renames a window. Requires prior `session::attach` (or `session.bootstrap`).
pub async fn set_window_label(
    ctrl: &mut Control,
    session_id: &str,
    window_id: &str,
    label: &str,
) -> Result<()> {
    ctrl.call(
        "session.set_window_label",
        json!({"session_id": session_id, "window_id": window_id, "label": label}),
    )
    .await?;
    Ok(())
}

/// Renames a block. Requires prior `session::attach` (or `session.bootstrap`).
pub async fn set_block_label(ctrl: &mut Control, block: BlockRef<'_>, label: &str) -> Result<()> {
    ctrl.call(
        "session.set_block_label",
        json!({"session_id": block.session_id, "block_id": block.block_id, "label": label}),
    )
    .await?;
    Ok(())
}

/// Closes a window. Requires prior `session::attach` (or `session.bootstrap`).
pub async fn close_window(ctrl: &mut Control, session_id: &str, window_id: &str) -> Result<()> {
    ctrl.call(
        "session.close_window",
        json!({"session_id": session_id, "window_id": window_id}),
    )
    .await?;
    Ok(())
}

/// Closes a block. Requires prior `session::attach` (or `session.bootstrap`).
pub async fn close_block(ctrl: &mut Control, block: BlockRef<'_>) -> Result<()> {
    ctrl.call(
        "block.close",
        json!({"session_id": block.session_id, "block_id": block.block_id}),
    )
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
    if let Some((window, block)) = resolve_window(&windows(&view), selector, block) {
        return Ok((window.id.clone(), block.map(str::to_owned)));
    }
    if block.is_none()
        && let Some((win_sel, _)) = split_window_block(selector)
        && win_sel.parse::<usize>().is_ok()
    {
        bail!("the session has no window {win_sel}");
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

pub fn matches(session: &Value, target: &str) -> bool {
    let id = id_of(session);
    id == target
        || label_of(session).eq_ignore_ascii_case(target)
        || (target.len() >= 4 && id.ends_with(target))
}

pub fn select_session<'a>(sessions: &'a [Value], target: Option<&str>) -> Option<&'a Value> {
    match target {
        Some(target) => sessions.iter().find(|session| matches(session, target)),
        None => sessions.first(),
    }
}

pub async fn find_or_create(ctrl: &mut Control, target: &str) -> Result<String> {
    let sessions = list(ctrl).await?;
    match select_session(&sessions, Some(target)) {
        Some(session) => Ok(id_of(session)),
        None => create(ctrl, Some(target)).await,
    }
}

pub async fn pick(ctrl: &mut Control, target: Option<&str>) -> Result<String> {
    let sessions = list(ctrl).await?;
    if sessions.is_empty() {
        bail!("the server has no sessions");
    }
    if let Some(session) = select_session(&sessions, target) {
        return Ok(id_of(session));
    }
    let target = target.expect("a nonempty session list has a default");
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
    pub focused_block_id: Option<String>,
    pub active_block_id: Option<String>,
    pub blocks: Vec<BlockSummary>,
}

impl WindowSummary {
    pub fn active_or_first_block_id(&self) -> Option<&str> {
        self.active_block_id
            .as_deref()
            .or_else(|| self.blocks.first().map(|block| block.id.as_str()))
    }
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
    let windows = windows(view);
    let (window, block_sel) = match window_selector {
        Some(selector) => resolve_window(&windows, selector, block_selector)?,
        None => (select_window(view, &windows, None)?, block_selector),
    };
    match block_sel {
        Some(selector) => find_block(window, selector),
        None => window.active_or_first_block_id().map(str::to_owned),
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
            let focused_block_id = window
                .get("focused_block_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let active_block_id = window
                .get("zoomed_block_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| focused_block_id.clone());
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
                focused_block_id,
                active_block_id,
                blocks,
            })
        })
        .collect()
}

/// A block's `owner` in a session view, or `None` when it has none.
pub fn owner_of(view: &Value, block_id: &str) -> Option<String> {
    let windows = view.get("windows").and_then(Value::as_array)?;
    windows
        .iter()
        .filter_map(|window| window.get("layers").and_then(Value::as_array))
        .flatten()
        .filter_map(|layer| layer.get("blocks").and_then(Value::as_array))
        .flatten()
        .find(|block| block.get("block_id").and_then(Value::as_str) == Some(block_id))
        .and_then(|block| block.get("owner").and_then(Value::as_str))
        .map(str::to_owned)
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

pub fn select_window<'a>(
    view: &Value,
    windows: &'a [WindowSummary],
    selector: Option<&str>,
) -> Option<&'a WindowSummary> {
    match selector {
        Some("-") => None,
        Some(selector) => find_window(windows, selector),
        None => {
            let id = active_window_id(view)?;
            windows.iter().find(|window| window.id == id)
        }
    }
}

fn resolve_window<'a, 's>(
    windows: &'a [WindowSummary],
    selector: &'s str,
    block: Option<&'s str>,
) -> Option<(&'a WindowSummary, Option<&'s str>)> {
    if let Some(window) = find_window(windows, selector) {
        return Some((window, block));
    }
    if block.is_none() {
        let (window, block) = split_window_block(selector)?;
        return Some((find_window(windows, window)?, Some(block)));
    }
    None
}

fn find_window<'a>(windows: &'a [WindowSummary], selector: &str) -> Option<&'a WindowSummary> {
    if let Some(window) = windows.iter().find(|window| window.id == selector) {
        return Some(window);
    }
    if let Ok(number) = selector.parse::<usize>()
        && let Some(window) = number.checked_sub(1).and_then(|idx| windows.get(idx))
    {
        return Some(window);
    }
    if let Some(window) = windows.iter().find(|window| window.label == selector) {
        return Some(window);
    }
    only(
        windows
            .iter()
            .filter(|window| window.label.starts_with(selector)),
    )
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
    fn reads_a_blocks_owner() {
        let view = json!({
            "windows": [{
                "window_id": "window:1",
                "layers": [{"blocks": [
                    {"block_id": "block:1", "owner": "client:2"},
                    {"block_id": "block:2"}
                ]}]
            }]
        });
        assert_eq!(owner_of(&view, "block:1").as_deref(), Some("client:2"));
        assert_eq!(owner_of(&view, "block:2"), None);
        assert_eq!(owner_of(&view, "block:3"), None);
    }

    #[test]
    fn names_match_a_label_an_id_or_the_tail_of_an_id() {
        let work = session("session:01a1a9ff-0560", "work");
        assert!(matches(&work, "work"));
        assert!(matches(&work, "WORK"));
        assert!(matches(&work, "session:01a1a9ff-0560"));
        assert!(matches(&work, "0560"));
        assert!(!matches(&work, "056"));
        assert!(!matches(&work, "rest"));
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
        let windows = windows(&view);
        let id = |selector| select_window(&view, &windows, selector).map(|w| w.id.as_str());
        assert_eq!(id(Some("2")), Some("window:logs"));
        assert_eq!(id(Some("0")), None);
        assert_eq!(id(Some("4")), None);
        assert_eq!(id(Some("logs")), Some("window:logs"));
        assert_eq!(id(Some("log")), None);
        assert_eq!(id(Some("build")), Some("window:build"));
        assert_eq!(id(Some("nope")), None);
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
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
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
                    "session.create" => {
                        if let Some(label) = req["payload"].get("label").and_then(Value::as_str) {
                            json!({"session_id": format!("session:2222-{label}")})
                        } else {
                            json!({"session_id": "session:2222-default"})
                        }
                    }
                    "session.view" => json!({
                        "active_window_id": "window:1",
                        "windows": [{"window_id": "window:1", "label": "editor", "focused_block_id": "block:1"}]
                    }),
                    "session.new_window" => {
                        assert_eq!(req["payload"]["focus"], json!(false));
                        if let Some(label) =
                            req["payload"].get("window_label").and_then(Value::as_str)
                        {
                            json!({"window_id": format!("window:{label}")})
                        } else {
                            json!({"window_id": "window:default"})
                        }
                    }
                    "session.set_label" => {
                        assert_eq!(req["payload"]["session_id"], "session:1111-aaaa");
                        assert_eq!(req["payload"]["label"], "renamed-session");
                        json!({"revision": 2})
                    }
                    "session.set_window_label" => {
                        assert_eq!(req["payload"]["session_id"], "session:1111-aaaa");
                        assert_eq!(req["payload"]["window_id"], "window:1");
                        assert_eq!(req["payload"]["label"], "renamed-window");
                        json!({"revision": 3})
                    }
                    "session.set_block_label" => {
                        assert_eq!(req["payload"]["session_id"], "session:1111-aaaa");
                        assert_eq!(req["payload"]["block_id"], "block:1");
                        assert_eq!(req["payload"]["label"], "");
                        json!({"revision": 4})
                    }
                    "session.close_window" => {
                        assert_eq!(req["payload"]["session_id"], "session:1111-aaaa");
                        assert_eq!(req["payload"]["window_id"], "window:1");
                        json!({"revision": 5})
                    }
                    "block.close" => {
                        assert_eq!(req["payload"]["session_id"], "session:1111-aaaa");
                        assert_eq!(req["payload"]["block_id"], "block:1");
                        json!({"block_id": "block:1", "revision": 6})
                    }
                    other => panic!("unexpected method {other}"),
                };
                ws.send(Message::text(
                    json!({"type": "response", "id": id, "seq": 0, "payload": payload}).to_string(),
                ))
                .await
                .unwrap();
            }
        });

        let server = format!("http://{addr}").parse().unwrap();
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
            "session:2222-fresh"
        );
        assert_eq!(
            create(&mut ctrl, None).await.unwrap(),
            "session:2222-default"
        );
        assert_eq!(
            create(&mut ctrl, Some("named")).await.unwrap(),
            "session:2222-named"
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
            ("window:logs".to_owned(), None)
        );
        assert_eq!(
            ensure_window(&mut ctrl, "session:1111-aaaa", "-", None)
                .await
                .unwrap(),
            ("window:default".to_owned(), None)
        );

        set_label(&mut ctrl, "session:1111-aaaa", "renamed-session")
            .await
            .unwrap();
        set_window_label(&mut ctrl, "session:1111-aaaa", "window:1", "renamed-window")
            .await
            .unwrap();
        set_block_label(&mut ctrl, BlockRef::new("session:1111-aaaa", "block:1"), "")
            .await
            .unwrap();
        close_window(&mut ctrl, "session:1111-aaaa", "window:1")
            .await
            .unwrap();
        close_block(&mut ctrl, BlockRef::new("session:1111-aaaa", "block:1"))
            .await
            .unwrap();
    }

    #[test]
    fn filters_stale_terminal_titles_using_process_owner() {
        let pi_title = json!({
            "title": "π - jack",
            "owner": {"pid": 420, "name": "node"}
        });
        let pi_running = json!({
            "last_exit": null,
            "foreground": {"pid": 420, "name": "node"},
            "child": {"pid": 100, "name": "login"},
            "ancestors": [{"pid": 200, "name": "zsh"}]
        });
        assert_eq!(
            live_terminal_title(&pi_title, Some(&pi_running)),
            Some("π - jack")
        );

        let pi_in_ancestors = json!({
            "last_exit": null,
            "foreground": {"pid": 500, "name": "cargo"},
            "ancestors": [{"pid": 420, "name": "node"}, {"pid": 200, "name": "zsh"}]
        });
        assert_eq!(
            live_terminal_title(&pi_title, Some(&pi_in_ancestors)),
            Some("π - jack")
        );

        // Process exited back to zsh -> stale title is dropped.
        let back_to_zsh = json!({
            "last_exit": null,
            "foreground": {"pid": 200, "name": "zsh"},
            "child": {"pid": 100, "name": "login"}
        });
        assert_eq!(live_terminal_title(&pi_title, Some(&back_to_zsh)), None);

        // PID reused by a different executable name -> still stale.
        let reused_pid = json!({
            "last_exit": null,
            "foreground": {"pid": 420, "name": "zsh"}
        });
        assert_eq!(live_terminal_title(&pi_title, Some(&reused_pid)), None);

        // Terminal exited completely -> stale.
        let exited = json!({
            "last_exit": {"exit_code": 0},
            "foreground": null,
            "child": null
        });
        assert_eq!(live_terminal_title(&pi_title, Some(&exited)), None);

        // Missing owner or unreadable process list preserves the title.
        let unowned = json!({"title": "manual title"});
        assert_eq!(
            live_terminal_title(&unowned, Some(&back_to_zsh)),
            Some("manual title")
        );
        assert_eq!(live_terminal_title(&pi_title, None), Some("π - jack"));
        assert_eq!(
            live_terminal_title(&pi_title, Some(&json!({"last_exit": null}))),
            Some("π - jack")
        );
    }

    #[test]
    fn process_name_prefers_script_then_argv0_then_name() {
        assert_eq!(
            process_name(&json!({
                "foreground": {
                    "script": "/opt/homebrew/bin/agy",
                    "argv0": "node",
                    "name": "node"
                }
            }))
            .as_deref(),
            Some("agy")
        );
        assert_eq!(
            process_name(&json!({
                "foreground": {
                    "argv0": "-zsh",
                    "name": "zsh"
                }
            }))
            .as_deref(),
            Some("zsh")
        );
        assert_eq!(
            process_name(&json!({
                "foreground": {
                    "argv0": "/bin/zsh",
                    "name": "zsh"
                }
            }))
            .as_deref(),
            Some("zsh")
        );
        assert_eq!(
            process_name(&json!({
                "foreground": null,
                "child": {
                    "argv0": "",
                    "name": "fish"
                }
            }))
            .as_deref(),
            Some("fish")
        );
        assert_eq!(
            process_name(&json!({"foreground": null, "child": null})),
            None
        );
    }

    #[test]
    fn fallback_title_prefers_custom_window_label_and_falls_back_to_session_label() {
        let view = json!({
            "windows": [
                {
                    "window_id": "window:1",
                    "label": "Antigravity ~/Projects/zrex",
                    "layers": [{"blocks": [{"block_id": "block:1"}]}]
                },
                {
                    "window_id": "window:2",
                    "label": "Window 1234abcd",
                    "layers": [{"blocks": [{"block_id": "block:2"}]}]
                }
            ]
        });
        let bootstrap = json!({
            "selected_session": {
                "label": "work",
                "view": view
            }
        });
        assert_eq!(
            fallback_title_for(&bootstrap, &view, "block:1").as_deref(),
            Some("Antigravity ~/Projects/zrex")
        );
        assert_eq!(
            fallback_title_for(&bootstrap, &view, "block:2").as_deref(),
            Some("work")
        );
    }

    #[test]
    fn resolved_terminal_title_prefers_live_title_then_process_and_osc7_pwd() {
        let process = json!({"foreground": {"pid": 200, "argv0": "-zsh", "name": "zsh"}});
        let screen = b"hello\x1b]7;file://MacBook.local/tmp/my%20dir\x07world";
        let live = json!({"title": "vim", "owner": {"pid": 200, "name": "zsh"}});
        let stale = json!({"title": "old", "owner": {"pid": 999, "name": "node"}});

        assert_eq!(
            resolved_terminal_title(Some(&live), Some(&process), Some(screen)).as_deref(),
            Some("vim")
        );
        assert_eq!(
            resolved_terminal_title(Some(&stale), Some(&process), Some(screen)).as_deref(),
            Some("zsh /tmp/my dir")
        );
        assert_eq!(
            resolved_terminal_title(Some(&stale), Some(&process), None).as_deref(),
            Some("zsh")
        );
        assert_eq!(
            process_pwd_title(Some(&process), Some(b"no osc7")).as_deref(),
            Some("zsh")
        );
    }

    #[test]
    fn detects_known_agent_processes_across_fields_and_ancestors() {
        assert!(has_agent_process(&json!({
            "last_exit": null,
            "foreground": {"pid": 200, "name": "agy"}
        })));
        assert!(has_agent_process(&json!({
            "last_exit": null,
            "foreground": {
                "pid": 201,
                "name": "node",
                "script": "/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js"
            }
        })));
        assert!(has_agent_process(&json!({
            "last_exit": null,
            "foreground": {
                "pid": 202,
                "name": "2.1.76",
                "argv0": "claude",
                "script": "/opt/claude/cli.js"
            }
        })));
        assert!(has_agent_process(&json!({
            "last_exit": null,
            "foreground": {
                "pid": 203,
                "name": "node",
                "invoked_path": "/opt/homebrew/bin/gemini"
            }
        })));
        assert!(has_agent_process(&json!({
            "last_exit": null,
            "foreground": {"pid": 300, "name": "cargo"},
            "ancestors": [
                {"pid": 250, "name": "zsh"},
                {"pid": 200, "name": "claude"}
            ],
            "child": {"pid": 100, "name": "login"}
        })));
        assert!(!has_agent_process(&json!({
            "last_exit": {"exit_code": 0},
            "foreground": {"pid": 200, "name": "claude"}
        })));
        assert!(!has_agent_process(&json!({
            "last_exit": null,
            "foreground": {"pid": 200, "argv0": "-zsh", "name": "zsh"},
            "child": {"pid": 100, "name": "login"}
        })));
    }
}

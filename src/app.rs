use std::io::{IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use serde_json::{Value, json};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

use crate::rex::control::{Control, Events};
use crate::rex::data::{self, Data, StreamClosed};
use crate::rex::proto;
use crate::rex::stream::{self, Filter};
use crate::session;

const DATA_REF: &str = "terminal";
const MAX_BLOB_BYTES: usize = 983_040;
const PROBE_EVERY: Duration = Duration::from_secs(10);
const PROBE_TIME: Duration = Duration::from_secs(5);
const RETRY_FIRST: Duration = Duration::from_millis(250);
const RETRY_MAX: Duration = Duration::from_secs(5);
const THEME_PROBE_TIMEOUT: Duration = Duration::from_millis(100);
/// DECSET 2031 asks the host terminal to report light and dark switches, which
/// the block's theme follows while attached.
const WATCH_SCHEME: &[u8] = b"\x1b[?2031h";

const RESET_COLORS: &[u8] =
    b"\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\\x1b]104\x07\x1b]110\x07\x1b]111\x07\x1b]112\x07";

/// Restore host terminal state on exit in case a program inside the block
/// enabled alternate screen, mouse tracking, Kitty keyboard, color-scheme
/// reporting, or custom palette colors.
const RESET_MODES: &[u8] = concat!(
    "\x1b[?2026l",
    "\x1b[<u",
    "\x1b[>4;0m",
    "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l",
    "\x1b[?1004l",
    "\x1b[?2004l",
    "\x1b[?2031l",
    "\x1b[?1l\x1b>",
    "\x1b[?1049l",
    "\x1b[r",
    "\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\",
    "\x1b]104\x07\x1b]110\x07\x1b]111\x07\x1b]112\x07",
    "\x1b[?25h",
    "\x1b[0m\r\n",
)
.as_bytes();

/// Forwarded to `com.superlogical.terminal.set_theme` when taking block
/// ownership so server-side terminal queries report the host terminal's theme
/// instead of the server's built-in dark default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Theme {
    foreground: Option<String>,
    background: Option<String>,
    cursor: Option<String>,
    palette: Vec<String>,
    scheme: Option<String>,
}

impl Theme {
    fn is_empty(&self) -> bool {
        self.foreground.is_none()
            && self.background.is_none()
            && self.cursor.is_none()
            && self.palette.is_empty()
            && self.scheme.is_none()
    }

    fn to_json(&self) -> Value {
        let mut args = json!({});
        if let Some(fg) = &self.foreground {
            args["foreground"] = json!(fg);
        }
        if let Some(bg) = &self.background {
            args["background"] = json!(bg);
        }
        if let Some(cursor) = &self.cursor {
            args["cursor"] = json!(cursor);
        }
        if !self.palette.is_empty() {
            args["palette"] = json!(self.palette);
        }
        if let Some(scheme) = &self.scheme {
            args["scheme"] = json!(scheme);
        }
        args
    }
}

pub fn ensure_terminal() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("zrex needs a terminal to attach to a session");
    }
    Ok(())
}

pub async fn attach(
    server: &str,
    target: Option<String>,
    window: Option<String>,
    block: Option<String>,
) -> Result<()> {
    ensure_terminal()?;
    let (mut ctrl, mut events) = Control::connect(server, None).await?;
    let session_id = match target.as_deref() {
        Some(target) => session::find_or_create(&mut ctrl, target).await?,
        None => session::pick(&mut ctrl, None).await?,
    };
    let (window, block) = match window.as_deref() {
        Some(selector) => {
            ctrl.call("session.attach", json!({"session_id": session_id}))
                .await?;
            let (win_id, blk) =
                session::ensure_window(&mut ctrl, &session_id, selector, block.as_deref()).await?;
            (Some(win_id), blk)
        }
        None => (None, block),
    };
    let size = crossterm::terminal::size()?;
    let mut guard = Screen::enter()?;
    let theme = guard.probe_theme();
    let mut attached = Attached::start(
        &mut ctrl,
        &session_id,
        server,
        window.as_deref(),
        block.as_deref(),
        size,
        theme,
    )
    .await?;

    let mut input = spawn_input();
    let mut winch = signal(SignalKind::window_change())?;
    let mut probe = tokio::time::interval(PROBE_EVERY);
    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    probe.reset();
    let mut token = ctrl.reconnect_token.clone();

    loop {
        let mut lost: Option<anyhow::Error> = None;
        tokio::select! {
            chunk = attached.data.next_chunk() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        if let Err(error) = attached.feed(&bytes, &mut ctrl).await {
                            lost = Some(error);
                        } else {
                            while let Some(next) = attached.data.try_next_chunk() {
                                match next {
                                    Ok(more) => {
                                        if let Err(error) = attached.feed(&more, &mut ctrl).await {
                                            lost = Some(error);
                                            break;
                                        }
                                    }
                                    Err(error) if closed_block(&error) => {
                                        attached.flush(guard.out())?;
                                        guard.leave()?;
                                        println!("the block closed");
                                        return Ok(());
                                    }
                                    Err(error) => {
                                        lost = Some(stream_lost(error));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Some(Err(error)) if closed_block(&error) => {
                        guard.leave()?;
                        println!("the block closed");
                        return Ok(());
                    }
                    Some(Err(error)) => lost = Some(stream_lost(error)),
                    None => lost = Some(data_ended()),
                }
            }
            message = events.recv() => {
                match message {
                    Some((name, payload)) => {
                        match attached.event(&name, &payload, &mut ctrl).await {
                            Ok(Some(ending)) => {
                                guard.leave()?;
                                println!("{}", ending.message());
                                return Ok(());
                            }
                            Ok(None) => {}
                            Err(error) => lost = Some(error),
                        }
                    }
                    None => lost = Some(anyhow!("the control connection ended")),
                }
            }
            Some(bytes) = input.recv() => {
                match attached.burst(&bytes, &mut input, &mut ctrl).await {
                    Ok(Flow::Detach) => {
                        detach(&mut ctrl, &attached).await;
                        guard.leave()?;
                        println!("detached from {}", attached.session_id);
                        return Ok(());
                    }
                    Ok(Flow::Continue) => {}
                    Err(error) => lost = Some(error),
                }
            }
            _ = winch.recv() => {
                if let Ok((cols, rows)) = crossterm::terminal::size()
                    && let Err(error) = attached.resize(cols, rows, &mut ctrl).await
                {
                    lost = Some(error);
                }
            }
            _ = probe.tick() => {
                // A socket reports a dead network only when something uses
                // it, so use it.
                match tokio::time::timeout(PROBE_TIME, ctrl.call("server.version", Value::Null))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => lost = Some(error),
                    Err(_) => lost = Some(anyhow!("the server stopped answering")),
                }
            }
        }

        if lost.is_none() && attached.theme_dirty {
            match attached
                .refresh_theme(guard.out(), &mut input, &mut ctrl)
                .await
            {
                Ok(Flow::Continue) => {}
                Ok(Flow::Detach) => {
                    detach(&mut ctrl, &attached).await;
                    guard.leave()?;
                    println!("detached from {}", attached.session_id);
                    return Ok(());
                }
                Err(error) => lost = Some(error),
            }
        }

        if let Some(error) = lost {
            if !transient(&ctrl, &error) {
                return Err(error);
            }
            match recover(
                server,
                &mut token,
                &mut ctrl,
                &mut events,
                &mut attached,
                &mut input,
            )
            .await?
            {
                Recovered::Live => {}
                Recovered::Detach => {
                    detach(&mut ctrl, &attached).await;
                    guard.leave()?;
                    println!("detached from {}", attached.session_id);
                    return Ok(());
                }
                Recovered::Ended(ending) => {
                    guard.leave()?;
                    println!("{}", ending.message());
                    return Ok(());
                }
            }
        }

        attached.flush(guard.out())?;
    }
}

#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Detach,
}

enum Ending {
    Block,
    Session,
}

impl Ending {
    fn message(&self) -> &'static str {
        match self {
            Ending::Block => "the block closed",
            Ending::Session => "the session closed",
        }
    }
}

struct Attached {
    server: String,
    session_id: String,
    block_id: String,
    client_id: String,
    size: (u16, u16),
    theme: Theme,
    data: Data,
    filter: Filter,
    pending: Vec<u8>,
    out: Vec<u8>,
    input_buf: Vec<u8>,
    primed: bool,
    theme_dirty: bool,
    owns: bool,
}

impl Attached {
    async fn start(
        ctrl: &mut Control,
        session_id: &str,
        server: &str,
        window: Option<&str>,
        block: Option<&str>,
        (cols, rows): (u16, u16),
        theme: Theme,
    ) -> Result<Self> {
        let bootstrap = ctrl
            .call(
                "session.bootstrap",
                json!({
                    "event_scope": "all",
                    "preferred_session_id": session_id,
                }),
            )
            .await?;
        let client_id = bootstrap
            .get("client_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("bootstrap returned no client_id"))?
            .to_owned();
        let view = bootstrap
            .get("selected_session")
            .and_then(|selected| selected.get("view"))
            .cloned()
            .ok_or_else(|| anyhow!("bootstrap attached to no session"))?;
        let block_id =
            session::block_of(&view, window, block).ok_or_else(|| match (window, block) {
                (_, Some(blk)) => anyhow!("the window has no block {blk}"),
                (Some(win), None) => anyhow!("the session has no window {win}"),
                (None, None) => anyhow!("the session's active window shows no block"),
            })?;

        finish_call(start_take(ctrl, session_id, &block_id)?).await?;
        let ticket_rx = start_ticket(ctrl, session_id, &block_id)?;
        publish(
            ctrl,
            session_id,
            &block_id,
            (cols, rows),
            &theme,
            Push::Both,
        )
        .await?;
        let ticket = parse_ticket(&finish_call(ticket_rx).await?)?;
        let data = Data::open(server, &ticket).await?;
        let filter = Filter::new(data.nonce);
        let attached = Self {
            server: server.to_owned(),
            session_id: session_id.to_owned(),
            block_id,
            client_id,
            size: (cols, rows),
            theme,
            data,
            filter,
            pending: Vec::new(),
            out: Vec::new(),
            input_buf: Vec::new(),
            primed: false,
            theme_dirty: false,
            owns: true,
        };
        attached.focus(ctrl, "in")?;
        Ok(attached)
    }

    async fn feed(&mut self, bytes: &[u8], ctrl: &mut Control) -> Result<()> {
        if self.primed {
            let filtered = self.filter.push(bytes);
            self.out.extend_from_slice(&filtered);
            return Ok(());
        }
        self.pending.extend_from_slice(bytes);
        let Some(len) = stream::snapshot_len(&self.pending)? else {
            return Ok(());
        };
        let _ = self.filter.push(&self.pending[len..]);
        self.pending.clear();
        self.prime(ctrl).await
    }

    async fn prime(&mut self, ctrl: &mut Control) -> Result<()> {
        let screen = format_vt(ctrl, &self.session_id, &self.block_id).await?;
        self.out.extend_from_slice(b"\x1b[2J\x1b[H");
        self.out.extend_from_slice(&screen);
        self.primed = true;
        Ok(())
    }

    fn flush(&mut self, out: &mut impl Write) -> Result<()> {
        if self.out.is_empty() {
            return Ok(());
        }
        out.write_all(&self.out)?;
        out.flush()?;
        self.out.clear();
        Ok(())
    }

    /// Programs in the block ask the server for colors, so the theme zrex gave
    /// the server has to keep up with the host or their answers go stale.
    async fn refresh_theme(
        &mut self,
        out: &mut impl Write,
        input: &mut mpsc::UnboundedReceiver<Vec<u8>>,
        ctrl: &mut Control,
    ) -> Result<Flow> {
        self.flush(out)?;
        out.write_all(theme_query().as_bytes())?;
        out.flush()?;
        let deadline = Instant::now() + THEME_PROBE_TIMEOUT;
        let mut replies = Vec::new();
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            let Ok(Some(bytes)) = tokio::time::timeout(remaining, input.recv()).await else {
                break;
            };
            let (found, typed) = split_replies(&bytes);
            replies.extend_from_slice(&found);
            if !typed.is_empty() {
                let flow = self.queue_input(&typed);
                self.flush_input(ctrl)?;
                if flow == Flow::Detach {
                    return Ok(Flow::Detach);
                }
            }
            if has_da1_reply(&replies) {
                break;
            }
        }
        self.theme_dirty = false;
        let theme = parse_theme_reply(&replies);
        if theme.is_empty() || theme == self.theme {
            return Ok(Flow::Continue);
        }
        self.theme = theme;
        self.sync(ctrl, Push::Theme).await?;
        Ok(Flow::Continue)
    }

    async fn burst(
        &mut self,
        first: &[u8],
        input: &mut mpsc::UnboundedReceiver<Vec<u8>>,
        ctrl: &mut Control,
    ) -> Result<Flow> {
        if self.queue_input(first) == Flow::Detach {
            self.flush_input(ctrl)?;
            return Ok(Flow::Detach);
        }
        while let Ok(bytes) = input.try_recv() {
            if self.queue_input(&bytes) == Flow::Detach {
                self.flush_input(ctrl)?;
                return Ok(Flow::Detach);
            }
        }
        let typed = !self.input_buf.is_empty();
        self.flush_input(ctrl)?;
        if typed && !self.owns {
            self.claim(ctrl).await?;
        }
        Ok(Flow::Continue)
    }

    fn queue_input(&mut self, bytes: &[u8]) -> Flow {
        if is_detach(bytes) {
            return Flow::Detach;
        }
        let (replies, typed) = split_replies(bytes);
        if reports_scheme(&replies) {
            self.theme_dirty = true;
        }
        if !typed.is_empty() {
            self.input_buf.extend_from_slice(&typed);
        }
        Flow::Continue
    }

    fn flush_input(&mut self, ctrl: &mut Control) -> Result<()> {
        let text = take_utf8(&mut self.input_buf);
        if !text.is_empty() {
            ctrl.post_write(&self.session_id, &self.block_id, &text)?;
        }
        Ok(())
    }

    async fn resize(&mut self, cols: u16, rows: u16, ctrl: &mut Control) -> Result<()> {
        if cols == 0 || rows == 0 {
            return Ok(());
        }
        self.size = (cols, rows);
        self.sync(ctrl, Push::Size).await
    }

    async fn claim(&mut self, ctrl: &mut Control) -> Result<()> {
        finish_call(start_take(ctrl, &self.session_id, &self.block_id)?).await?;
        self.owns = true;
        self.sync(ctrl, Push::Both).await
    }

    /// The block takes its size and colors from its owner, so this client
    /// publishes its own only while it holds the block and keeps them for the
    /// next claim.
    async fn sync(&mut self, ctrl: &mut Control, push: Push) -> Result<()> {
        if !self.owns {
            return Ok(());
        }
        publish(
            ctrl,
            &self.session_id,
            &self.block_id,
            self.size,
            &self.theme,
            push,
        )
        .await
    }

    fn focus(&self, ctrl: &mut Control, action: &str) -> Result<()> {
        ctrl.post_event(
            &self.session_id,
            &self.block_id,
            json!({"type": "focus", "payload": {"action": action}}),
        )
    }

    async fn event(
        &mut self,
        event: &str,
        body: &Value,
        ctrl: &mut Control,
    ) -> Result<Option<Ending>> {
        let session = body
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !session.is_empty() && session != self.session_id {
            return Ok(None);
        }
        let block = body
            .get("block_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match event {
            "session_destroyed" => return Ok(Some(Ending::Session)),
            "block_closed" => {
                if block == self.block_id {
                    return Ok(Some(Ending::Block));
                }
            }
            "block_owner_changed" => {
                let owner = body
                    .get("owner")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if block == self.block_id {
                    // Claiming the block back here would make two clients trade
                    // it forever, so a client that lost it waits for the user
                    // to type.
                    let owned = owner == self.client_id;
                    if owned != self.owns {
                        self.owns = owned;
                        self.sync(ctrl, Push::Both).await?;
                    }
                }
            }
            "block_event" if block == self.block_id => {
                self.block_event(body, ctrl).await?;
            }
            _ => {}
        }
        Ok(None)
    }

    async fn block_event(&mut self, body: &Value, ctrl: &mut Control) -> Result<()> {
        let name = body.get("name").and_then(Value::as_str).unwrap_or_default();
        let payload = body.get("payload").cloned().unwrap_or(Value::Null);
        match name {
            "bell" => {
                self.out.push(b'\x07');
            }
            "clipboard_written" => {
                let text = match payload.get("text").and_then(Value::as_str) {
                    Some(text) => text.to_owned(),
                    None => {
                        let id = payload.get("id").and_then(Value::as_i64).unwrap_or(0);
                        clipboard(ctrl, &self.session_id, &self.block_id, id).await?
                    }
                };
                if !text.is_empty() {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
                    self.out
                        .extend_from_slice(format!("\x1b]52;c;{encoded}\x07").as_bytes());
                }
            }
            "desktop_notification" => {
                let title = payload.get("title").and_then(Value::as_str).unwrap_or("");
                let body = payload.get("body").and_then(Value::as_str).unwrap_or("");
                let text = if title.is_empty() {
                    body.to_owned()
                } else {
                    format!("{title}: {body}")
                };
                let clean = text.replace(['\x07', '\x1b'], "");
                if !clean.is_empty() {
                    self.out
                        .extend_from_slice(format!("\x1b]9;{clean}\x07").as_bytes());
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn reconnect(&mut self, ctrl: &mut Control) -> Result<Option<Ending>> {
        let bootstrap = ctrl
            .call(
                "session.bootstrap",
                json!({
                    "event_scope": "all",
                    "preferred_session_id": self.session_id,
                }),
            )
            .await?;
        let Some(view) = bootstrap
            .get("selected_session")
            .and_then(|selected| selected.get("view"))
        else {
            return Ok(Some(Ending::Session));
        };
        if let Some(client_id) = bootstrap.get("client_id").and_then(Value::as_str) {
            self.client_id = client_id.to_owned();
        }
        if let Ok(size) = crossterm::terminal::size() {
            self.size = size;
        }
        // A dropped connection gives the block back to its owner, unless
        // another client claimed it meanwhile. Claim it again only when
        // nobody else holds it.
        let owner = session::owner_of(view, &self.block_id);
        if owner.is_some_and(|owner| owner != self.client_id) {
            self.owns = false;
            self.reconnect_data(ctrl).await?;
            return Ok(None);
        }
        if let Err(error) = finish_call(start_take(ctrl, &self.session_id, &self.block_id)?).await {
            // A refusal while the block is still in the view is worth another
            // try. A missing block is not.
            if session::has_block(view, &self.block_id) {
                return Err(error);
            }
            return Ok(Some(Ending::Block));
        }
        self.owns = true;
        self.sync(ctrl, Push::Both).await?;
        self.reconnect_data(ctrl).await?;
        Ok(None)
    }

    async fn reconnect_data(&mut self, ctrl: &mut Control) -> Result<()> {
        match Data::resume(&self.server, self.data.token, self.data.received).await {
            Ok(data) => {
                self.filter = Filter::new(data.nonce);
                self.data = data;
                Ok(())
            }
            Err(_) => {
                let ticket = ticket(ctrl, &self.session_id, &self.block_id).await?;
                self.data = Data::open(&self.server, &ticket).await?;
                self.filter = Filter::new(self.data.nonce);
                self.pending.clear();
                self.primed = false;
                Ok(())
            }
        }
    }
}

fn is_detach(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        b"\x1c"
            | b"\x1b[92;5u"
            | b"\x1b[92;5:1u"
            | b"\x1b[92;5:2u"
            | b"\x1b[92:124;5u"
            | b"\x1b[92:124;5:1u"
            | b"\x1b[92:124;5:2u"
            | b"\x1b[27;5;92~"
    )
}

/// Asks the host terminal for its default colors and its whole 256-color
/// palette. DA1 (`ESC [ c`) acts as a completion sentinel because terminals
/// answer queries in order and always support DA1, even if they ignore OSC 4
/// or OSC 10.
fn theme_query() -> String {
    let mut query = String::from("\x1b]10;?\x07\x1b]11;?\x07\x1b]12;?\x07");
    for index in 0..=255 {
        query.push_str(&format!("\x1b]4;{index};?\x07"));
    }
    query.push_str("\x1b[c");
    query
}

/// The Rex server's `libghostty-vt` answers terminal queries on the server
/// side, so forwarding the local terminal's duplicate replies into
/// `com.superlogical.terminal.write` would inject unconsumed escape sequences
/// into the remote PTY. The replies still carry the host's colors, which is why
/// they are kept rather than dropped.
fn split_replies(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut replies = Vec::new();
    let mut typed = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() {
            let end = match bytes[i + 1] {
                b']' => osc_reply_end(&bytes[i..]),
                b'[' => csi_reply_end(&bytes[i..]),
                _ => None,
            };
            if let Some(end) = end {
                replies.extend_from_slice(&bytes[i..i + end]);
                i += end;
                continue;
            }
        }
        typed.push(bytes[i]);
        i += 1;
    }
    (replies, typed)
}

/// DECSET 2031's report: `ESC [ ? 997 ; Ps n`, where Ps is 1 for dark and 2
/// for light.
fn reports_scheme(replies: &[u8]) -> bool {
    replies.windows(7).any(|window| window == b"\x1b[?997;")
}

fn osc_reply_end(slice: &[u8]) -> Option<usize> {
    let rest = slice.strip_prefix(b"\x1b]")?;
    let semi = rest.iter().position(|&b| b == b';')?;
    let code = std::str::from_utf8(&rest[..semi]).ok()?;
    if !matches!(code, "4" | "10" | "11" | "12") {
        return None;
    }
    let body = &rest[semi + 1..];
    for (idx, &b) in body.iter().enumerate() {
        if b == 0x07 {
            return Some(2 + semi + 1 + idx + 1);
        }
        if b == 0x1b && body.get(idx + 1) == Some(&b'\\') {
            return Some(2 + semi + 1 + idx + 2);
        }
    }
    None
}

fn csi_reply_end(slice: &[u8]) -> Option<usize> {
    let rest = slice.strip_prefix(b"\x1b[")?;
    let (&prefix, params) = rest.split_first()?;
    if prefix != b'?' && prefix != b'>' {
        return None;
    }
    let end = params
        .iter()
        .position(|&b| !b.is_ascii_digit() && b != b';' && b != b':')?;
    let final_byte = params[end];
    if final_byte == b'c' || (prefix == b'?' && final_byte == b'n' && params.starts_with(b"997;")) {
        return Some(2 + 1 + end + 1);
    }
    None
}

fn parse_theme_reply(bytes: &[u8]) -> Theme {
    let mut theme = Theme::default();
    let text = String::from_utf8_lossy(bytes);
    for part in text.split("\x1b]") {
        let Some(end) = part.find('\x07').or_else(|| part.find("\x1b\\")) else {
            continue;
        };
        let body = &part[..end];
        let Some((code, rest)) = body.split_once(';') else {
            continue;
        };
        match code {
            "10" => theme.foreground = parse_osc_rgb(rest).map(|(hex, _)| hex),
            "11" => {
                if let Some((hex, (r, g, b))) = parse_osc_rgb(rest) {
                    let luma =
                        (299 * u32::from(r) + 587 * u32::from(g) + 114 * u32::from(b)) / 1000;
                    theme.scheme = Some(if luma >= 128 { "light" } else { "dark" }.to_owned());
                    theme.background = Some(hex);
                }
            }
            "12" => theme.cursor = parse_osc_rgb(rest).map(|(hex, _)| hex),
            "4" => {
                if let Some((idx_str, color_str)) = rest.split_once(';')
                    && let Ok(idx) = idx_str.parse::<u8>()
                    && let Some((hex, _)) = parse_osc_rgb(color_str)
                {
                    theme.palette.push(format!("{idx}={hex}"));
                }
            }
            _ => {}
        }
    }
    theme
}

fn parse_osc_rgb(s: &str) -> Option<(String, (u8, u8, u8))> {
    let rgb = s.strip_prefix("rgb:")?;
    let mut parts = rgb.split('/');
    let r = parse_color_channel(parts.next()?)?;
    let g = parse_color_channel(parts.next()?)?;
    let b = parse_color_channel(parts.next()?)?;
    Some((format!("#{r:02x}{g:02x}{b:02x}"), (r, g, b)))
}

fn parse_color_channel(hex: &str) -> Option<u8> {
    if hex.len() >= 2 {
        u8::from_str_radix(&hex[..2], 16).ok()
    } else if hex.len() == 1 {
        let v = u8::from_str_radix(hex, 16).ok()?;
        Some((v << 4) | v)
    } else {
        None
    }
}

fn take_utf8(buf: &mut Vec<u8>) -> String {
    let mut out = String::new();
    loop {
        match std::str::from_utf8(buf) {
            Ok(valid) => {
                out.push_str(valid);
                buf.clear();
                return out;
            }
            Err(error) => {
                let valid_len = error.valid_up_to();
                if valid_len > 0 {
                    out.push_str(std::str::from_utf8(&buf[..valid_len]).unwrap());
                    buf.drain(..valid_len);
                }
                match error.error_len() {
                    None => return out,
                    Some(invalid_len) => {
                        out.push(char::REPLACEMENT_CHARACTER);
                        buf.drain(..invalid_len);
                    }
                }
            }
        }
    }
}

async fn finish_call(rx: tokio::sync::oneshot::Receiver<Result<Value>>) -> Result<Value> {
    rx.await
        .map_err(|_| anyhow!("the control connection ended"))?
}

fn start_take(
    ctrl: &mut Control,
    session_id: &str,
    block_id: &str,
) -> Result<tokio::sync::oneshot::Receiver<Result<Value>>> {
    ctrl.start_call(
        "session.own_block",
        json!({
            "session_id": session_id,
            "block_ids": [block_id],
            "mode": "take",
        }),
    )
}

fn start_set_theme(
    ctrl: &mut Control,
    session_id: &str,
    block_id: &str,
    theme: &Theme,
) -> Result<tokio::sync::oneshot::Receiver<Result<Value>>> {
    ctrl.start_call(
        "com.superlogical.terminal.set_theme",
        json!({
            "session_id": session_id,
            "block_id": block_id,
            "args": theme.to_json(),
        }),
    )
}

fn start_resize(
    ctrl: &mut Control,
    session_id: &str,
    block_id: &str,
    cols: u16,
    rows: u16,
) -> Result<tokio::sync::oneshot::Receiver<Result<Value>>> {
    ctrl.start_call(
        "com.superlogical.terminal.resize",
        json!({
            "session_id": session_id,
            "block_id": block_id,
            "args": {"columns": cols, "rows": rows},
        }),
    )
}

/// Which part of the block's state to publish. A client publishes what it
/// changed while it holds the block, or both when it takes it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Push {
    Size,
    Theme,
    Both,
}

impl Push {
    fn size(self) -> bool {
        matches!(self, Self::Size | Self::Both)
    }

    fn theme(self) -> bool {
        matches!(self, Self::Theme | Self::Both)
    }
}

async fn publish(
    ctrl: &mut Control,
    session_id: &str,
    block_id: &str,
    size: (u16, u16),
    theme: &Theme,
    push: Push,
) -> Result<()> {
    let theme_rx = (push.theme() && !theme.is_empty())
        .then(|| start_set_theme(ctrl, session_id, block_id, theme))
        .transpose()?;
    let size_rx = push
        .size()
        .then(|| start_resize(ctrl, session_id, block_id, size.0, size.1))
        .transpose()?;
    if let Some(rx) = theme_rx {
        finish_call(rx).await?;
    }
    if let Some(rx) = size_rx {
        finish_call(rx).await?;
    }
    Ok(())
}

/// `extra_palette` is omitted so the server's 256-color table does not
/// overwrite the host terminal's color theme via OSC 4.
async fn format_vt(ctrl: &mut Control, session_id: &str, block_id: &str) -> Result<Vec<u8>> {
    let reply = ctrl
        .call(
            "com.superlogical.terminal.format",
            json!({
                "session_id": session_id,
                "block_id": block_id,
                "args": {
                    "format": "vt",
                    "trim": false,
                    "extra_cursor": true,
                    "extra_style": true,
                    "extra_modes": true,
                    "extra_scrolling_region": true,
                    "extra_tabstops": true,
                    "extra_keyboard": true,
                    "extra_kitty_keyboard": true,
                    "extra_charsets": true,
                    "extra_hyperlink": true,
                    "extra_protection": true,
                    "extra_pwd": true,
                    "max_bytes": MAX_BLOB_BYTES,
                },
            }),
        )
        .await?;
    let content = reply
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let Some(id) = reply.get("id").and_then(Value::as_i64) else {
        return Ok(content.into_bytes());
    };
    let full = read_chunks(
        ctrl,
        session_id,
        block_id,
        "com.superlogical.terminal.blob_read",
        id,
        content,
    )
    .await?;
    Ok(full.into_bytes())
}

async fn clipboard(
    ctrl: &mut Control,
    session_id: &str,
    block_id: &str,
    id: i64,
) -> Result<String> {
    read_chunks(
        ctrl,
        session_id,
        block_id,
        "com.superlogical.terminal.clipboard_read",
        id,
        String::new(),
    )
    .await
}

async fn read_chunks(
    ctrl: &mut Control,
    session_id: &str,
    block_id: &str,
    method: &str,
    id: i64,
    mut out: String,
) -> Result<String> {
    loop {
        let part = ctrl
            .call(
                method,
                json!({
                    "session_id": session_id,
                    "block_id": block_id,
                    "args": {"id": id, "offset": out.len(), "max_bytes": MAX_BLOB_BYTES},
                }),
            )
            .await?;
        out.push_str(part.get("data").and_then(Value::as_str).unwrap_or_default());
        if part.get("eof").and_then(Value::as_bool).unwrap_or(true) {
            break;
        }
    }
    Ok(out)
}

fn spawn_input() -> mpsc::UnboundedReceiver<Vec<u8>> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                return;
            }
        }
    });
    rx
}

enum Recovered {
    Live,
    Detach,
    Ended(Ending),
}

async fn recover(
    server: &str,
    token: &mut Option<String>,
    ctrl: &mut Control,
    events: &mut Events,
    attached: &mut Attached,
    input: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<Recovered> {
    let mut delay = RETRY_FIRST;
    loop {
        match attempt(server, token, ctrl, events, attached).await {
            Ok(None) => {
                // Keys pressed while the link was down have nowhere to go.
                while input.try_recv().is_ok() {}
                return Ok(Recovered::Live);
            }
            Ok(Some(ending)) => return Ok(Recovered::Ended(ending)),
            Err(_) => {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    Some(bytes) = input.recv() => {
                        if is_detach(&bytes) {
                            return Ok(Recovered::Detach);
                        }
                    }
                }
                delay = backoff(delay);
            }
        }
    }
}

async fn attempt(
    server: &str,
    token: &mut Option<String>,
    ctrl: &mut Control,
    events: &mut Events,
    attached: &mut Attached,
) -> Result<Option<Ending>> {
    if ctrl.call("server.version", Value::Null).await.is_err() {
        let (new_ctrl, new_events) = Control::connect(server, token.as_deref()).await?;
        *token = new_ctrl.reconnect_token.clone();
        *ctrl = new_ctrl;
        *events = new_events;
    }
    attached.reconnect(ctrl).await
}

fn backoff(delay: Duration) -> Duration {
    (delay * 2).min(RETRY_MAX)
}

fn transient(ctrl: &Control, error: &anyhow::Error) -> bool {
    if ctrl.is_lost() || error.downcast_ref::<StreamClosed>().is_some() {
        return true;
    }
    match error.downcast_ref::<proto::ApiError>() {
        Some(error) => error.status == 409,
        None => false,
    }
}

fn data_ended() -> anyhow::Error {
    anyhow::Error::new(StreamClosed {
        code: None,
        reason: String::new(),
    })
}

fn stream_lost(error: anyhow::Error) -> anyhow::Error {
    match error.downcast::<StreamClosed>() {
        Ok(closed) => anyhow::Error::new(closed),
        Err(error) => anyhow::Error::new(StreamClosed {
            code: None,
            reason: error.to_string(),
        }),
    }
}

async fn detach(ctrl: &mut Control, attached: &Attached) {
    let _ = ctrl
        .call("session.detach", json!({"session_id": attached.session_id}))
        .await;
}

fn start_ticket(
    ctrl: &mut Control,
    session_id: &str,
    block_id: &str,
) -> Result<tokio::sync::oneshot::Receiver<Result<Value>>> {
    ctrl.start_call(
        "data.connect",
        json!({
            "session_id": session_id,
            "block_id": block_id,
            "data_ref_id": DATA_REF,
            "subprotocol": data::SUBPROTOCOL,
        }),
    )
}

fn parse_ticket(reply: &Value) -> Result<String> {
    reply
        .get("ticket")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("data.connect returned no ticket"))
}

async fn ticket(ctrl: &mut Control, session_id: &str, block_id: &str) -> Result<String> {
    parse_ticket(&finish_call(start_ticket(ctrl, session_id, block_id)?).await?)
}

fn closed_block(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<StreamClosed>()
        .is_some_and(StreamClosed::is_block_closed)
}

struct Screen {
    stdout: std::io::Stdout,
    entered: bool,
}

impl Screen {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        // Clear any leftover OSC 4/10/11/12 overrides before probing the host
        // terminal's theme.
        stdout.write_all(RESET_COLORS)?;
        stdout.flush()?;
        Ok(Self {
            stdout,
            entered: true,
        })
    }

    fn probe_theme(&mut self) -> Theme {
        if self.stdout.write_all(theme_query().as_bytes()).is_err() || self.stdout.flush().is_err()
        {
            return Theme::default();
        }

        let stdin = std::io::stdin();
        let fd = stdin.as_raw_fd();
        let deadline = Instant::now() + THEME_PROBE_TIMEOUT;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];

        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            let timeout_ms = (remaining.as_millis() as i32).max(1);
            let mut pfd = libc_pollfd {
                fd,
                events: POLLIN,
                revents: 0,
            };
            let ready = unsafe { poll(&mut pfd, 1, timeout_ms) };
            if ready <= 0 {
                break;
            }
            let Ok(n) = (&stdin).read(&mut chunk) else {
                break;
            };
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if has_da1_reply(&buf) {
                break;
            }
        }
        let _ = self
            .stdout
            .write_all(WATCH_SCHEME)
            .and_then(|()| self.stdout.flush());
        parse_theme_reply(&buf)
    }

    fn out(&mut self) -> &mut std::io::Stdout {
        &mut self.stdout
    }

    fn leave(&mut self) -> Result<()> {
        if !self.entered {
            return Ok(());
        }
        self.entered = false;
        self.stdout.write_all(RESET_MODES)?;
        self.stdout.flush()?;
        disable_raw_mode()?;
        Ok(())
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = self.leave();
    }
}

const POLLIN: i16 = 0x0001;

#[repr(C)]
struct libc_pollfd {
    fd: i32,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn poll(fds: *mut libc_pollfd, nfds: usize, timeout: i32) -> i32;
}

fn has_da1_reply(bytes: &[u8]) -> bool {
    for (i, &b) in bytes.iter().enumerate() {
        if b == 0x1b
            && bytes.get(i + 1) == Some(&b'[')
            && bytes.get(i + 2) == Some(&b'?')
            && let Some(end) = bytes[i + 3..]
                .iter()
                .position(|&c| !c.is_ascii_digit() && c != b';')
            && bytes[i + 3 + end] == b'c'
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{
        Attached, Ending, Flow, RETRY_FIRST, RETRY_MAX, Theme, backoff, closed_block, detach,
        has_da1_reply, is_detach, parse_theme_reply, reports_scheme, split_replies, take_utf8,
        theme_query,
    };
    use crate::rex::control::Control;
    use crate::rex::data::StreamClosed;
    use base64::Engine as _;
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    fn snapshot_header() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"GHOSTSNP\x01\x00");
        buf.extend_from_slice(&6u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    }

    #[test]
    fn recognizes_detach_key_in_legacy_kitty_and_xterm_modes() {
        assert!(is_detach(b"\x1c"));
        assert!(is_detach(b"\x1b[92;5u"));
        assert!(is_detach(b"\x1b[92;5:1u"));
        assert!(is_detach(b"\x1b[92;5:2u"));
        assert!(is_detach(b"\x1b[92:124;5u"));
        assert!(is_detach(b"\x1b[92:124;5:1u"));
        assert!(is_detach(b"\x1b[27;5;92~"));

        assert!(!is_detach(b"\\"));
        assert!(!is_detach(b"\x1b[92;1u"));
        assert!(!is_detach(b"hello"));
    }

    #[test]
    fn parses_osc_theme_replies_and_detects_light_or_dark_scheme() {
        let reply = concat!(
            "\x1b]10;rgb:1111/2222/3333\x1b\\",
            "\x1b]11;rgb:f8f8/f9f9/fafa\x07",
            "\x1b]12;rgb:00/55/ff\x07",
            "\x1b]4;0;rgb:0000/0000/0000\x1b\\",
            "\x1b]4;1;rgb:a6a6/0000/0000\x07",
            "\x1b[?62;22c",
        )
        .as_bytes();
        assert!(has_da1_reply(reply));
        let theme = parse_theme_reply(reply);
        assert_eq!(theme.foreground.as_deref(), Some("#112233"));
        assert_eq!(theme.background.as_deref(), Some("#f8f9fa"));
        assert_eq!(theme.cursor.as_deref(), Some("#0055ff"));
        assert_eq!(theme.scheme.as_deref(), Some("light"));
        assert_eq!(theme.palette, vec!["0=#000000", "1=#a60000"]);
    }

    #[test]
    fn separates_host_query_replies_from_typed_input() {
        let mixed = concat!(
            "abc",
            "\x1b]4;232;rgb:0808/0808/0808\x07",
            "\x1b]11;rgb:ffff/ffff/ffff\x1b\\",
            "\x1b[?997;2n",
            "\x1b[?62;22c",
            "\x1b[>1;10;0c",
            "def\x1b[A",
        )
        .as_bytes();
        let (replies, typed) = split_replies(mixed);
        assert_eq!(typed, b"abcdef\x1b[A");
        assert_eq!(
            replies,
            concat!(
                "\x1b]4;232;rgb:0808/0808/0808\x07",
                "\x1b]11;rgb:ffff/ffff/ffff\x1b\\",
                "\x1b[?997;2n",
                "\x1b[?62;22c",
                "\x1b[>1;10;0c",
            )
            .as_bytes()
        );
    }

    #[test]
    fn spots_color_scheme_reports_from_the_host() {
        let (replies, typed) = split_replies(b"\x1b[?997;2n");
        assert!(reports_scheme(&replies));
        assert!(typed.is_empty());

        let (replies, _) = split_replies(b"\x1b]11;rgb:0000/0000/0000\x07");
        assert!(!reports_scheme(&replies));
    }

    #[test]
    fn asks_the_host_for_its_whole_palette_and_a_da1_sentinel() {
        let query = theme_query();
        assert!(query.starts_with("\x1b]10;?\x07\x1b]11;?\x07\x1b]12;?\x07"));
        assert!(query.contains("\x1b]4;0;?\x07"));
        assert!(query.contains("\x1b]4;255;?\x07"));
        assert!(!query.contains("\x1b]4;256;?\x07"));
        assert!(query.ends_with("\x1b[c"));
    }

    #[test]
    fn buffers_incomplete_utf8_until_remaining_bytes_arrive() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"hi \xF0\x9F");
        assert_eq!(take_utf8(&mut buf), "hi ");
        assert_eq!(buf, b"\xF0\x9F");

        buf.extend_from_slice(b"\xA6\x80!");
        assert_eq!(take_utf8(&mut buf), "🦀!");
        assert!(buf.is_empty());
    }

    #[test]
    fn waits_longer_between_reconnect_tries_but_not_forever() {
        let mut delay = RETRY_FIRST;
        let mut waits = Vec::new();
        while delay < RETRY_MAX {
            waits.push(delay.as_millis());
            delay = backoff(delay);
        }
        assert_eq!(waits, vec![250, 500, 1000, 2000, 4000]);
        assert_eq!(delay, Duration::from_secs(5));
        assert_eq!(backoff(delay), Duration::from_secs(5));
    }

    #[test]
    fn detects_closed_block_stream_error() {
        let err_4000 = anyhow::Error::new(StreamClosed {
            code: Some(4000),
            reason: String::new(),
        });
        assert!(closed_block(&err_4000));

        let err_reason = anyhow::Error::new(StreamClosed {
            code: Some(1000),
            reason: "block closed".to_owned(),
        });
        assert!(closed_block(&err_reason));

        let err_other = anyhow::Error::new(StreamClosed {
            code: Some(1001),
            reason: "keepalive timeout".to_owned(),
        });
        assert!(!closed_block(&err_other));
    }

    #[tokio::test]
    async fn attaches_primes_stream_and_passes_through_io_and_events() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (ctrl_tcp, _) = listener.accept().await.unwrap();
            let mut ctrl_ws = tokio_tungstenite::accept_hdr_async(
                ctrl_tcp,
                |req: &Request, mut res: Response| {
                    if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                        res.headers_mut()
                            .insert("Sec-WebSocket-Protocol", proto.clone());
                    }
                    Ok(res)
                },
            )
            .await
            .unwrap();

            let _hello = ctrl_ws.next().await.unwrap().unwrap();
            ctrl_ws
                .send(Message::Text(
                    json!({
                        "type": "welcome",
                        "api_revision": 8,
                        "client": {"reconnect_token": "tok-1"}
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .unwrap();

            let data_task = tokio::spawn(async move {
                let (data_tcp, _) = listener.accept().await.unwrap();
                let mut data_ws = tokio_tungstenite::accept_hdr_async(
                    data_tcp,
                    |req: &Request, mut res: Response| {
                        if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                            res.headers_mut()
                                .insert("Sec-WebSocket-Protocol", proto.clone());
                        }
                        Ok(res)
                    },
                )
                .await
                .unwrap();
                let _hello = data_ws.next().await.unwrap().unwrap();
                let mut welcome = vec![0u8; 32];
                welcome[0] = 0x81;
                welcome[1..17].copy_from_slice(&[9u8; 16]);
                welcome[24..32].copy_from_slice(&42u64.to_le_bytes());
                data_ws.send(Message::Binary(welcome.into())).await.unwrap();
                data_ws
            });

            let mut wrote = String::new();
            let mut saw_set_theme = false;
            let mut theme_calls = 0;
            let mut take_calls = 0;
            while let Some(Ok(Message::Text(text))) = ctrl_ws.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap_or("");
                let method = req["method"].as_str().unwrap();
                if method == "com.superlogical.terminal.write" {
                    wrote.push_str(req["payload"]["args"]["data"].as_str().unwrap_or(""));
                    continue;
                }
                if method == "block.event" {
                    continue;
                }
                let result = match method {
                    "session.bootstrap" => json!({
                        "client_id": "client:1",
                        "selected_session": {
                            "view": {
                                "label": "work",
                                "active_window_id": "window:1",
                                "windows": [{
                                    "window_id": "window:1",
                                    "focused_block_id": "block:1",
                                    "active_layer_id": "layer:1",
                                    "layers": [{
                                        "id": "layer:1",
                                        "focused_block_id": "block:1",
                                        "root": {"type": "block", "block_id": "block:1"}
                                    }]
                                }]
                            }
                        }
                    }),
                    "com.superlogical.terminal.set_theme" => {
                        assert_eq!(req["payload"]["args"]["scheme"], "light");
                        saw_set_theme = true;
                        theme_calls += 1;
                        json!({})
                    }
                    "session.own_block" => {
                        take_calls += 1;
                        json!({})
                    }
                    "com.superlogical.terminal.resize" => json!({}),
                    "data.connect" => json!({
                        "ticket": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16])
                    }),
                    "com.superlogical.terminal.format" => {
                        assert_ne!(req["payload"]["args"]["extra_palette"], json!(true));
                        json!({"content": "primed-", "id": 7})
                    }
                    "com.superlogical.terminal.blob_read" => {
                        json!({"data": "screen ", "eof": true})
                    }
                    _ => json!({}),
                };
                ctrl_ws
                    .send(Message::Text(
                        json!({
                            "type": "response",
                            "id": id,
                            "payload": result
                        })
                        .to_string()
                        .into(),
                    ))
                    .await
                    .unwrap();
                if method == "session.detach" {
                    break;
                }
            }
            assert!(saw_set_theme);
            let _data_ws = data_task.await.unwrap();
            (wrote, theme_calls, take_calls)
        });

        let (mut ctrl, _events) = Control::connect(&format!("http://{addr}"), None)
            .await
            .unwrap();
        let theme = Theme {
            foreground: Some("#000000".to_owned()),
            background: Some("#ffffff".to_owned()),
            cursor: None,
            palette: Vec::new(),
            scheme: Some("light".to_owned()),
        };
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &format!("http://{addr}"),
            None,
            None,
            (40, 10),
            theme,
        )
        .await
        .unwrap();
        assert_eq!(attached.block_id, "block:1");
        assert!(!attached.primed);

        let mut stream_bytes = snapshot_header();
        stream_bytes.extend_from_slice(b"stale");
        attached.feed(&stream_bytes, &mut ctrl).await.unwrap();
        assert!(attached.primed);

        let live = b"live!\x1b_rex1;42;{\"type\":\"resize\",\"cols\":50,\"rows\":12}\x1b\\";
        attached.feed(live, &mut ctrl).await.unwrap();

        let mut out = Vec::new();
        attached.flush(&mut out).unwrap();
        assert_eq!(out, b"\x1b[2J\x1b[Hprimed-screen live!");

        let other = attached
            .event(
                "session_destroyed",
                &json!({"session_id": "session:other"}),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(other.is_none());

        attached
            .event(
                "block_event",
                &json!({
                    "session_id": "session:1",
                    "block_id": "block:1",
                    "name": "clipboard_written",
                    "payload": {"text": "copied"}
                }),
                &mut ctrl,
            )
            .await
            .unwrap();
        let mut clip_out = Vec::new();
        attached.flush(&mut clip_out).unwrap();
        assert_eq!(clip_out, b"\x1b]52;c;Y29waWVk\x07");

        // The host reported a scheme change: zrex asks it for the colors again
        // and hands the new theme to the block.
        let (host_tx, mut host_rx) = tokio::sync::mpsc::unbounded_channel();
        host_tx
            .send(
                b"\x1b]10;rgb:1111/1111/1111\x07\x1b]11;rgb:eeee/eeee/eeee\x07\x1b[?62;22c"
                    .to_vec(),
            )
            .unwrap();
        let mut host_out = Vec::new();
        let flow = attached
            .refresh_theme(&mut host_out, &mut host_rx, &mut ctrl)
            .await
            .unwrap();
        assert!(matches!(flow, Flow::Continue));
        assert!(host_out.starts_with(b"\x1b]10;?\x07"));
        assert_eq!(attached.theme.background.as_deref(), Some("#eeeeee"));
        assert_eq!(attached.theme.scheme.as_deref(), Some("light"));

        // Another client took the block. The block keeps that client's size
        // and colors until this one is claimed back, so zrex claims nothing.
        let owner = attached
            .event(
                "block_owner_changed",
                &json!({
                    "session_id": "session:1",
                    "block_id": "block:1",
                    "owner": "client:2"
                }),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(owner.is_none());
        assert!(!attached.owns);

        // A scheme change while another client owns the block updates the
        // colors zrex holds, but not the block's.
        let (other_tx, mut other_rx) = tokio::sync::mpsc::unbounded_channel();
        other_tx
            .send(
                b"\x1b]10;rgb:2222/2222/2222\x07\x1b]11;rgb:dddd/dddd/dddd\x07\x1b[?62;22c"
                    .to_vec(),
            )
            .unwrap();
        let mut other_out = Vec::new();
        let flow = attached
            .refresh_theme(&mut other_out, &mut other_rx, &mut ctrl)
            .await
            .unwrap();
        assert!(matches!(flow, Flow::Continue));
        assert_eq!(attached.theme.background.as_deref(), Some("#dddddd"));

        // Typing in the terminal claims the block back, with this terminal's
        // size and colors.
        let (in_tx, mut in_rx) = tokio::sync::mpsc::unbounded_channel();
        in_tx.send(b" -l".to_vec()).unwrap();
        in_tx.send(b"a\n".to_vec()).unwrap();
        let flow = attached.burst(b"ls", &mut in_rx, &mut ctrl).await.unwrap();
        assert!(matches!(flow, Flow::Continue));
        assert!(attached.owns);

        // The other client gives the block up, so the server hands it to the
        // client in line: this one. It takes this terminal's size and colors
        // again without claiming anything.
        attached
            .event(
                "block_owner_changed",
                &json!({
                    "session_id": "session:1",
                    "block_id": "block:1",
                    "owner": "client:2"
                }),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(!attached.owns);
        attached
            .event(
                "block_owner_changed",
                &json!({
                    "session_id": "session:1",
                    "block_id": "block:1",
                    "owner": "client:1"
                }),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(attached.owns);

        let detach_flow = attached
            .burst(b"\x1c", &mut in_rx, &mut ctrl)
            .await
            .unwrap();
        assert!(matches!(detach_flow, Flow::Detach));

        let block_end = attached
            .event(
                "block_closed",
                &json!({"session_id": "session:1", "block_id": "block:1"}),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(matches!(block_end, Some(Ending::Block)));

        let session_end = attached
            .event(
                "session_destroyed",
                &json!({"session_id": "session:1"}),
                &mut ctrl,
            )
            .await
            .unwrap();
        assert!(matches!(session_end, Some(Ending::Session)));

        detach(&mut ctrl, &attached).await;
        let (wrote, theme_calls, take_calls) = server.await.unwrap();
        assert_eq!(wrote, "ls -la\n");
        // Attach, a scheme change while owning, the claim on typing, and the
        // block coming back from the other client.
        assert_eq!(theme_calls, 4);
        // Attach and the claim on typing; the other client's claim does not
        // make zrex claim back.
        assert_eq!(take_calls, 2);
    }
}

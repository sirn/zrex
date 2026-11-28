use std::collections::VecDeque;
use std::future::Future;
use std::io::{IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use serde_json::{Value, json};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

use crate::config::{DetachKey, ServerConfig};
use crate::rex::control::{CALL_TIME, CallTimeout, Control, Events};
use crate::rex::data::{self, Data, StreamClosed};
use crate::rex::proto;
use crate::rex::stream::{self, Filter};
use crate::rex::{BlockRef, CONNECT_TIME, ServerAddress, format_timeout};
use crate::session;

const DATA_REF: &str = "terminal";
const MAX_BLOB_BYTES: usize = 983_040;
/// Cap total reassembled blob/clipboard size so a misbehaving server cannot
/// cause unbounded memory growth.
const MAX_TOTAL_BLOB_BYTES: usize = 16 * 1024 * 1024;
const BLOB_READ_TIME: Duration = CALL_TIME;
/// Cap each `com.superlogical.terminal.write` request so huge pastes stay well
/// within WebSocket frame limits while normal input goes out in one call.
const MAX_WRITE_BYTES: usize = 64 * 1024;
const PROBE_EVERY: Duration = Duration::from_secs(10);
const PROBE_TIME: Duration = Duration::from_secs(5);
const DETACH_TIME: Duration = Duration::from_secs(1);
const RETRY_FIRST: Duration = Duration::from_millis(250);
const RETRY_MAX: Duration = Duration::from_secs(5);
const THEME_PROBE_IDLE: Duration = Duration::from_millis(200);
const THEME_PROBE_MAX: Duration = Duration::from_millis(2000);
const DETACH_DRAIN_IDLE: Duration = Duration::from_millis(150);
const DETACH_DRAIN_MAX: Duration = Duration::from_millis(400);
const TITLE_QUERY_TIMEOUT: Duration = Duration::from_millis(250);
/// DSR Device Status Report (`CSI 5 n` -> `CSI 0 n`). Sent after `RESET_MODES`
/// on detach so any in-flight host replies (such as delayed OSC 4/10/11/12 or
/// DA1 responses over SSH) are drained in raw mode before restoring the shell.
/// Using DSR 5 instead of DA1 prevents an in-flight probe DA1 from falsely
/// ending the drain early.
const DSR_STATUS_QUERY: &[u8] = b"\x1b[5n";
const DSR_STATUS_REPLY: &[u8] = b"\x1b[0n";
/// An unterminated local reply grows no larger than this before zrex stops
/// holding it and forwards the bytes as input. The longest reply a terminal
/// sends is a 256-color palette entry at 29 bytes.
const MAX_HELD_REPLY: usize = 64;
/// A terminal answers a query in one burst, so a bare opener held this long
/// was typing after all, and a reply this old is no longer a sign that more
/// are coming.
const REPLY_HOLD: Duration = Duration::from_millis(50);
/// Definite partial host replies (such as a split `OSC 4` color entry) are
/// never user typing; hold them longer so slow terminals or buffered PTYs can
/// finish the sequence cleanly, and drop them rather than injecting garbage if
/// the host never completes the reply.
const REPLY_FRAGMENT_HOLD: Duration = Duration::from_secs(2);
/// DECSET 2031 asks the host terminal to report light and dark switches, which
/// the block's theme follows while attached.
const WATCH_SCHEME: &[u8] = b"\x1b[?2031h";

const RESET_COLORS: &[u8] =
    b"\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\\x1b]104\x07\x1b]110\x07\x1b]111\x07\x1b]112\x07";

/// Restore host terminal state on exit in case a program inside the block
/// enabled alternate screen, mouse tracking, Kitty keyboard, color-scheme
/// reporting, in-band resize reporting, or custom palette colors.
///
/// Begins with CAN (`0x18`) to abort any partial escape/OSC/DCS sequence, and
/// resets Kitty keyboard (`<99u` + `=0u`) and `modifyOtherKeys` both before
/// and after leaving the alternate screen because terminals like `foot`,
/// Kitty, and Ghostty maintain separate keyboard stacks per screen buffer.
const RESET_MODES: &[u8] = concat!(
    "\x18",
    "\x1b[?2026l",
    "\x1b[<99u\x1b[=0u",
    "\x1b[>4;0m\x1b[>4m",
    "\x1b[?9l\x1b[?1000l\x1b[?1001l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1016l",
    "\x1b[?1004l",
    "\x1b[?2004l",
    "\x1b[?2031l",
    "\x1b[?2048l",
    "\x1b[?1l\x1b>",
    "\x1b[?6l\x1b[?7h\x1b[4l",
    "\x1b[?1049l\x1b[?1047l\x1b[?47l",
    "\x1b[<99u\x1b[=0u",
    "\x1b[>4;0m\x1b[>4m",
    "\x1b[r",
    "\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\",
    "\x1b]104\x07\x1b]110\x07\x1b]111\x07\x1b]112\x07",
    "\x1b[23;0t",
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachExit {
    Detached {
        session_id: String,
        block_id: String,
        /// True when a second detach sequence was already read right behind the
        /// first detach sequence (fast double-detach).
        double_detach: bool,
    },
    /// User cancelled before the block was fully attached (e.g. while
    /// connecting to a slow or unreachable server).
    Cancelled {
        /// True when the user pressed `Ctrl-C` or double-detached.
        quit: bool,
    },
    BlockClosed,
    SessionClosed,
}

impl AttachExit {
    pub fn closed_message(&self) -> Option<&'static str> {
        match self {
            Self::BlockClosed => Some("the block closed"),
            Self::SessionClosed => Some("the session closed"),
            Self::Detached { .. } | Self::Cancelled { .. } => None,
        }
    }

    fn cli_message(&self) -> String {
        match self {
            Self::Detached { session_id, .. } => format!("detached from {session_id}"),
            Self::Cancelled { .. } => "cancelled".to_owned(),
            other => other.closed_message().unwrap_or_default().to_owned(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TerminalMode {
    RestoreOnLeave,
    KeepRawOnLeave,
}

pub async fn attach(
    server_config: &ServerConfig,
    target: Option<String>,
    window: Option<String>,
    block: Option<String>,
    detach_key: DetachKey,
) -> Result<()> {
    ensure_terminal()?;
    let (server, mut ctrl, events) = server_config.connect().await?;
    let session_id = match target.as_deref() {
        Some(target) => session::find_or_create(&mut ctrl, target).await?,
        None => session::pick(&mut ctrl, None).await?,
    };
    let (window, block) = match window.as_deref() {
        Some(selector) => {
            session::attach(&mut ctrl, &session_id).await?;
            let (win_id, blk) =
                session::ensure_window(&mut ctrl, &session_id, selector, block.as_deref()).await?;
            (Some(win_id), blk)
        }
        None => (None, block),
    };
    let exit = attach_block(
        &server,
        ctrl,
        events,
        &session_id,
        BlockSelection::Selectors(window.as_deref(), block.as_deref()),
        TerminalMode::RestoreOnLeave,
        detach_key,
    )
    .await?;
    println!("{}", exit.cli_message());
    Ok(())
}

/// Runs a pre-attach network step while listening for the detach key or `Ctrl-C`
/// so connecting to a dead/rebooting server while raw mode is active never freezes.
async fn run_pre_attach<T>(
    detach_key: DetachKey,
    future: impl Future<Output = Result<T>>,
) -> Result<std::result::Result<T, AttachExit>> {
    let mut input = InputReader::spawn()?;
    let outcome = input.await_or_cancel(detach_key, future).await;
    let extra_detach = input.stop_and_drain_detach(detach_key);
    match outcome {
        PreAttachOutcome::Done(result) => Ok(Ok(result?)),
        PreAttachOutcome::Cancelled { quit } => Ok(Err(AttachExit::Cancelled {
            quit: quit || extra_detach,
        })),
    }
}

/// Picker targets are a snapshot of existing IDs, never creation selectors.
pub async fn attach_existing(
    server: &ServerAddress,
    session_id: &str,
    block_id: &str,
    detach_key: DetachKey,
) -> Result<AttachExit> {
    ensure_terminal()?;
    let (ctrl, events) = match run_pre_attach(detach_key, async {
        let (mut ctrl, events) = Control::connect(server, None).await?;
        session::attach(&mut ctrl, session_id).await?;
        Ok((ctrl, events))
    })
    .await?
    {
        Ok(pair) => pair,
        Err(exit) => return Ok(exit),
    };
    attach_block(
        server,
        ctrl,
        events,
        session_id,
        BlockSelection::Exact(block_id),
        TerminalMode::KeepRawOnLeave,
        detach_key,
    )
    .await
}

pub async fn attach_new_session(
    server: &ServerAddress,
    label: Option<&str>,
    detach_key: DetachKey,
) -> Result<AttachExit> {
    ensure_terminal()?;
    let (ctrl, events, session_id) = match run_pre_attach(detach_key, async {
        let (mut ctrl, events) = Control::connect(server, None).await?;
        let session_id = session::create(&mut ctrl, label).await?;
        Ok((ctrl, events, session_id))
    })
    .await?
    {
        Ok(triple) => triple,
        Err(exit) => return Ok(exit),
    };
    attach_block(
        server,
        ctrl,
        events,
        &session_id,
        BlockSelection::Selectors(None, None),
        TerminalMode::KeepRawOnLeave,
        detach_key,
    )
    .await
}

pub async fn attach_new_window(
    server: &ServerAddress,
    session_id: &str,
    label: Option<&str>,
    detach_key: DetachKey,
) -> Result<AttachExit> {
    ensure_terminal()?;
    let (ctrl, events, window_id) = match run_pre_attach(detach_key, async {
        let (mut ctrl, events) = Control::connect(server, None).await?;
        session::attach(&mut ctrl, session_id).await?;
        let window_id = session::new_window(&mut ctrl, session_id, label).await?;
        Ok((ctrl, events, window_id))
    })
    .await?
    {
        Ok(triple) => triple,
        Err(exit) => return Ok(exit),
    };
    attach_block(
        server,
        ctrl,
        events,
        session_id,
        BlockSelection::Selectors(Some(&window_id), None),
        TerminalMode::KeepRawOnLeave,
        detach_key,
    )
    .await
}

#[derive(Clone, Copy)]
enum BlockSelection<'a> {
    Selectors(Option<&'a str>, Option<&'a str>),
    Exact(&'a str),
}

async fn attach_block(
    server: &ServerAddress,
    mut ctrl: Control,
    mut events: Events,
    session_id: &str,
    selection: BlockSelection<'_>,
    terminal_mode: TerminalMode,
    detach_key: DetachKey,
) -> Result<AttachExit> {
    let size = crossterm::terminal::size()?;
    let mut guard = Screen::enter(terminal_mode)?;
    let probed = guard.probe_theme();
    let mut input = InputReader::spawn()?;
    let mut attached = match input
        .await_or_cancel(
            detach_key,
            Attached::start(&mut ctrl, session_id, server, selection, size, probed.theme),
        )
        .await
    {
        PreAttachOutcome::Done(Ok(attached)) => attached,
        PreAttachOutcome::Done(Err(error)) => {
            input.stop();
            let _ = guard.leave_and_drain(detach_key, probed.replied);
            return Err(error);
        }
        PreAttachOutcome::Cancelled { mut quit } => {
            quit |= input.stop_and_drain_detach(detach_key);
            quit |= guard.leave_and_drain(detach_key, probed.replied)?;
            return Ok(AttachExit::Cancelled { quit });
        }
    };
    attached.detach_key = detach_key;
    attached.host_replied = probed.replied;
    // Replies the probe cut off (or any delayed scheme report after
    // WATCH_SCHEME) can arrive after probe_theme returns, so the reader that
    // takes over stdin starts out holding any unfinished tail and expecting
    // split host replies.
    attached.replies.hold_probe(probed.tail, !probed.da1_seen);

    let mut winch = signal(SignalKind::window_change())?;
    let mut probe = tokio::time::interval(PROBE_EVERY);
    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    probe.reset();
    let mut probe_inflight: Option<InflightCall> = None;
    let mut token = ctrl.reconnect_token.clone();

    loop {
        let mut lost: Option<anyhow::Error> = None;
        tokio::select! {
            chunk = attached.data.next_chunk() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        match input
                            .await_or_detach(detach_key, false, attached.feed(&bytes, &mut ctrl))
                            .await
                        {
                            Interruptible::Detach { double } => {
                                return finish_detach(
                                    &mut ctrl,
                                    &mut input,
                                    &mut guard,
                                    attached,
                                    double,
                                    DetachMode::Immediate,
                                )
                                .await;
                            }
                            Interruptible::Done(Err(error)) => lost = Some(error),
                            Interruptible::Done(Ok(())) => {
                                while let Some(next) = attached.data.try_next_chunk() {
                                    match next {
                                        Ok(more) => {
                                            match input
                                                .await_or_detach(
                                                    detach_key,
                                                    false,
                                                    attached.feed(&more, &mut ctrl),
                                                )
                                                .await
                                            {
                                                Interruptible::Detach { double } => {
                                                    return finish_detach(
                                                        &mut ctrl,
                                                        &mut input,
                                                        &mut guard,
                                                        attached,
                                                        double,
                                                        DetachMode::Immediate,
                                                    )
                                                    .await;
                                                }
                                                Interruptible::Done(Err(error)) => {
                                                    lost = Some(error);
                                                    break;
                                                }
                                                Interruptible::Done(Ok(())) => {}
                                            }
                                        }
                                        Err(error) if closed_block(&error) => {
                                            attached.flush(guard.out())?;
                                            return finish_ending(
                                                &mut input,
                                                &mut guard,
                                                attached.detach_key,
                                                attached.host_replied,
                                                Ending::Block,
                                            );
                                        }
                                        Err(error) => {
                                            lost = Some(stream_lost(error));
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some(Err(error)) if closed_block(&error) => {
                        return finish_ending(
                            &mut input,
                            &mut guard,
                            attached.detach_key,
                            attached.host_replied,
                            Ending::Block,
                        );
                    }
                    Some(Err(error)) => lost = Some(stream_lost(error)),
                    None => lost = Some(data_ended()),
                }
            }
            message = events.recv() => {
                match message {
                    Some((name, payload)) => {
                        match input
                            .await_or_detach(
                                detach_key,
                                false,
                                attached.event(&name, &payload, &mut ctrl),
                            )
                            .await
                        {
                            Interruptible::Detach { double } => {
                                return finish_detach(
                                    &mut ctrl,
                                    &mut input,
                                    &mut guard,
                                    attached,
                                    double,
                                    DetachMode::Immediate,
                                )
                                .await;
                            }
                            Interruptible::Done(Ok(Some(ending))) => {
                                return finish_ending(
                                    &mut input,
                                    &mut guard,
                                    attached.detach_key,
                                    attached.host_replied,
                                    ending,
                                );
                            }
                            Interruptible::Done(Ok(None)) => {}
                            Interruptible::Done(Err(error)) => lost = Some(error),
                        }
                    }
                    None => lost = Some(anyhow!("the control connection ended")),
                }
            }
            Some(bytes) = input.recv() => {
                match attached.burst(&bytes, &mut input, &mut ctrl).await {
                    Ok(Flow::Detach { double }) => {
                        return finish_detach(
                            &mut ctrl,
                            &mut input,
                            &mut guard,
                            attached,
                            double,
                            DetachMode::Graceful,
                        )
                        .await;
                    }
                    Ok(Flow::Continue) => {}
                    Err(error) => lost = Some(error),
                }
            }
            // Rex runs `com.superlogical.terminal.write` calls concurrently, so
            // wait for each write to be queued on the server before sending the
            // next coalesced batch.
            result = finish_write(&mut attached.write_inflight) => {
                match result {
                    Ok(_) => {
                        if let Err(error) = attached.pump_write(&mut ctrl) {
                            lost = Some(error);
                        }
                    }
                    Err(error) if write_target_gone(&error) => {
                        // The block or session already closed on the server;
                        // wait for the close event or data stream end instead
                        // of failing the attach loop with an error.
                        attached.write_queue.clear();
                    }
                    Err(error) => lost = Some(error),
                }
            }
            // Non-blocking liveness probe reply so a black-holed connection
            // never blocks detach or user input.
            result = finish_inflight(&mut probe_inflight) => {
                if let Err(error) = result {
                    lost = Some(error);
                }
            }
            // A fragment the host stopped sending was typing after all.
            _ = stalled(attached.replies.due()) => {
                // Another arm can hold the loop long enough for the host's
                // continuation to queue up behind it, so take that first.
                if input.is_empty() {
                    match attached.flush_held(&mut input, &mut ctrl).await {
                        Ok(Flow::Continue) => {}
                        Ok(Flow::Detach { double }) => {
                            return finish_detach(
                                &mut ctrl,
                                &mut input,
                                &mut guard,
                                attached,
                                double,
                                DetachMode::Immediate,
                            )
                            .await;
                        }
                        Err(error) => lost = Some(error),
                    }
                } else {
                    attached.replies.defer();
                }
            }
            _ = winch.recv() => {
                if let Ok((cols, rows)) = crossterm::terminal::size() {
                    match input
                        .await_or_detach(detach_key, false, attached.resize(cols, rows, &mut ctrl))
                        .await
                    {
                        Interruptible::Detach { double } => {
                            return finish_detach(
                                &mut ctrl,
                                &mut input,
                                &mut guard,
                                attached,
                                double,
                                DetachMode::Immediate,
                            )
                            .await;
                        }
                        Interruptible::Done(Err(error)) => lost = Some(error),
                        Interruptible::Done(Ok(())) => {}
                    }
                }
            }
            _ = probe.tick() => {
                // A socket reports a dead network only when something uses
                // it, so use it — without blocking the event loop while waiting
                // for the reply.
                if probe_inflight.is_none() {
                    match ctrl.start_call("server.version", Value::Null) {
                        Ok(rx) => {
                            probe_inflight = Some(InflightCall {
                                method: "server.version",
                                timeout: PROBE_TIME,
                                rx,
                                deadline: tokio::time::Instant::now() + PROBE_TIME,
                            });
                        }
                        Err(error) => lost = Some(error),
                    }
                }
            }
        }

        if lost.is_none() && attached.theme_dirty {
            match attached
                .refresh_theme(guard.out(), &mut input, &mut ctrl)
                .await
            {
                Ok(Flow::Continue) => {}
                Ok(Flow::Detach { double }) => {
                    return finish_detach(
                        &mut ctrl,
                        &mut input,
                        &mut guard,
                        attached,
                        double,
                        DetachMode::Graceful,
                    )
                    .await;
                }
                Err(error) => lost = Some(error),
            }
        }

        if let Some(error) = lost {
            if !transient(&ctrl, &error) {
                return Err(error);
            }
            probe_inflight = None;
            write_reconnecting_title(guard.out(), detach_key)?;
            match recover(
                &mut token,
                &mut ctrl,
                &mut events,
                &mut attached,
                &mut input,
            )
            .await?
            {
                Recovered::Live => {
                    probe.reset();
                    if attached.primed {
                        let title = attached
                            .last_title
                            .as_deref()
                            .or(attached.fallback_title.as_deref())
                            .unwrap_or("");
                        attached
                            .out
                            .extend_from_slice(&stream::format_osc_title(b'0', title, b"\x07"));
                    }
                }
                Recovered::Detach { double } => {
                    return finish_detach(
                        &mut ctrl,
                        &mut input,
                        &mut guard,
                        attached,
                        double,
                        DetachMode::Immediate,
                    )
                    .await;
                }
                Recovered::Ended(ending) => {
                    return finish_ending(
                        &mut input,
                        &mut guard,
                        attached.detach_key,
                        attached.host_replied,
                        ending,
                    );
                }
            }
        }

        attached.flush(guard.out())?;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DetachMode {
    /// Connected: drain queued and in-flight keystrokes before `session.detach`.
    Graceful,
    /// Interrupted during reconnect: skip draining writes and just send `session.detach`.
    Immediate,
}

fn finish_ending(
    input: &mut InputReader,
    guard: &mut Screen,
    detach_key: DetachKey,
    host_replied: bool,
    ending: Ending,
) -> Result<AttachExit> {
    input.stop();
    let _ = guard.leave_and_drain(detach_key, host_replied)?;
    Ok(ending.into_exit())
}

async fn finish_detach(
    ctrl: &mut Control,
    input: &mut InputReader,
    guard: &mut Screen,
    mut attached: Attached<'_>,
    mut double_detach: bool,
    mode: DetachMode,
) -> Result<AttachExit> {
    let detach_key = attached.detach_key;
    double_detach |= input.stop_and_drain_detach(detach_key);
    match mode {
        DetachMode::Graceful => detach(ctrl, &mut attached).await,
        DetachMode::Immediate => {
            if !ctrl.is_lost() {
                let _ = ctrl.post("session.detach", json!({"session_id": attached.session_id}));
            }
        }
    }
    double_detach |= guard.leave_and_drain(detach_key, attached.host_replied)?;
    Ok(AttachExit::Detached {
        session_id: attached.session_id,
        block_id: attached.block_id,
        double_detach,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Continue,
    Detach { double: bool },
}

impl Flow {
    fn detach_after(tail: &[u8], detach_key: DetachKey) -> Self {
        Self::Detach {
            double: contains_detach_for(tail, detach_key),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Ending {
    Block,
    Session,
}

impl Ending {
    fn into_exit(self) -> AttachExit {
        match self {
            Ending::Block => AttachExit::BlockClosed,
            Ending::Session => AttachExit::SessionClosed,
        }
    }
}

struct InflightWrite {
    rx: tokio::sync::oneshot::Receiver<Result<Value>>,
    deadline: tokio::time::Instant,
}

struct InflightCall {
    method: &'static str,
    timeout: Duration,
    rx: tokio::sync::oneshot::Receiver<Result<Value>>,
    deadline: tokio::time::Instant,
}

struct Attached<'a> {
    server: &'a ServerAddress,
    session_id: String,
    block_id: String,
    client_id: String,
    size: (u16, u16),
    theme: Theme,
    fallback_title: Option<String>,
    last_title: Option<String>,
    data: Data,
    filter: Filter,
    pending: Vec<u8>,
    out: Vec<u8>,
    input_buf: Vec<u8>,
    write_queue: String,
    write_inflight: Option<InflightWrite>,
    replies: Replies,
    detach_key: DetachKey,
    host_replied: bool,
    primed: bool,
    theme_dirty: bool,
    owns: bool,
}

impl<'a> Attached<'a> {
    async fn start(
        ctrl: &mut Control,
        session_id: &str,
        server: &'a ServerAddress,
        selection: BlockSelection<'_>,
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
        let block_id = match selection {
            BlockSelection::Exact(id) if session::has_block(&view, id) => id.to_owned(),
            BlockSelection::Exact(id) => bail!("the selected block {id} is no longer available"),
            BlockSelection::Selectors(window, block) => session::block_of(&view, window, block)
                .ok_or_else(|| match (window, block) {
                    (_, Some(blk)) => anyhow!("the window has no block {blk}"),
                    (Some(win), None) => anyhow!("the session has no window {win}"),
                    (None, None) => anyhow!("the session's active window shows no block"),
                })?,
        };
        let fallback_title = session::fallback_title_for(&bootstrap, &view, &block_id);

        let block = BlockRef::new(session_id, &block_id);
        start_take(ctrl, block)?.finish().await?;
        let ticket_call = start_ticket(ctrl, block)?;
        publish(ctrl, block, (cols, rows), &theme, Push::Both).await?;
        let ticket = parse_ticket(&ticket_call.finish().await?)?;
        let data = Data::open(server, &ticket).await?;
        let filter = Filter::new(data.nonce);
        let attached = Self {
            server,
            session_id: session_id.to_owned(),
            block_id,
            client_id,
            size: (cols, rows),
            theme,
            fallback_title,
            last_title: None,
            data,
            filter,
            pending: Vec::new(),
            out: Vec::new(),
            input_buf: Vec::new(),
            write_queue: String::new(),
            write_inflight: None,
            replies: Replies::default(),
            detach_key: DetachKey::default(),
            host_replied: false,
            primed: false,
            theme_dirty: false,
            owns: true,
        };
        attached.focus(ctrl, "in")?;
        Ok(attached)
    }

    fn block(&self) -> BlockRef<'_> {
        BlockRef::new(&self.session_id, &self.block_id)
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
        let block = self.block();
        let title_rx = session::start_terminal_title(ctrl, block);
        let process_rx = session::start_terminal_process(ctrl, block);
        let screen = format_vt(ctrl, block).await?;
        let deadline = tokio::time::Instant::now() + TITLE_QUERY_TIMEOUT;
        let (title_reply, process_reply) = tokio::join!(
            session::optional_reply(title_rx, deadline),
            session::optional_reply(process_rx, deadline),
        );
        let title = session::resolved_terminal_title(
            title_reply.as_ref(),
            process_reply.as_ref(),
            Some(&screen),
        )
        .or_else(|| self.fallback_title.clone());
        self.last_title = title.clone();
        self.out.extend_from_slice(b"\x1b[2J\x1b[H");
        self.out.extend_from_slice(&screen);
        self.out.extend_from_slice(&stream::format_osc_title(
            b'0',
            title.as_deref().unwrap_or(""),
            b"\x07",
        ));
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
        input: &mut InputReader,
        ctrl: &mut Control,
    ) -> Result<Flow> {
        self.flush(out)?;
        self.replies.expect_reply();
        let mut deadline = ProbeDeadline::new(THEME_PROBE_IDLE, THEME_PROBE_MAX);
        let mut replies = Vec::new();
        for batch in theme_query_batches(false) {
            out.write_all(batch.as_bytes())?;
            out.flush()?;
            self.host_replied = true;
            let batch_start = replies.len();
            let mut saw_da1 = false;
            while let Some(remaining) = deadline.remaining() {
                let Ok(Some(bytes)) = tokio::time::timeout(remaining, input.recv()).await else {
                    break;
                };
                deadline.bump();
                let flow = self.queue_input(&bytes, Some(&mut replies));
                self.flush_input(ctrl)?;
                if let Flow::Detach { .. } = flow {
                    return Ok(flow);
                }
                if has_da1_reply(&replies[batch_start..]) {
                    saw_da1 = true;
                    break;
                }
            }
            if !saw_da1 {
                break;
            }
        }
        self.theme_dirty = false;
        let theme = parse_theme_reply(&replies);
        if theme.is_empty() || theme == self.theme {
            return Ok(Flow::Continue);
        }
        self.theme = theme;
        match input
            .await_or_detach(self.detach_key, false, self.sync(ctrl, Push::Theme))
            .await
        {
            Interruptible::Done(res) => {
                res?;
                Ok(Flow::Continue)
            }
            Interruptible::Detach { double } => Ok(Flow::Detach { double }),
        }
    }

    async fn burst(
        &mut self,
        first: &[u8],
        input: &mut InputReader,
        ctrl: &mut Control,
    ) -> Result<Flow> {
        let mut flow = self.queue_input(first, None);
        while flow == Flow::Continue {
            let Some(bytes) = input.try_recv() else {
                break;
            };
            flow = self.queue_input(&bytes, None);
        }
        if let Flow::Detach { mut double } = flow {
            double |= input.drain_detach(self.detach_key);
            self.flush_input(ctrl)?;
            return Ok(Flow::Detach { double });
        }
        let typed = !self.input_buf.is_empty();
        self.flush_input(ctrl)?;
        if typed && !self.owns {
            match input
                .await_or_detach(self.detach_key, false, self.claim(ctrl))
                .await
            {
                Interruptible::Done(res) => res?,
                Interruptible::Detach { double } => return Ok(Flow::Detach { double }),
            }
        }
        Ok(Flow::Continue)
    }

    fn queue_input(&mut self, bytes: &[u8], mut collected_replies: Option<&mut Vec<u8>>) -> Flow {
        match self.detach_key {
            DetachKey::None => {
                let (replies, typed) = self.replies.push(bytes);
                self.record_replies(&replies, collected_replies.as_deref_mut());
                self.input_buf.extend_from_slice(&typed);
                Flow::Continue
            }
            // BEL (`0x07`) also terminates legacy OSC replies, so strip host
            // replies before scanning for `Ctrl-G` detach/pass-through.
            DetachKey::Ctrl(0x07) => {
                let (replies, typed) = self.replies.push(bytes);
                self.record_replies(&replies, collected_replies.as_deref_mut());
                self.consume_key_actions(&typed)
            }
            DetachKey::Ctrl(_) => {
                let mut rest = bytes;
                while let Some((pos, len, action)) = find_next_key_action(rest, self.detach_key) {
                    if pos > 0 {
                        let (replies, typed) = self.replies.push(&rest[..pos]);
                        self.record_replies(&replies, collected_replies.as_deref_mut());
                        if let Flow::Detach { double } = self.consume_key_actions(&typed) {
                            let tail = &rest[pos..];
                            return Flow::Detach {
                                double: double
                                    || matches!(action, KeyAction::Detach)
                                    || contains_detach_for(tail, self.detach_key),
                            };
                        }
                    }
                    let tail = &rest[pos + len..];
                    match action {
                        KeyAction::Detach => return Flow::detach_after(tail, self.detach_key),
                        KeyAction::PassThrough(byte) => {
                            self.input_buf.push(byte);
                            rest = tail;
                        }
                        KeyAction::Ignore => {
                            rest = tail;
                        }
                    }
                }
                if !rest.is_empty() {
                    let (replies, typed) = self.replies.push(rest);
                    self.record_replies(&replies, collected_replies);
                    return self.consume_key_actions(&typed);
                }
                Flow::Continue
            }
        }
    }

    fn record_replies(&mut self, replies: &[u8], collected: Option<&mut Vec<u8>>) {
        if !replies.is_empty() {
            self.host_replied = true;
            if let Some(collected) = collected {
                collected.extend_from_slice(replies);
            }
            if reports_scheme(replies) {
                self.theme_dirty = true;
            }
        }
    }

    /// Scans already-classified typed bytes for detach and pass-through
    /// sequences, appending forwarded bytes to `self.input_buf`.
    fn consume_key_actions(&mut self, mut bytes: &[u8]) -> Flow {
        while let Some((pos, len, action)) = find_next_key_action(bytes, self.detach_key) {
            if pos > 0 {
                self.input_buf.extend_from_slice(&bytes[..pos]);
            }
            let tail = &bytes[pos + len..];
            match action {
                KeyAction::Detach => return Flow::detach_after(tail, self.detach_key),
                KeyAction::PassThrough(byte) => {
                    self.input_buf.push(byte);
                    bytes = tail;
                }
                KeyAction::Ignore => {
                    bytes = tail;
                }
            }
        }
        if !bytes.is_empty() {
            self.input_buf.extend_from_slice(bytes);
        }
        Flow::Continue
    }

    /// Forwards a stalled fragment if it could be user typing, or drops an
    /// unfinished host reply so it never leaks into the remote PTY.
    async fn flush_held(&mut self, input: &mut InputReader, ctrl: &mut Control) -> Result<Flow> {
        let held = self.replies.give_up_stalled();
        if held.is_empty() {
            return Ok(Flow::Continue);
        }
        self.input_buf.extend_from_slice(&held);
        self.flush_input(ctrl)?;
        // Typing this late still makes this client the block's owner.
        if !self.owns {
            match input
                .await_or_detach(self.detach_key, false, self.claim(ctrl))
                .await
            {
                Interruptible::Done(res) => res?,
                Interruptible::Detach { double } => return Ok(Flow::Detach { double }),
            }
        }
        Ok(Flow::Continue)
    }

    fn flush_input(&mut self, ctrl: &mut Control) -> Result<()> {
        let text = take_utf8(&mut self.input_buf);
        if !text.is_empty() {
            self.write_queue.push_str(&text);
        }
        self.pump_write(ctrl)
    }

    fn pump_write(&mut self, ctrl: &mut Control) -> Result<()> {
        if self.write_inflight.is_some() || self.write_queue.is_empty() {
            return Ok(());
        }
        let chunk = take_write_chunk(&mut self.write_queue, MAX_WRITE_BYTES);
        self.write_inflight = Some(InflightWrite {
            rx: ctrl.start_write(self.block(), &chunk)?,
            deadline: tokio::time::Instant::now() + CALL_TIME,
        });
        Ok(())
    }

    async fn drain_writes(&mut self, ctrl: &mut Control, deadline: tokio::time::Instant) -> bool {
        self.input_buf.extend(self.replies.give_up_typed());
        if self.flush_input(ctrl).is_err() {
            return false;
        }
        loop {
            if self.write_inflight.is_some() {
                match tokio::time::timeout_at(deadline, finish_write(&mut self.write_inflight))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) | Err(_) => return false,
                }
            }
            if self.write_queue.is_empty() {
                break;
            }
            if self.pump_write(ctrl).is_err() {
                return false;
            }
        }
        true
    }

    async fn resize(&mut self, cols: u16, rows: u16, ctrl: &mut Control) -> Result<()> {
        if cols == 0 || rows == 0 {
            return Ok(());
        }
        self.size = (cols, rows);
        self.sync(ctrl, Push::Size).await
    }

    async fn claim(&mut self, ctrl: &mut Control) -> Result<()> {
        start_take(ctrl, self.block())?.finish().await?;
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
        publish(ctrl, self.block(), self.size, &self.theme, push).await
    }

    fn focus(&self, ctrl: &mut Control, action: &str) -> Result<()> {
        ctrl.post_event(
            self.block(),
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
                        clipboard(ctrl, self.block(), id).await?
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
        let Some(selected) = bootstrap.get("selected_session") else {
            return Ok(Some(Ending::Session));
        };
        if selected
            .get("session_id")
            .and_then(Value::as_str)
            .is_some_and(|id| id != self.session_id)
        {
            return Ok(Some(Ending::Session));
        }
        let Some(view) = selected.get("view") else {
            return Ok(Some(Ending::Session));
        };
        if let Some(client_id) = bootstrap.get("client_id").and_then(Value::as_str) {
            self.client_id = client_id.to_owned();
        }
        self.fallback_title = session::fallback_title_for(&bootstrap, view, &self.block_id);
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
        if let Err(error) = start_take(ctrl, self.block())?.finish().await {
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
        match Data::resume(self.server, self.data.token, self.data.received).await {
            Ok(data) => {
                self.filter = Filter::new(data.nonce);
                self.data = data;
                Ok(())
            }
            Err(_) => {
                let ticket = ticket(ctrl, self.block()).await?;
                self.data = Data::open(self.server, &ticket).await?;
                self.filter = Filter::new(self.data.nonce);
                self.pending.clear();
                self.primed = false;
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyAction {
    /// Detach the current zrex client.
    Detach,
    /// `Alt` + detach key: forward the literal control byte to the remote block
    /// so a nested zrex (or program expecting the key) receives it.
    PassThrough(u8),
    /// Kitty release event for `Alt` + detach key: consume without forwarding.
    Ignore,
}

/// Finds the earliest detach or `Alt`-pass-through sequence for `key` in
/// `bytes`, returning `(start, byte_len, action)`.
fn find_next_key_action(bytes: &[u8], key: DetachKey) -> Option<(usize, usize, KeyAction)> {
    let ctrl_byte = key.ctrl_byte()?;
    let mut i = 0;
    while i < bytes.len() {
        if let Some((len, action)) = match_key_action_at(&bytes[i..], ctrl_byte) {
            return Some((i, len, action));
        }
        i += 1;
    }
    None
}

fn match_key_action_at(slice: &[u8], ctrl_byte: u8) -> Option<(usize, KeyAction)> {
    if slice.first() == Some(&0x1b) {
        if slice.get(1) == Some(&ctrl_byte) {
            return Some((2, KeyAction::PassThrough(ctrl_byte)));
        }
        if let Some((len, cp, shifted, mods, event_type)) = parse_csi_u(slice)
            && let Some(is_alt) = key_matches_ctrl(ctrl_byte, cp, shifted, mods)
        {
            return match (is_alt, event_type) {
                (false, 1 | 2) => Some((len, KeyAction::Detach)),
                (true, 1 | 2) => Some((len, KeyAction::PassThrough(ctrl_byte))),
                (true, 3) => Some((len, KeyAction::Ignore)),
                _ => None,
            };
        }
        if let Some((len, mods, cp)) = parse_modify_other_keys(slice)
            && let Some(is_alt) = key_matches_ctrl(ctrl_byte, cp, None, mods)
        {
            let action = if is_alt {
                KeyAction::PassThrough(ctrl_byte)
            } else {
                KeyAction::Detach
            };
            return Some((len, action));
        }
        return None;
    }
    if slice.first() == Some(&ctrl_byte) {
        return Some((1, KeyAction::Detach));
    }
    None
}

/// Parses a Kitty keyboard CSI-u sequence:
/// `ESC [ <cp>[:<shifted>[:<base>]] ; <mods>[:<event_type>] u`.
fn parse_csi_u(slice: &[u8]) -> Option<(usize, u32, Option<u32>, u32, u32)> {
    let rest = slice.strip_prefix(b"\x1b[")?;
    let mut pos = 0;
    let (cp, n) = parse_u32_prefix(&rest[pos..])?;
    pos += n;
    let mut shifted = None;
    if rest.get(pos) == Some(&b':') {
        pos += 1;
        if let Some((val, n)) = parse_u32_prefix(&rest[pos..]) {
            shifted = Some(val);
            pos += n;
        }
        if rest.get(pos) == Some(&b':') {
            pos += 1;
            if let Some((_, n)) = parse_u32_prefix(&rest[pos..]) {
                pos += n;
            }
        }
    }
    if rest.get(pos) != Some(&b';') {
        return None;
    }
    pos += 1;
    let (mods, n) = parse_u32_prefix(&rest[pos..])?;
    pos += n;
    let mut event_type = 1;
    if rest.get(pos) == Some(&b':') {
        pos += 1;
        let (val, n) = parse_u32_prefix(&rest[pos..])?;
        event_type = val;
        pos += n;
    }
    if rest.get(pos) != Some(&b'u') {
        return None;
    }
    Some((2 + pos + 1, cp, shifted, mods, event_type))
}

/// Parses an xterm `modifyOtherKeys` sequence: `ESC [ 27 ; <mods> ; <cp> ~`.
fn parse_modify_other_keys(slice: &[u8]) -> Option<(usize, u32, u32)> {
    let rest = slice.strip_prefix(b"\x1b[27;")?;
    let mut pos = 0;
    let (mods, n) = parse_u32_prefix(&rest[pos..])?;
    pos += n;
    if rest.get(pos) != Some(&b';') {
        return None;
    }
    pos += 1;
    let (cp, n) = parse_u32_prefix(&rest[pos..])?;
    pos += n;
    if rest.get(pos) != Some(&b'~') {
        return None;
    }
    Some((5 + pos + 1, mods, cp))
}

fn parse_u32_prefix(bytes: &[u8]) -> Option<(u32, usize)> {
    let len = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if len == 0 {
        return None;
    }
    let text = std::str::from_utf8(&bytes[..len]).ok()?;
    let value = text.parse::<u32>().ok()?;
    Some((value, len))
}

/// Returns `Some(has_alt)` when `(cp, shifted, mods)` encodes `ctrl_byte` with
/// Ctrl (and optionally Alt), or `None` otherwise.
fn key_matches_ctrl(ctrl_byte: u8, cp: u32, shifted: Option<u32>, mods: u32) -> Option<bool> {
    let bits = mods.checked_sub(1)?;
    // Ignore Lock/Super/Hyper/Meta bits beyond Shift(1) | Alt(2) | Ctrl(4).
    if bits & !7 != 0 || (bits & 4) == 0 {
        return None;
    }
    let has_shift = (bits & 1) != 0;
    let has_alt = (bits & 2) != 0;
    let matched = match ctrl_byte {
        0x00 => {
            cp == u32::from(b'@')
                || cp == u32::from(b'2')
                || cp == u32::from(b' ')
                || shifted == Some(u32::from(b'@'))
        }
        0x01..=0x1a => !has_shift && cp == u32::from(b'a' + ctrl_byte - 1),
        0x1c => !has_shift && cp == u32::from(b'\\'),
        0x1d => !has_shift && cp == u32::from(b']'),
        0x1e => cp == u32::from(b'^') || cp == u32::from(b'6') || shifted == Some(u32::from(b'^')),
        0x1f => {
            cp == u32::from(b'_')
                || cp == u32::from(b'-')
                || cp == u32::from(b'/')
                || shifted == Some(u32::from(b'_'))
        }
        _ => false,
    };
    matched.then_some(has_alt)
}

/// Splits `bytes` before the earliest detach sequence for `key`, skipping
/// `Alt` pass-through sequences so `\x1b<ctrl>` is never mistaken for detach.
fn split_at_detach_for(bytes: &[u8], key: DetachKey) -> (&[u8], Option<&[u8]>) {
    let mut offset = 0;
    while let Some((rel, len, action)) = find_next_key_action(&bytes[offset..], key) {
        let pos = offset + rel;
        match action {
            KeyAction::Detach => return (&bytes[..pos], Some(&bytes[pos + len..])),
            KeyAction::PassThrough(_) | KeyAction::Ignore => offset = pos + len,
        }
    }
    (bytes, None)
}

fn contains_detach_for(bytes: &[u8], key: DetachKey) -> bool {
    split_at_detach_for(bytes, key).1.is_some()
}

#[cfg(test)]
fn split_at_detach(bytes: &[u8]) -> (&[u8], Option<&[u8]>) {
    split_at_detach_for(bytes, DetachKey::default())
}

#[cfg(test)]
fn contains_detach(bytes: &[u8]) -> bool {
    contains_detach_for(bytes, DetachKey::default())
}

const PALETTE_LEN: usize = 256;
const PALETTE_BATCH: usize = 64;

/// Asks the host terminal for its default colors and its whole 256-color
/// palette in paced batches, each ending with a DA1 (`ESC [ c`) sentinel so
/// callers wait for each batch's replies (~1.8 KiB max, well below a 4 KiB
/// kernel PTY buffer) before writing the next batch. Uses ST (`ESC \`) rather
/// than BEL (`0x07`) so compliant terminals do not emit `Ctrl-G` bytes in
/// their replies. When `watch_scheme` is true, enables DECSET 2031 in batch 0
/// before its DA1 sentinel so any immediate `CSI ? 997 ; n` report is drained
/// with the probe rather than triggering a redundant refresh right after attach.
fn theme_query_batches(watch_scheme: bool) -> Vec<String> {
    let mut batches = Vec::with_capacity(PALETTE_LEN.div_ceil(PALETTE_BATCH));
    for start in (0..PALETTE_LEN).step_by(PALETTE_BATCH) {
        let mut batch = String::new();
        if start == 0 {
            batch.push_str("\x1b]10;?\x1b\\\x1b]11;?\x1b\\\x1b]12;?\x1b\\");
            if watch_scheme {
                batch.push_str(std::str::from_utf8(WATCH_SCHEME).unwrap());
            }
        }
        for index in start..(start + PALETTE_BATCH).min(PALETTE_LEN) {
            batch.push_str(&format!("\x1b]4;{index};?\x1b\\"));
        }
        batch.push_str("\x1b[c");
        batches.push(batch);
    }
    batches
}

struct ProbeDeadline {
    idle: Duration,
    idle_at: Instant,
    hard_at: Instant,
}

impl ProbeDeadline {
    fn new(idle: Duration, max: Duration) -> Self {
        let now = Instant::now();
        Self {
            idle,
            idle_at: now + idle,
            hard_at: now + max,
        }
    }

    fn remaining(&self) -> Option<Duration> {
        self.idle_at
            .min(self.hard_at)
            .checked_duration_since(Instant::now())
    }

    fn bump(&mut self) {
        self.idle_at = Instant::now() + self.idle;
    }
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

/// Holds a reply that arrived only partly: one `theme_query` answer is larger
/// than the 4096-byte reads the input thread hands out, so replies regularly
/// straddle two of them. Half a reply looks like typed input on its own and
/// would be forwarded into the block's PTY, whose program echoes the bytes.
#[derive(Default)]
struct Replies {
    held: Vec<u8>,
    /// True when `held` came from a startup probe tail or an active reply burst
    /// rather than standalone typing, so detaching drops it instead of writing
    /// a truncated host reply into the remote PTY.
    held_from_reply: bool,
    /// When the host has been silent long enough for `held` to be typing.
    until: Option<Instant>,
    /// Deadline until which incoming split openers are treated as part of an
    /// active host reply stream rather than standalone keypresses.
    answered_until: Option<Instant>,
}

impl Replies {
    fn is_definite_reply_fragment(fragment: &[u8], from_reply: bool) -> bool {
        from_reply && !bare_opener(fragment)
    }

    fn hold_duration(fragment: &[u8], from_reply: bool) -> Duration {
        if Self::is_definite_reply_fragment(fragment, from_reply) {
            REPLY_FRAGMENT_HOLD
        } else {
            REPLY_HOLD
        }
    }

    fn holding_definite_reply(&self) -> bool {
        Self::is_definite_reply_fragment(&self.held, self.held_from_reply)
    }

    fn push(&mut self, bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let now = Instant::now();
        let resumed = !self.held.is_empty();
        let was_from_reply = self.held_from_reply;
        let answering = self.answered_until.is_some_and(|until| now < until);
        let mut pending = std::mem::take(&mut self.held);
        pending.extend_from_slice(bytes);
        let cut = reply_tail(&pending).unwrap_or(pending.len());
        let (replies, mut typed) = split_replies(&pending[..cut]);
        let mut fragment = pending.split_off(cut);
        // Nothing here answered a query, so an opener at the end is a keypress:
        // holding it would merge it with the next key into an Alt combination.
        // A reply burst never arrives as one or two bytes.
        if !resumed && !answering && replies.is_empty() && bare_opener(&fragment) {
            typed.extend_from_slice(&fragment);
            fragment.clear();
        }
        let from_reply = !replies.is_empty() || answering || (resumed && was_from_reply);
        self.hold_at(fragment, from_reply, now);
        self.answered_until = if !replies.is_empty() || (from_reply && !self.held.is_empty()) {
            Some(now + REPLY_HOLD)
        } else if answering {
            self.answered_until
        } else {
            None
        };
        (replies, typed)
    }

    /// Keeps a startup probe's unfinished tail (if any) and keeps expecting
    /// split host replies (longer when the probe did not finish all DA1
    /// batches, and briefly otherwise for any late scheme report).
    fn hold_probe(&mut self, fragment: Vec<u8>, awaiting_more: bool) {
        let now = Instant::now();
        self.hold_at(fragment, true, now);
        let window = if awaiting_more || !self.held.is_empty() {
            REPLY_FRAGMENT_HOLD
        } else {
            REPLY_HOLD
        };
        self.answered_until = Some(now + window);
    }

    /// Marks that a host query was just sent so a split first chunk is treated
    /// as a reply fragment rather than typed input.
    fn expect_reply(&mut self) {
        self.answered_until = Some(Instant::now() + REPLY_HOLD);
    }

    fn hold_at(&mut self, fragment: Vec<u8>, from_reply: bool, now: Instant) {
        let hold_for = Self::hold_duration(&fragment, from_reply);
        self.until = (!fragment.is_empty()).then(|| now + hold_for);
        self.held_from_reply = !fragment.is_empty() && from_reply;
        self.held = fragment;
    }

    /// When the host has been silent long enough for `held` to be typing.
    fn due(&self) -> Option<Instant> {
        self.until
    }

    /// Postpones the clock while queued input can still finish the fragment.
    fn defer(&mut self) {
        if !self.held.is_empty() {
            let hold_for = Self::hold_duration(&self.held, self.held_from_reply);
            self.until = Some(Instant::now() + hold_for);
        }
    }

    /// Hands back a fragment the host stopped sending, which was typing.
    fn give_up(&mut self) -> Vec<u8> {
        self.until = None;
        self.answered_until = None;
        self.held_from_reply = false;
        std::mem::take(&mut self.held)
    }

    /// Called when the stall timer expires: forwards standalone typing or an
    /// ambiguous bare opener (`Esc`, `Alt+[`, `Alt+]`), but drops a definite
    /// partial host reply so truncated escape sequences never enter the PTY
    /// while keeping reply-expectation active for any straggling sequence.
    fn give_up_stalled(&mut self) -> Vec<u8> {
        if self.holding_definite_reply() {
            self.until = None;
            self.held_from_reply = false;
            self.held.clear();
            self.answered_until = Some(Instant::now() + REPLY_HOLD);
            Vec::new()
        } else {
            self.give_up()
        }
    }

    /// Like `give_up`, but drops fragments that originated from a host reply
    /// stream so detaching mid-reply does not inject escape garbage into the PTY.
    fn give_up_typed(&mut self) -> Vec<u8> {
        let from_reply = self.held_from_reply;
        let held = self.give_up();
        if from_reply { Vec::new() } else { held }
    }
}

/// True for the fragments that are ambiguous on their own: the Escape key, Alt+[
/// and Alt+].
fn bare_opener(fragment: &[u8]) -> bool {
    matches!(fragment, [0x1b] | [0x1b, b'['] | [0x1b, b']'])
}

const REPLY_CODES: [&[u8]; 4] = [b"4", b"10", b"11", b"12"];

/// Where a reply that is still arriving starts, if the buffer ends inside one.
/// An unfinished reply runs to the end of the buffer, so its start is the first
/// ESC that opens a sequence which never closes: the terminator a reply waits
/// for can itself arrive split, as ESC then backslash.
fn reply_tail(bytes: &[u8]) -> Option<usize> {
    bytes
        .iter()
        .enumerate()
        .filter(|&(_, &b)| b == 0x1b)
        .map(|(start, _)| start)
        .find(|&start| tail_unfinished(&bytes[start..]))
}

/// True while the reply starting at tail has not finished arriving. Whether a
/// lone ESC or a bare opener really is one is up to `Replies`, which knows what
/// the rest of the read held.
fn tail_unfinished(tail: &[u8]) -> bool {
    if tail.len() > MAX_HELD_REPLY {
        return false;
    }
    match tail {
        [0x1b] => true,
        [0x1b, b']', rest @ ..] => osc_open(rest),
        [0x1b, b'[', rest @ ..] => csi_open(rest),
        _ => false,
    }
}

/// True while `rest` is the unfinished body of an `OSC 4` or `OSC 10`/`11`/`12`
/// reply.
fn osc_open(rest: &[u8]) -> bool {
    if rest.contains(&0x07) || rest.windows(2).any(|pair| pair == b"\x1b\\") {
        return false;
    }
    let end = rest
        .iter()
        .position(|&b| !b.is_ascii_digit())
        .unwrap_or(rest.len());
    let code = &rest[..end];
    if end < rest.len() {
        // The code is complete, so both `;` and a reply code are required.
        return rest[end] == b';' && REPLY_CODES.contains(&code);
    }
    if code.is_empty() {
        // `ESC ]` alone is either Alt+] or an OSC reply starting up.
        return true;
    }
    REPLY_CODES.iter().any(|want| want.starts_with(code))
}

/// True while `rest` is the unfinished parameter bytes of a CSI reply. A
/// complete control sequence, and anything without the `?`/`>` that only
/// replies carry, is typing that has to reach the block untouched.
fn csi_open(rest: &[u8]) -> bool {
    if rest.iter().any(|&b| (0x40..=0x7e).contains(&b)) {
        return false;
    }
    match rest {
        [] => true,
        [b'?' | b'>', params @ ..] => params
            .iter()
            .all(|&b| b.is_ascii_digit() || b == b';' || b == b':' || b == b'$'),
        _ => false,
    }
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
    if final_byte == b'c'
        || (prefix == b'?' && final_byte == b'n' && params.starts_with(b"997;"))
        || (prefix == b'?' && final_byte == b'u')
    {
        return Some(2 + 1 + end + 1);
    }
    if prefix == b'?' && final_byte == b'$' && params.get(end + 1) == Some(&b'y') {
        return Some(2 + 1 + end + 2);
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

fn take_write_chunk(queue: &mut String, max_bytes: usize) -> String {
    if queue.len() <= max_bytes {
        return std::mem::take(queue);
    }
    let mut split = max_bytes;
    while split > 0 && !queue.is_char_boundary(split) {
        split -= 1;
    }
    if split == 0 {
        // Never stall if max_bytes is smaller than the leading UTF-8 char.
        split = queue.chars().next().map_or(0, char::len_utf8);
    }
    let rest = queue.split_off(split);
    std::mem::replace(queue, rest)
}

async fn finish_write(inflight: &mut Option<InflightWrite>) -> Result<Value> {
    let Some(write) = inflight.as_mut() else {
        return std::future::pending().await;
    };
    let outcome = tokio::time::timeout_at(write.deadline, &mut write.rx).await;
    *inflight = None;
    match outcome {
        Ok(received) => received.map_err(|_| anyhow!("the control connection ended"))?,
        Err(_) => Err(anyhow::Error::new(CallTimeout(format!(
            "the server did not answer com.superlogical.terminal.write within {}",
            format_timeout(CALL_TIME)
        )))),
    }
}

async fn finish_inflight(inflight: &mut Option<InflightCall>) -> Result<Value> {
    let Some(call) = inflight.as_mut() else {
        return std::future::pending().await;
    };
    let method = call.method;
    let timeout = call.timeout;
    let outcome = tokio::time::timeout_at(call.deadline, &mut call.rx).await;
    *inflight = None;
    match outcome {
        Ok(received) => received.map_err(|_| anyhow!("the control connection ended"))?,
        Err(_) => Err(anyhow::Error::new(CallTimeout(format!(
            "the server did not answer {method} within {}",
            format_timeout(timeout)
        )))),
    }
}

struct PendingRpc {
    method: &'static str,
    rx: tokio::sync::oneshot::Receiver<Result<Value>>,
}

impl PendingRpc {
    fn start(ctrl: &mut Control, method: &'static str, payload: Value) -> Result<Self> {
        Ok(Self {
            method,
            rx: ctrl.start_call(method, payload)?,
        })
    }

    async fn finish(self) -> Result<Value> {
        match tokio::time::timeout(CALL_TIME, self.rx).await {
            Ok(received) => received.map_err(|_| anyhow!("the control connection ended"))?,
            Err(_) => Err(anyhow::Error::new(CallTimeout(format!(
                "the server did not answer {} within {}",
                self.method,
                format_timeout(CALL_TIME)
            )))),
        }
    }
}

fn start_take(ctrl: &mut Control, block: BlockRef<'_>) -> Result<PendingRpc> {
    PendingRpc::start(
        ctrl,
        "session.own_block",
        json!({
            "session_id": block.session_id,
            "block_ids": [block.block_id],
            "mode": "take",
        }),
    )
}

fn start_set_theme(ctrl: &mut Control, block: BlockRef<'_>, theme: &Theme) -> Result<PendingRpc> {
    PendingRpc::start(
        ctrl,
        "com.superlogical.terminal.set_theme",
        json!({
            "session_id": block.session_id,
            "block_id": block.block_id,
            "args": theme.to_json(),
        }),
    )
}

fn start_resize(
    ctrl: &mut Control,
    block: BlockRef<'_>,
    cols: u16,
    rows: u16,
) -> Result<PendingRpc> {
    PendingRpc::start(
        ctrl,
        "com.superlogical.terminal.resize",
        json!({
            "session_id": block.session_id,
            "block_id": block.block_id,
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
    block: BlockRef<'_>,
    size: (u16, u16),
    theme: &Theme,
    push: Push,
) -> Result<()> {
    let theme_call = (push.theme() && !theme.is_empty())
        .then(|| start_set_theme(ctrl, block, theme))
        .transpose()?;
    let size_call = push
        .size()
        .then(|| start_resize(ctrl, block, size.0, size.1))
        .transpose()?;
    if let Some(call) = theme_call {
        call.finish().await?;
    }
    if let Some(call) = size_call {
        call.finish().await?;
    }
    Ok(())
}

/// `extra_palette` is omitted so the server's 256-color table does not
/// overwrite the host terminal's color theme via OSC 4.
async fn format_vt(ctrl: &mut Control, block: BlockRef<'_>) -> Result<Vec<u8>> {
    let reply = ctrl
        .call(
            "com.superlogical.terminal.format",
            json!({
                "session_id": block.session_id,
                "block_id": block.block_id,
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
        block,
        "com.superlogical.terminal.blob_read",
        id,
        content,
    )
    .await?;
    Ok(full.into_bytes())
}

async fn clipboard(ctrl: &mut Control, block: BlockRef<'_>, id: i64) -> Result<String> {
    read_chunks(
        ctrl,
        block,
        "com.superlogical.terminal.clipboard_read",
        id,
        String::new(),
    )
    .await
}

async fn read_chunks(
    ctrl: &mut Control,
    block: BlockRef<'_>,
    method: &str,
    id: i64,
    out: String,
) -> Result<String> {
    read_chunks_with_limits(
        ctrl,
        block,
        method,
        id,
        out,
        tokio::time::Instant::now() + BLOB_READ_TIME,
        MAX_TOTAL_BLOB_BYTES,
    )
    .await
}

async fn read_chunks_with_limits(
    ctrl: &mut Control,
    block: BlockRef<'_>,
    method: &str,
    id: i64,
    mut out: String,
    deadline: tokio::time::Instant,
    max_total_bytes: usize,
) -> Result<String> {
    if out.len() > max_total_bytes {
        bail!("{method} exceeded maximum size of {max_total_bytes} bytes");
    }
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| {
                anyhow::Error::new(CallTimeout(format!(
                    "the server did not finish {method} within {}",
                    format_timeout(BLOB_READ_TIME)
                )))
            })?;
        let part = ctrl
            .call_with_timeout(
                method,
                json!({
                    "session_id": block.session_id,
                    "block_id": block.block_id,
                    "args": {"id": id, "offset": out.len(), "max_bytes": MAX_BLOB_BYTES},
                }),
                remaining,
            )
            .await?;
        let data = part.get("data").and_then(Value::as_str).unwrap_or_default();
        let eof = part.get("eof").and_then(Value::as_bool).unwrap_or(true);
        if out.len().saturating_add(data.len()) > max_total_bytes {
            bail!("{method} exceeded maximum size of {max_total_bytes} bytes");
        }
        out.push_str(data);
        if eof {
            break;
        }
        if data.is_empty() {
            bail!("{method} returned empty chunk before eof");
        }
    }
    Ok(out)
}

/// Resolves when a held fragment has waited long enough to count as typing, and
/// never while nothing is held.
async fn stalled(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending::<()>().await,
    }
}

enum Interruptible<T> {
    Done(T),
    Detach { double: bool },
}

enum PreAttachOutcome<T> {
    Done(T),
    Cancelled { quit: bool },
}

fn detect_detach_in_input(bytes: &[u8], detach_key: DetachKey) -> Option<bool> {
    if detach_key == DetachKey::Ctrl(0x07) {
        let (_, typed) = split_replies(bytes);
        split_at_detach_for(&typed, detach_key)
            .1
            .map(|tail| contains_detach_for(tail, detach_key))
    } else {
        split_at_detach_for(bytes, detach_key)
            .1
            .map(|tail| contains_detach_for(tail, detach_key))
    }
}

struct InputReader {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    buffered: VecDeque<Vec<u8>>,
    wake: Option<std::io::PipeWriter>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl InputReader {
    fn spawn() -> Result<Self> {
        Self::spawn_reader(std::io::stdin())
    }

    fn spawn_reader(input: impl Read + AsRawFd + Send + 'static) -> Result<Self> {
        let (wake_rd, wake_wr) = std::io::pipe()?;
        let (tx, rx) = mpsc::unbounded_channel();
        let thread = std::thread::spawn(move || {
            read_until_wake(input, wake_rd, tx);
        });
        Ok(Self {
            rx,
            buffered: VecDeque::new(),
            wake: Some(wake_wr),
            thread: Some(thread),
        })
    }

    #[cfg(test)]
    fn from_channel(rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buffered: VecDeque::new(),
            wake: None,
            thread: None,
        }
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        if let Some(bytes) = self.buffered.pop_front() {
            return Some(bytes);
        }
        self.rx.recv().await
    }

    fn try_recv(&mut self) -> Option<Vec<u8>> {
        if let Some(bytes) = self.buffered.pop_front() {
            return Some(bytes);
        }
        self.rx.try_recv().ok()
    }

    fn is_empty(&self) -> bool {
        self.buffered.is_empty() && self.rx.is_empty()
    }

    fn drain_detach(&mut self, detach_key: DetachKey) -> bool {
        let mut saw_detach = false;
        while let Some(bytes) = self.try_recv() {
            if detect_detach_in_input(&bytes, detach_key).is_some() {
                saw_detach = true;
            }
        }
        saw_detach
    }

    /// Awaits `future` while continuously monitoring stdin for `detach_key`.
    /// When `discard_other` is false (live session), non-detach input chunks
    /// are buffered in order and delivered on subsequent `recv()` calls; when
    /// true (offline recovery), non-detach input is dropped and EOF detaches.
    async fn await_or_detach<T>(
        &mut self,
        detach_key: DetachKey,
        discard_other: bool,
        future: impl Future<Output = T>,
    ) -> Interruptible<T> {
        if discard_other {
            while let Some(bytes) = self.try_recv() {
                if let Some(double) = detect_detach_in_input(&bytes, detach_key) {
                    return Interruptible::Detach {
                        double: double || self.drain_detach(detach_key),
                    };
                }
            }
        }
        let mut fut = std::pin::pin!(future);
        loop {
            tokio::select! {
                biased;
                bytes = self.rx.recv() => {
                    match bytes {
                        Some(bytes) => {
                            if let Some(double) = detect_detach_in_input(&bytes, detach_key) {
                                return Interruptible::Detach {
                                    double: double || self.drain_detach(detach_key),
                                };
                            }
                            if !discard_other {
                                self.buffered.push_back(bytes);
                            }
                        }
                        None => {
                            if discard_other {
                                return Interruptible::Detach { double: false };
                            }
                            return Interruptible::Done(fut.await);
                        }
                    }
                }
                result = fut.as_mut() => return Interruptible::Done(result),
            }
        }
    }

    /// Awaits a pre-attach network step while monitoring stdin for `detach_key`
    /// or `Ctrl-C`, cancelling immediately if the user interrupts.
    async fn await_or_cancel<T>(
        &mut self,
        detach_key: DetachKey,
        future: impl Future<Output = T>,
    ) -> PreAttachOutcome<T> {
        let mut fut = std::pin::pin!(future);
        loop {
            tokio::select! {
                biased;
                bytes = self.rx.recv() => {
                    match bytes {
                        Some(bytes) => {
                            if let Some(double) = detect_detach_in_input(&bytes, detach_key) {
                                return PreAttachOutcome::Cancelled {
                                    quit: double || self.drain_detach(detach_key),
                                };
                            }
                            if contains_detach_for(&bytes, DetachKey::Ctrl(0x03)) {
                                return PreAttachOutcome::Cancelled { quit: true };
                            }
                        }
                        None => return PreAttachOutcome::Cancelled { quit: true },
                    }
                }
                result = fut.as_mut() => return PreAttachOutcome::Done(result),
            }
        }
    }

    fn stop(&mut self) {
        if let Some(mut wake) = self.wake.take() {
            let _ = wake.write_all(&[1]);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Stops the background reader thread so it cannot steal subsequent keys
    /// from the picker, and reports whether any already-queued chunks carried a
    /// second detach key.
    fn stop_and_drain_detach(&mut self, detach_key: DetachKey) -> bool {
        self.stop();
        self.drain_detach(detach_key)
    }
}

impl Drop for InputReader {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_until_wake(
    mut input: impl Read + AsRawFd,
    wake_rd: std::io::PipeReader,
    tx: mpsc::UnboundedSender<Vec<u8>>,
) {
    let input_fd = input.as_raw_fd();
    let wake_fd = wake_rd.as_raw_fd();
    let mut buf = [0u8; 4096];
    loop {
        let mut fds = [
            libc_pollfd {
                fd: input_fd,
                events: POLLIN,
                revents: 0,
            },
            libc_pollfd {
                fd: wake_fd,
                events: POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { poll(fds.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if fds[1].revents != 0 {
            return;
        }
        if fds[0].revents != 0 {
            match input.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
        }
    }
}

fn write_reconnecting_title(out: &mut impl Write, detach_key: DetachKey) -> Result<()> {
    let title = match detach_key {
        DetachKey::None => "reconnecting…".to_owned(),
        key => format!("reconnecting… ({key} to detach)"),
    };
    out.write_all(&stream::format_osc_title(b'0', &title, b"\x07"))?;
    out.flush()?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Recovered {
    Live,
    Detach { double: bool },
    Ended(Ending),
}

async fn recover(
    token: &mut Option<String>,
    ctrl: &mut Control,
    events: &mut Events,
    attached: &mut Attached<'_>,
    input: &mut InputReader,
) -> Result<Recovered> {
    let detach_key = attached.detach_key;
    let mut delay = RETRY_FIRST;
    loop {
        let outcome = match input
            .await_or_detach(detach_key, true, attempt(token, ctrl, events, attached))
            .await
        {
            Interruptible::Detach { double } => return Ok(Recovered::Detach { double }),
            Interruptible::Done(outcome) => outcome,
        };
        match outcome {
            Ok(None) => {
                // Keys pressed while the link was down have nowhere to go,
                // except a detach key that raced with reconnect completion.
                while let Some(bytes) = input.try_recv() {
                    if let Some(double) = detect_detach_in_input(&bytes, detach_key) {
                        return Ok(Recovered::Detach {
                            double: double || input.drain_detach(detach_key),
                        });
                    }
                }
                attached.replies = Replies::default();
                attached.input_buf.clear();
                attached.write_queue.clear();
                attached.write_inflight = None;
                return Ok(Recovered::Live);
            }
            Ok(Some(ending)) => return Ok(Recovered::Ended(ending)),
            Err(_) => {
                if let Interruptible::Detach { double } = input
                    .await_or_detach(detach_key, true, tokio::time::sleep(delay))
                    .await
                {
                    return Ok(Recovered::Detach { double });
                }
                delay = backoff(delay);
            }
        }
    }
}

async fn attempt(
    token: &mut Option<String>,
    ctrl: &mut Control,
    events: &mut Events,
    attached: &mut Attached<'_>,
) -> Result<Option<Ending>> {
    if ctrl
        .call_with_timeout("server.version", Value::Null, PROBE_TIME)
        .await
        .is_err()
    {
        let (new_ctrl, new_events) =
            Control::connect_once(attached.server, token.as_deref(), CONNECT_TIME).await?;
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
    if ctrl.is_lost()
        || error.downcast_ref::<StreamClosed>().is_some()
        || error.downcast_ref::<CallTimeout>().is_some()
    {
        return true;
    }
    match error.downcast_ref::<proto::ApiError>() {
        Some(error) => error.status == 409,
        None => false,
    }
}

fn write_target_gone(error: &anyhow::Error) -> bool {
    error.downcast_ref::<proto::ApiError>().is_some_and(|api| {
        api.status == 404
            || matches!(
                api.code.as_str(),
                "not_found" | "block_not_found" | "session_not_found" | "block_closed"
            )
    })
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

async fn detach(ctrl: &mut Control, attached: &mut Attached<'_>) {
    let deadline = tokio::time::Instant::now() + DETACH_TIME;
    if !ctrl.is_lost() && attached.drain_writes(ctrl, deadline).await {
        detach_session(ctrl, &attached.session_id, deadline).await;
    }
}

async fn detach_session(ctrl: &mut Control, session_id: &str, deadline: tokio::time::Instant) {
    if ctrl.is_lost() {
        return;
    }
    let Some(timeout) = deadline.checked_duration_since(tokio::time::Instant::now()) else {
        return;
    };
    let _ = ctrl
        .call_with_timeout("session.detach", json!({"session_id": session_id}), timeout)
        .await;
}

fn start_ticket(ctrl: &mut Control, block: BlockRef<'_>) -> Result<PendingRpc> {
    PendingRpc::start(
        ctrl,
        "data.connect",
        json!({
            "session_id": block.session_id,
            "block_id": block.block_id,
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

async fn ticket(ctrl: &mut Control, block: BlockRef<'_>) -> Result<String> {
    parse_ticket(&start_ticket(ctrl, block)?.finish().await?)
}

fn closed_block(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<StreamClosed>()
        .is_some_and(StreamClosed::is_block_closed)
}

struct ProbeOutcome {
    theme: Theme,
    tail: Vec<u8>,
    da1_seen: bool,
    replied: bool,
}

fn drain_ready_input(fd: i32, input: &mut impl Read, chunk: &mut [u8]) {
    loop {
        let mut pfd = libc_pollfd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        let ready = unsafe { poll(&mut pfd, 1, 0) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if ready == 0 || (pfd.revents & POLLIN) == 0 {
            break;
        }
        match input.read(chunk) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

fn probe_theme_with(
    out: &mut impl Write,
    input: &mut (impl Read + AsRawFd),
    idle_timeout: Duration,
    max_timeout: Duration,
) -> ProbeOutcome {
    let fd = input.as_raw_fd();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    // Clear any stale reply bytes already queued in stdin so an earlier DA1
    // cannot short-circuit batch 0.
    drain_ready_input(fd, input, &mut chunk);

    let mut deadline = ProbeDeadline::new(idle_timeout, max_timeout);
    let mut all_da1_seen = true;

    for batch in theme_query_batches(true) {
        let batch_start = buf.len();
        if out.write_all(batch.as_bytes()).is_err() || out.flush().is_err() {
            all_da1_seen = false;
            break;
        }

        while !has_da1_reply(&buf[batch_start..]) {
            let Some(remaining) = deadline.remaining() else {
                break;
            };
            let timeout_ms = (remaining.as_millis() as i32).max(1);
            let mut pfd = libc_pollfd {
                fd,
                events: POLLIN,
                revents: 0,
            };
            let ready = unsafe { poll(&mut pfd, 1, timeout_ms) };
            if ready < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if ready == 0 {
                break;
            }
            match input.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    deadline.bump();
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }

        if !has_da1_reply(&buf[batch_start..]) {
            all_da1_seen = false;
            break;
        }
    }

    let tail = reply_tail(&buf).map_or_else(Vec::new, |start| buf[start..].to_vec());
    let replied = !buf.is_empty();
    ProbeOutcome {
        theme: parse_theme_reply(&buf),
        tail,
        da1_seen: all_da1_seen,
        replied,
    }
}

fn has_dsr_reply(bytes: &[u8]) -> bool {
    bytes
        .windows(DSR_STATUS_REPLY.len())
        .any(|window| window == DSR_STATUS_REPLY)
}

/// Writes `RESET_MODES` and, when `wait_for_dsr` is true, sends a DSR status
/// query (`CSI 5 n`) and drains stdin while raw mode is still active until the
/// terminal replies `CSI 0 n` (or the deadline expires). This ensures any
/// in-flight OSC/DA1 replies over SSH arrive and are discarded before cooked
/// mode or the picker resumes. Returns true if the drained bytes contained the
/// configured detach key (fast double-detach).
fn drain_after_reset_with(
    out: &mut impl Write,
    input: &mut (impl Read + AsRawFd),
    detach_key: DetachKey,
    wait_for_dsr: bool,
    idle_timeout: Duration,
    max_timeout: Duration,
) -> Result<bool> {
    out.write_all(RESET_MODES)?;
    if !wait_for_dsr {
        out.flush()?;
        return Ok(false);
    }
    out.write_all(DSR_STATUS_QUERY)?;
    out.flush()?;

    let fd = input.as_raw_fd();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut deadline = ProbeDeadline::new(idle_timeout, max_timeout);

    while !has_dsr_reply(&buf) {
        let Some(remaining) = deadline.remaining() else {
            break;
        };
        let timeout_ms = (remaining.as_millis() as i32).max(1);
        let mut pfd = libc_pollfd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        let ready = unsafe { poll(&mut pfd, 1, timeout_ms) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if ready == 0 {
            break;
        }
        match input.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                deadline.bump();
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    let saw_detach = if detach_key == DetachKey::Ctrl(0x07) {
        let (_, typed) = split_replies(&buf);
        contains_detach_for(&typed, detach_key)
    } else {
        contains_detach_for(&buf, detach_key)
    };
    Ok(saw_detach)
}

struct Screen {
    stdout: std::io::Stdout,
    entered: bool,
    host_replied: bool,
    terminal_mode: TerminalMode,
}

impl Screen {
    fn enter(terminal_mode: TerminalMode) -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        // Clear any leftover OSC 4/10/11/12 overrides before probing the host
        // terminal's theme, and save the host title so RESET_MODES can restore it.
        stdout.write_all(RESET_COLORS)?;
        stdout.write_all(b"\x1b[22;0t")?;
        stdout.flush()?;
        Ok(Self {
            stdout,
            entered: true,
            host_replied: false,
            terminal_mode,
        })
    }

    /// Returns the theme and any unfinished reply state if the probe timed out.
    fn probe_theme(&mut self) -> ProbeOutcome {
        let mut stdin = std::io::stdin();
        let outcome = probe_theme_with(
            &mut self.stdout,
            &mut stdin,
            THEME_PROBE_IDLE,
            THEME_PROBE_MAX,
        );
        self.host_replied |= outcome.replied;
        outcome
    }

    fn out(&mut self) -> &mut std::io::Stdout {
        &mut self.stdout
    }

    fn leave_and_drain(&mut self, detach_key: DetachKey, host_replied: bool) -> Result<bool> {
        if !self.entered {
            return Ok(false);
        }
        self.entered = false;
        let wait_for_dsr = self.host_replied || host_replied;
        let mut stdin = std::io::stdin();
        let saw_detach = drain_after_reset_with(
            &mut self.stdout,
            &mut stdin,
            detach_key,
            wait_for_dsr,
            DETACH_DRAIN_IDLE,
            DETACH_DRAIN_MAX,
        )?;
        if self.terminal_mode == TerminalMode::RestoreOnLeave {
            disable_raw_mode()?;
        }
        Ok(saw_detach)
    }

    fn leave_immediate(&mut self) -> Result<()> {
        if !self.entered {
            return Ok(());
        }
        self.entered = false;
        self.stdout.write_all(RESET_MODES)?;
        self.stdout.flush()?;
        if self.terminal_mode == TerminalMode::RestoreOnLeave {
            disable_raw_mode()?;
        }
        Ok(())
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = self.leave_immediate();
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
        Attached, BlockSelection, DSR_STATUS_QUERY, DSR_STATUS_REPLY, Ending, Flow, InflightWrite,
        InputReader, KeyAction, PALETTE_BATCH, PALETTE_LEN, REPLY_FRAGMENT_HOLD, REPLY_HOLD,
        RESET_MODES, RETRY_FIRST, RETRY_MAX, Replies, Theme, WATCH_SCHEME, backoff, closed_block,
        contains_detach, contains_detach_for, detach, drain_after_reset_with, find_next_key_action,
        finish_write, has_da1_reply, parse_theme_reply, probe_theme_with, read_chunks_with_limits,
        reports_scheme, split_at_detach, split_at_detach_for, split_replies, take_utf8,
        take_write_chunk, theme_query_batches, transient, write_target_gone,
    };
    use crate::config::DetachKey;
    use crate::rex::BlockRef;
    use crate::rex::control::{CallTimeout, Control};
    use crate::rex::data::StreamClosed;
    use crate::rex::proto::ApiError;
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
    fn recognizes_detach_key_in_legacy_kitty_and_xterm_modes_including_batched_reads() {
        for seq in [
            b"\x1c".as_slice(),
            b"\x1b[92;5u".as_slice(),
            b"\x1b[92;5:1u".as_slice(),
            b"\x1b[92;5:2u".as_slice(),
            b"\x1b[92:124;5u".as_slice(),
            b"\x1b[92:124;5:1u".as_slice(),
            b"\x1b[27;5;92~".as_slice(),
        ] {
            assert_eq!(split_at_detach(seq), (b"".as_slice(), Some(b"".as_slice())));
            assert!(contains_detach(seq));
        }

        assert_eq!(
            split_at_detach(b"abc\x1c"),
            (b"abc".as_slice(), Some(b"".as_slice()))
        );
        assert_eq!(
            split_at_detach(b"abc\x1b[92;5u"),
            (b"abc".as_slice(), Some(b"".as_slice()))
        );
        assert_eq!(
            split_at_detach(b"a\x1b[27;5;92~tail"),
            (b"a".as_slice(), Some(b"tail".as_slice()))
        );
        assert_eq!(
            split_at_detach(b"\x1ctail"),
            (b"".as_slice(), Some(b"tail".as_slice()))
        );

        // Double detach in a single read exposes the second sequence in the tail.
        for pair in [
            b"\x1c\x1c".as_slice(),
            b"abc\x1c\x1c".as_slice(),
            b"\x1b[92;5u\x1b[92;5u".as_slice(),
            b"\x1c\x1b[92;5u".as_slice(),
            b"\x1b[27;5;92~\x1c".as_slice(),
        ] {
            let (_, tail) = split_at_detach(pair);
            assert!(
                tail.is_some_and(contains_detach),
                "expected second detach in tail of {pair:?}"
            );
        }

        assert_eq!(split_at_detach(b"\\"), (b"\\".as_slice(), None));
        assert_eq!(
            split_at_detach(b"\x1b[92;1u"),
            (b"\x1b[92;1u".as_slice(), None)
        );
        assert_eq!(split_at_detach(b"hello"), (b"hello".as_slice(), None));
    }

    #[tokio::test]
    async fn input_reader_stops_without_consuming_subsequent_bytes_and_drains_queued_detach() {
        use std::io::{Read, Write};

        let (input_rd, mut input_wr) = std::io::pipe().unwrap();
        // Keep a duplicate read handle on the same pipe so we can verify bytes
        // written after stop() are not stolen by the background thread.
        let mut reader_after = input_rd.try_clone().unwrap();
        let mut reader = InputReader::spawn_reader(input_rd).unwrap();

        input_wr.write_all(b"hello").unwrap();
        let first = tokio::time::timeout(Duration::from_secs(1), reader.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first, b"hello");

        // Queue a detach byte and wait until the reader thread has placed it in the channel.
        input_wr.write_all(b"\x1c").unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while reader.is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(reader.stop_and_drain_detach(DetachKey::default()));

        // Bytes written after stop() stay in the pipe for the next reader (e.g. picker).
        input_wr.write_all(b"\x1cnext").unwrap();
        let mut remaining = [0u8; 16];
        let n = reader_after.read(&mut remaining).unwrap();
        assert_eq!(&remaining[..n], b"\x1cnext");
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

    fn palette_reply(terminator: &[u8], entries: usize) -> Vec<u8> {
        let mut stream = Vec::new();
        for code in ["10", "11", "12"] {
            stream.extend_from_slice(format!("\x1b]{code};rgb:cdcd/d6d6/f4f4").as_bytes());
            stream.extend_from_slice(terminator);
        }
        for index in 0..entries {
            stream.extend_from_slice(format!("\x1b]4;{index};rgb:0000/0000/0000").as_bytes());
            stream.extend_from_slice(terminator);
        }
        stream.extend_from_slice(b"\x1b[?62;22c");
        stream
    }

    #[test]
    fn holds_replies_split_across_reads_until_the_rest_arrives() {
        let mut replies = Replies::default();
        let (found, typed) = replies.push(b"ab\x1b]4;147;rgb:000");
        assert!(found.is_empty());
        assert_eq!(typed, b"ab");

        let (found, typed) = replies.push(b"0/0000/0000\x1b\\\x1b");
        assert!(typed.is_empty());
        assert_eq!(found, b"\x1b]4;147;rgb:0000/0000/0000\x1b\\");

        let (found, typed) = replies.push(b"[");
        assert!(found.is_empty());
        assert!(typed.is_empty());

        let (found, typed) = replies.push(b"?62;22c");
        assert!(typed.is_empty());
        assert_eq!(found, b"\x1b[?62;22c");
        assert!(replies.due().is_none());
    }

    #[test]
    fn forwards_nothing_when_a_read_splits_a_palette_reply() {
        for terminator in [b"\x07".as_slice(), b"\x1b\\".as_slice()] {
            let stream = palette_reply(terminator, 256);
            // A cut of one or two bytes is the Escape key or Alt+[ rather than
            // the start of a reply, so the burst starts at three.
            for cut in 3..stream.len() {
                let mut replies = Replies::default();
                let (mut found, typed) = replies.push(&stream[..cut]);
                assert_eq!(typed, b"", "typed before the split at {cut}");
                let (kept, typed) = replies.push(&stream[cut..]);
                assert_eq!(typed, b"", "typed after the split at {cut}");
                found.extend_from_slice(&kept);
                assert_eq!(found, stream, "replies around the split at {cut}");
                assert!(replies.due().is_none(), "held after the split at {cut}");
            }
        }
    }

    #[test]
    fn holds_a_lone_escape_that_arrives_right_after_a_reply() {
        let mut replies = Replies::default();
        let (found, typed) = replies.push(b"\x1b]11;rgb:ffff/ffff/ffff\x07\x1b");
        assert_eq!(found, b"\x1b]11;rgb:ffff/ffff/ffff\x07");
        assert!(typed.is_empty());
        assert!(replies.due().is_some());

        let (found, typed) = replies.push(b"]4;147;rgb:0000/0000/0000\x07");
        assert!(typed.is_empty());
        assert_eq!(found, b"\x1b]4;147;rgb:0000/0000/0000\x07");
        assert!(replies.due().is_none());
    }

    #[test]
    fn hands_a_lone_escape_back_when_the_host_stays_silent() {
        let mut replies = Replies::default();
        assert!(replies.push(b"\x1b]11;rgb:ffff/ffff/ffff\x07").1.is_empty());
        assert!(replies.push(b"\x1b").1.is_empty());
        assert!(replies.due().is_some());
        assert_eq!(replies.give_up(), b"\x1b");
        assert!(replies.due().is_none());
    }

    #[test]
    fn hands_a_half_reply_back_only_after_the_host_stops_sending() {
        let mut replies = Replies::default();
        let (found, typed) = replies.push(b"\x1b]4;147;rgb:000");
        assert!(found.is_empty());
        assert!(typed.is_empty());

        let (found, typed) = replies.push(b"0/0000/0000\x07");
        assert!(typed.is_empty());
        assert_eq!(found, b"\x1b]4;147;rgb:0000/0000/0000\x07");

        let (found, typed) = replies.push(b"\x1b]4;147;rgb:000");
        assert!(found.is_empty() && typed.is_empty());
        assert_eq!(replies.give_up(), b"\x1b]4;147;rgb:000");
    }

    #[test]
    fn finishes_a_reply_the_startup_probe_read_only_the_start_of() {
        let mut replies = Replies::default();
        replies.hold_probe(b"\x1b]11;rgb:ffff".to_vec(), true);
        let (found, typed) = replies.push(b"/ffff/ffff\x07");
        assert!(typed.is_empty());
        assert_eq!(found, b"\x1b]11;rgb:ffff/ffff/ffff\x07");
    }

    #[test]
    fn give_up_stalled_drops_definite_host_replies_but_forwards_bare_openers_and_typing() {
        // A bare ESC right after a reply burst could be the Escape key, so it
        // uses the short REPLY_HOLD and is forwarded on stall.
        let mut replies = Replies::default();
        assert!(replies.push(b"\x1b]11;rgb:ffff/ffff/ffff\x07").1.is_empty());
        assert!(replies.push(b"\x1b").1.is_empty());
        assert!(replies.due().unwrap() <= std::time::Instant::now() + REPLY_HOLD);
        assert_eq!(replies.give_up_stalled(), b"\x1b");

        // A definite partial OSC 4 reply (e.g. cut off before `5f\x07`) is held
        // much longer than REPLY_HOLD and dropped rather than injected on stall,
        // while keeping reply expectation active for any straggling sequence.
        let mut replies = Replies::default();
        replies.hold_probe(b"\x1b]4;149;rgb:afaf/d7d7/5f".to_vec(), true);
        let remaining = replies
            .due()
            .unwrap()
            .saturating_duration_since(std::time::Instant::now());
        assert!(remaining > REPLY_HOLD && remaining <= REPLY_FRAGMENT_HOLD);
        assert!(replies.give_up_stalled().is_empty());
        assert!(replies.push(b"\x1b").1.is_empty());
        assert_eq!(
            replies.push(b"]4;150;rgb:afaf/d7d7/8787\x07"),
            (b"\x1b]4;150;rgb:afaf/d7d7/8787\x07".to_vec(), Vec::new())
        );

        // Standalone typing without a prior reply is still forwarded on stall.
        let mut replies = Replies::default();
        assert!(replies.push(b"\x1b[?").1.is_empty());
        assert_eq!(replies.give_up_stalled(), b"\x1b[?");
    }

    #[test]
    fn hold_probe_keeps_expecting_split_replies_even_with_empty_tail() {
        for awaiting_more in [true, false] {
            let mut replies = Replies::default();
            replies.hold_probe(Vec::new(), awaiting_more);
            // A split first byte (`\x1b`) followed by either a Konsole OSC 4
            // reply or a late CSI ?997 scheme report must be held and stripped.
            let (found, typed) = replies.push(b"\x1b");
            assert!(found.is_empty());
            assert!(typed.is_empty());
            let (found, typed) = replies.push(b"[?997;1n");
            assert!(typed.is_empty());
            assert_eq!(found, b"\x1b[?997;1n");
        }
    }

    #[test]
    fn probe_theme_with_paces_batches_by_da1_ignores_stale_da1_and_keeps_incomplete_tail() {
        use std::io::{Read, Write};

        // 1) Simulate Konsole answering each 64-color batch only after it is
        // written (using BEL for OSC 4, ST for OSC 10/11/12, plus an immediate
        // CSI ?997 scheme report and DA1). Pre-seed a stale DA1 in stdin to
        // ensure it is drained and cannot short-circuit batch 0.
        let (mut query_rd, mut query_wr) = std::io::pipe().unwrap();
        let (mut reply_rd, mut reply_wr) = std::io::pipe().unwrap();
        reply_wr.write_all(b"\x1b[?1;2c").unwrap();

        let expected_batches = theme_query_batches(true);
        let terminal = std::thread::spawn(move || {
            let mut read_buf = [0u8; 4096];
            for (batch_idx, expected) in expected_batches.iter().enumerate() {
                let mut got = Vec::new();
                while got.len() < expected.len() {
                    let n = query_rd.read(&mut read_buf).unwrap();
                    assert!(n > 0);
                    got.extend_from_slice(&read_buf[..n]);
                }
                assert_eq!(got, expected.as_bytes(), "batch {batch_idx} mismatch");

                let mut resp = Vec::new();
                if batch_idx == 0 {
                    resp.extend_from_slice(
                        b"\x1b]10;rgb:cdcd/d6d6/f4f4\x1b\\\x1b]11;rgb:1e1e/1e1e/2e2e\x1b\\\x1b[?997;1n",
                    );
                }
                let start = batch_idx * PALETTE_BATCH;
                let end = (start + PALETTE_BATCH).min(PALETTE_LEN);
                for index in start..end {
                    resp.extend_from_slice(
                        format!("\x1b]4;{index};rgb:0000/0000/5f5f\x07").as_bytes(),
                    );
                }
                resp.extend_from_slice(b"\x1b[?1;2c");
                assert!(
                    resp.len() < 2048,
                    "each batch reply must stay well under 4 KiB"
                );
                reply_wr.write_all(&resp).unwrap();
            }
        });

        let probed = probe_theme_with(
            &mut query_wr,
            &mut reply_rd,
            Duration::from_millis(500),
            Duration::from_millis(2000),
        );
        drop(query_wr);
        terminal.join().unwrap();
        assert!(probed.da1_seen);
        assert!(probed.tail.is_empty());
        assert_eq!(probed.theme.background.as_deref(), Some("#1e1e2e"));
        assert_eq!(probed.theme.palette.len(), PALETTE_LEN);

        // 2) If a batch times out mid-OSC-4 right before `5f\x07`, probing
        // stops after that batch and returns `da1_seen == false` + the tail.
        // The reply follows the query instead of a fixed sleep, so a loaded
        // runner neither lands it before the stale-input drain nor after the
        // batch gives up.
        struct SignalOnWrite<'a> {
            out: &'a mut Vec<u8>,
            written: std::sync::mpsc::Sender<()>,
        }

        impl std::io::Write for SignalOnWrite<'_> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let written = self.out.write(buf)?;
                let _ = self.written.send(());
                Ok(written)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.out.flush()
            }
        }

        let (mut in_rd, mut in_wr) = std::io::pipe().unwrap();
        let (written, written_rd) = std::sync::mpsc::channel();
        let (release, release_rd) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            written_rd.recv().unwrap();
            in_wr
                .write_all(b"\x1b]10;rgb:1111/2222/3333\x1b\\\x1b]4;149;rgb:afaf/d7d7/5f")
                .unwrap();
            // Hold the pipe open until the probe gives up, so the batch ends by
            // its idle timeout and not by end-of-file.
            release_rd.recv().unwrap();
        });
        let mut out = Vec::new();
        let probed = probe_theme_with(
            &mut SignalOnWrite {
                out: &mut out,
                written,
            },
            &mut in_rd,
            Duration::from_millis(250),
            Duration::from_millis(750),
        );
        let _ = release.send(());
        writer.join().unwrap();
        assert!(!probed.da1_seen);
        assert_eq!(probed.tail, b"\x1b]4;149;rgb:afaf/d7d7/5f");
        // Only batch 0 was written before timing out.
        assert_eq!(out, theme_query_batches(true)[0].as_bytes());

        let mut replies = Replies::default();
        replies.hold_probe(probed.tail, !probed.da1_seen);
        let (found, typed) = replies.push(b"5f\x07\x1b[?1;2c");
        assert!(typed.is_empty());
        assert_eq!(found, b"\x1b]4;149;rgb:afaf/d7d7/5f5f\x07\x1b[?1;2c");
    }

    #[test]
    fn forwards_input_that_only_looks_like_the_start_of_a_reply() {
        let mut replies = Replies::default();
        // The Escape key, Alt+[ and Alt+] on their own are keypresses, not the
        // start of a reply.
        assert_eq!(replies.push(b"\x1b").1, b"\x1b");
        assert_eq!(replies.push(b"\x1b[").1, b"\x1b[");
        assert_eq!(replies.push(b"\x1b]").1, b"\x1b]");
        assert_eq!(replies.push(b"\x1b[A").1, b"\x1b[A");
        assert_eq!(replies.push(b"\x1b[<0;3;4M").1, b"\x1b[<0;3;4M");
        assert_eq!(replies.push(b"\x1b]0;title\x07").1, b"\x1b]0;title\x07");
        assert_eq!(replies.push(b"\x1b]abc\r").1, b"\x1b]abc\r");
        assert_eq!(replies.push(b"\x1b[?x").1, b"\x1b[?x");
        // OSC 1 is a title query, not a palette reply.
        assert_eq!(replies.push(b"\x1b]1;title\x07").1, b"\x1b]1;title\x07");
    }

    #[test]
    fn give_up_typed_flushes_standalone_typing_but_drops_host_reply_fragments() {
        // Standalone ambiguous input is flushed on detach.
        let mut replies = Replies::default();
        assert_eq!(replies.push(b"abc\x1b[?").1, b"abc");
        assert_eq!(replies.give_up_typed(), b"\x1b[?");

        // A startup probe tail is dropped on detach instead of entering the PTY.
        let mut replies = Replies::default();
        replies.hold_probe(b"\x1b]4;12;rgb:ffff/".to_vec(), true);
        assert!(replies.give_up_typed().is_empty());

        // A partial reply trailing a host reply burst is dropped on detach.
        let mut replies = Replies::default();
        let (found, typed) = replies.push(b"\x1b]10;rgb:1111/2222/3333\x07\x1b]4;12;rgb:ffff/");
        assert_eq!(found, b"\x1b]10;rgb:1111/2222/3333\x07");
        assert!(typed.is_empty());
        assert!(replies.give_up_typed().is_empty());

        // A split first chunk after `expect_reply` (e.g. `refresh_theme`) is dropped.
        let mut replies = Replies::default();
        replies.expect_reply();
        assert!(replies.push(b"\x1b]10;rgb:ffff/").1.is_empty());
        assert!(replies.give_up_typed().is_empty());
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
        let batches = theme_query_batches(true);
        assert_eq!(batches.len(), PALETTE_LEN / PALETTE_BATCH);
        assert!(batches[0].starts_with("\x1b]10;?\x1b\\\x1b]11;?\x1b\\\x1b]12;?\x1b\\"));
        assert!(batches[0].contains(std::str::from_utf8(WATCH_SCHEME).unwrap()));
        for batch in &batches {
            assert!(!batch.contains('\x07'));
            assert!(batch.ends_with("\x1b[c"));
        }
        let query = batches.concat();
        assert!(query.contains("\x1b]4;0;?\x1b\\"));
        assert!(query.contains("\x1b]4;255;?\x1b\\"));
        assert!(!query.contains("\x1b]4;256;?"));

        let refresh_batches = theme_query_batches(false);
        assert!(!refresh_batches[0].contains(std::str::from_utf8(WATCH_SCHEME).unwrap()));
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
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
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
                #[allow(
                    clippy::result_large_err,
                    reason = "tungstenite fixes the callback error type"
                )]
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
                    let data = req["payload"]["args"]["data"].as_str().unwrap_or("");
                    wrote.push_str(data);
                    ctrl_ws
                        .send(Message::Text(
                            json!({
                                "type": "response",
                                "id": id,
                                "payload": {"bytes_written": data.len()}
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
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
                    "com.superlogical.terminal.title" => {
                        json!({"title": "vim"})
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

        let address = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
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
            &address,
            BlockSelection::Selectors(None, None),
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

        let live = b"live!\x1b]2;running\x07\x1b_rex1;42;{\"type\":\"resize\",\"cols\":50,\"rows\":12}\x1b\\";
        attached.feed(live, &mut ctrl).await.unwrap();

        let mut out = Vec::new();
        attached.flush(&mut out).unwrap();
        assert_eq!(
            out,
            b"\x1b[2J\x1b[Hprimed-screen \x1b]0;zrex: vim\x07live!\x1b]2;zrex: running\x07"
        );

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
        let (host_tx, host_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut host_input = InputReader::from_channel(host_rx);
        host_tx
            .send(
                b"\x1b]10;rgb:1111/1111/1111\x07\x1b]11;rgb:eeee/eeee/eeee\x07\x1b[?62;22c"
                    .to_vec(),
            )
            .unwrap();
        drop(host_tx);
        let mut host_out = Vec::new();
        let flow = attached
            .refresh_theme(&mut host_out, &mut host_input, &mut ctrl)
            .await
            .unwrap();
        assert!(matches!(flow, Flow::Continue));
        assert!(host_out.starts_with(b"\x1b]10;?\x1b\\"));
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
        let (other_tx, other_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut other_input = InputReader::from_channel(other_rx);
        other_tx
            .send(
                b"\x1b]10;rgb:2222/2222/2222\x07\x1b]11;rgb:dddd/dddd/dddd\x07\x1b[?62;22c"
                    .to_vec(),
            )
            .unwrap();
        drop(other_tx);
        let mut other_out = Vec::new();
        let flow = attached
            .refresh_theme(&mut other_out, &mut other_input, &mut ctrl)
            .await
            .unwrap();
        assert!(matches!(flow, Flow::Continue));
        assert_eq!(attached.theme.background.as_deref(), Some("#dddddd"));

        // Typing in the terminal claims the block back, with this terminal's
        // size and colors.
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(in_rx);
        in_tx.send(b" -l".to_vec()).unwrap();
        in_tx.send(b"a\n".to_vec()).unwrap();
        let flow = attached.burst(b"ls", &mut input, &mut ctrl).await.unwrap();
        assert!(matches!(flow, Flow::Continue));
        assert!(attached.owns);
        finish_write(&mut attached.write_inflight).await.unwrap();
        attached.pump_write(&mut ctrl).unwrap();
        assert!(attached.write_inflight.is_none());

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
            .burst(b"\x1c", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(detach_flow, Flow::Detach { double: false });

        let double_same_read = attached
            .burst(b"\x1c\x1c", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(double_same_read, Flow::Detach { double: true });

        let (queued_tx, queued_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut queued_input = InputReader::from_channel(queued_rx);
        queued_tx.send(b"\x1b[92;5u".to_vec()).unwrap();
        let double_queued = attached
            .burst(b"\x1c", &mut queued_input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(double_queued, Flow::Detach { double: true });
        assert!(queued_input.is_empty());

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

        detach(&mut ctrl, &mut attached).await;
        let (wrote, theme_calls, take_calls) = server.await.unwrap();
        assert_eq!(wrote, "ls -la\n");
        // Attach, a scheme change while owning, the claim on typing, and the
        // block coming back from the other client.
        assert_eq!(theme_calls, 4);
        // Attach and the claim on typing; the other client's claim does not
        // make zrex claim back.
        assert_eq!(take_calls, 2);
    }

    #[test]
    fn chunks_writes_on_utf8_boundaries() {
        let mut queue = "hi🦀ok".to_owned();
        assert_eq!(take_write_chunk(&mut queue, 4), "hi");
        assert_eq!(queue, "🦀ok");
        assert_eq!(take_write_chunk(&mut queue, 2), "🦀");
        assert_eq!(queue, "ok");
        assert_eq!(take_write_chunk(&mut queue, 10), "ok");
        assert!(queue.is_empty());
    }

    #[tokio::test]
    async fn serializes_terminal_writes_and_coalesces_split_bracketed_paste() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel::<()>();
        let (saw_first_tx, saw_first_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (ctrl_tcp, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
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
                #[allow(
                    clippy::result_large_err,
                    reason = "tungstenite fixes the callback error type"
                )]
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

            let mut writes = Vec::new();
            let mut saw_first_tx = Some(saw_first_tx);
            let mut release_first_rx = Some(release_first_rx);
            while let Some(Ok(Message::Text(text))) = ctrl_ws.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap_or("");
                let method = req["method"].as_str().unwrap();
                if method == "block.event" {
                    continue;
                }
                if method == "com.superlogical.terminal.write" {
                    let data = req["payload"]["args"]["data"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned();
                    writes.push(data.clone());
                    if writes.len() == 1 {
                        if let Some(tx) = saw_first_tx.take() {
                            let _ = tx.send(());
                        }
                        if let Some(rx) = release_first_rx.take() {
                            let _ = rx.await;
                        }
                    }
                    ctrl_ws
                        .send(Message::Text(
                            json!({
                                "type": "response",
                                "id": id,
                                "payload": {"bytes_written": data.len()}
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
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
                    "data.connect" => json!({
                        "ticket": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16])
                    }),
                    _ => json!({}),
                };
                ctrl_ws
                    .send(Message::Text(
                        json!({"type": "response", "id": id, "payload": result})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                if method == "session.detach" {
                    break;
                }
            }
            let _data_ws = data_task.await.unwrap();
            writes
        });

        let address = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Selectors(None, None),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();

        let (_in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(in_rx);
        // Simulate a terminal like foot emitting bracketed paste across
        // separate reads: ESC[200~, body, ESC[201~.
        attached
            .burst(b"\x1b[200~", &mut input, &mut ctrl)
            .await
            .unwrap();
        saw_first_rx.await.unwrap();
        assert!(attached.write_inflight.is_some());

        // While the first write is still in flight, later chunks must queue
        // locally instead of racing concurrently on the server.
        attached
            .burst(b"pasted text", &mut input, &mut ctrl)
            .await
            .unwrap();
        attached
            .burst(b"\x1b[201~", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(attached.write_queue, "pasted text\x1b[201~");

        // Completing the first write flushes the coalesced remainder in order.
        release_first_tx.send(()).unwrap();
        finish_write(&mut attached.write_inflight).await.unwrap();
        attached.pump_write(&mut ctrl).unwrap();
        assert!(attached.write_queue.is_empty());
        assert!(attached.write_inflight.is_some());

        finish_write(&mut attached.write_inflight).await.unwrap();
        attached.pump_write(&mut ctrl).unwrap();
        assert!(attached.write_inflight.is_none());

        detach(&mut ctrl, &mut attached).await;
        let writes = server.await.unwrap();
        assert_eq!(writes, vec!["\x1b[200~", "pasted text\x1b[201~"]);
    }

    #[tokio::test]
    async fn detach_drains_inflight_coalesced_writes_and_batched_prefix_before_detaching() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel::<()>();
        let (saw_first_tx, saw_first_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (ctrl_tcp, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
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
                #[allow(
                    clippy::result_large_err,
                    reason = "tungstenite fixes the callback error type"
                )]
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

            let mut order = Vec::new();
            let mut saw_first_tx = Some(saw_first_tx);
            let mut release_first_rx = Some(release_first_rx);
            while let Some(Ok(Message::Text(text))) = ctrl_ws.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap_or("");
                let method = req["method"].as_str().unwrap();
                if method == "block.event" {
                    continue;
                }
                if method == "com.superlogical.terminal.write" {
                    let data = req["payload"]["args"]["data"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned();
                    order.push(format!("write:{data}"));
                    if order.len() == 1 {
                        if let Some(tx) = saw_first_tx.take() {
                            let _ = tx.send(());
                        }
                        if let Some(rx) = release_first_rx.take() {
                            let _ = rx.await;
                        }
                    }
                    ctrl_ws
                        .send(Message::Text(
                            json!({
                                "type": "response",
                                "id": id,
                                "payload": {"bytes_written": data.len()}
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
                    continue;
                }
                if method == "session.detach" {
                    order.push("detach".to_owned());
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
                    "data.connect" => json!({
                        "ticket": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16])
                    }),
                    _ => json!({}),
                };
                ctrl_ws
                    .send(Message::Text(
                        json!({"type": "response", "id": id, "payload": result})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                if method == "session.detach" {
                    break;
                }
            }
            let _data_ws = data_task.await.unwrap();
            order
        });

        let address = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Selectors(None, None),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();

        let (_in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(in_rx);
        attached
            .burst(b"first-", &mut input, &mut ctrl)
            .await
            .unwrap();
        saw_first_rx.await.unwrap();

        // While the first write is in flight, the user types more text batched
        // with Ctrl-\ in the same read.
        let flow = attached
            .burst(b"second\x1b[?\x1cignored", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(flow, Flow::Detach { double: false });

        release_first_tx.send(()).unwrap();
        detach(&mut ctrl, &mut attached).await;
        let order = server.await.unwrap();
        assert_eq!(order, vec!["write:first-", "write:second\x1b[?", "detach"]);
    }

    #[tokio::test]
    async fn read_chunks_enforces_deadline_size_cap_and_progress() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    #[allow(
                        clippy::result_large_err,
                        reason = "tungstenite fixes the callback error type"
                    )]
                    let mut ws = tokio_tungstenite::accept_hdr_async(
                        stream,
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
                    let _ = ws.next().await;
                    ws.send(Message::Text(
                        json!({"type": "welcome", "api_revision": 8})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();

                    while let Some(Ok(Message::Text(text))) = ws.next().await {
                        let req: Value = serde_json::from_str(&text).unwrap();
                        let id = req["id"].as_str().unwrap();
                        let blob_id = req["payload"]["args"]["id"].as_i64().unwrap();
                        let payload = match blob_id {
                            1 => json!({"data": "123456", "eof": false}),
                            2 => json!({"data": "", "eof": false}),
                            3 => {
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                json!({"data": "late", "eof": true})
                            }
                            _ => json!({"data": "ok", "eof": true}),
                        };
                        let _ = ws
                            .send(Message::Text(
                                json!({"type": "response", "id": id, "payload": payload})
                                    .to_string()
                                    .into(),
                            ))
                            .await;
                    }
                });
            }
        });

        let address = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
        let block = BlockRef::new("session:1", "block:1");

        // 1. Size cap exceeded.
        let err = read_chunks_with_limits(
            &mut ctrl,
            block,
            "com.superlogical.terminal.blob_read",
            1,
            String::new(),
            tokio::time::Instant::now() + Duration::from_secs(2),
            10,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("maximum size"));

        // 2. Empty non-EOF chunk fails instead of looping forever.
        let err = read_chunks_with_limits(
            &mut ctrl,
            block,
            "com.superlogical.terminal.blob_read",
            2,
            String::new(),
            tokio::time::Instant::now() + Duration::from_secs(2),
            1024,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("empty chunk"));

        // 3. Wedged server hits deadline with CallTimeout, which transient() recognizes.
        let err = read_chunks_with_limits(
            &mut ctrl,
            block,
            "com.superlogical.terminal.blob_read",
            3,
            String::new(),
            tokio::time::Instant::now() + Duration::from_millis(40),
            1024,
        )
        .await
        .unwrap_err();
        assert!(err.downcast_ref::<CallTimeout>().is_some());
        assert!(transient(&ctrl, &err));
    }

    #[test]
    fn detects_write_target_gone_errors() {
        for (code, status) in [
            ("unknown", 404),
            ("not_found", 404),
            ("not_found", 400),
            ("block_not_found", 400),
            ("session_not_found", 400),
            ("block_closed", 410),
        ] {
            let err = anyhow::Error::new(ApiError {
                code: code.to_owned(),
                message: "gone".to_owned(),
                status,
            });
            assert!(write_target_gone(&err), "expected gone for {code} {status}");
        }

        for (code, status) in [("conflict", 409), ("internal", 500), ("forbidden", 403)] {
            let err = anyhow::Error::new(ApiError {
                code: code.to_owned(),
                message: "other".to_owned(),
                status,
            });
            assert!(
                !write_target_gone(&err),
                "expected not gone for {code} {status}"
            );
        }

        assert!(!write_target_gone(&anyhow::anyhow!(
            "the control connection ended"
        )));
        assert!(!write_target_gone(&anyhow::Error::new(StreamClosed {
            code: Some(4000),
            reason: String::new(),
        })));
    }

    #[tokio::test]
    async fn ignores_write_target_gone_until_block_closed_arrives() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (ctrl_tcp, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
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
                #[allow(
                    clippy::result_large_err,
                    reason = "tungstenite fixes the callback error type"
                )]
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

            while let Some(Ok(Message::Text(text))) = ctrl_ws.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap_or("");
                let method = req["method"].as_str().unwrap();
                if method == "block.event" {
                    continue;
                }
                if method == "com.superlogical.terminal.write" {
                    ctrl_ws
                        .send(Message::Text(
                            json!({
                                "type": "response",
                                "id": id,
                                "error": {
                                    "code": "block_not_found",
                                    "message": "block already closed",
                                    "status": 404
                                }
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
                    ctrl_ws
                        .send(Message::Text(
                            json!({
                                "type": "event",
                                "payload": {
                                    "type": "session_event",
                                    "payload": {
                                        "session_id": "session:1",
                                        "event": {
                                            "type": "block_closed",
                                            "payload": {"block_id": "block:1"}
                                        }
                                    }
                                }
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
                    break;
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
                    "data.connect" => json!({
                        "ticket": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16])
                    }),
                    _ => json!({}),
                };
                ctrl_ws
                    .send(Message::Text(
                        json!({"type": "response", "id": id, "payload": result})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
            }
            let _data_ws = data_task.await.unwrap();
        });

        let address = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, mut events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Selectors(None, None),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();

        let (_in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(in_rx);
        attached.burst(b"a", &mut input, &mut ctrl).await.unwrap();
        attached.write_queue.push_str("queued");

        let err = finish_write(&mut attached.write_inflight)
            .await
            .unwrap_err();
        assert!(write_target_gone(&err));
        attached.write_queue.clear();
        assert!(attached.write_queue.is_empty());

        let (name, payload) = events.recv().await.unwrap();
        let ending = attached.event(&name, &payload, &mut ctrl).await.unwrap();
        assert!(matches!(ending, Some(Ending::Block)));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn finish_write_times_out_with_call_timeout_and_clears_inflight() {
        let (_tx, rx) = tokio::sync::oneshot::channel::<anyhow::Result<Value>>();
        let mut inflight = Some(InflightWrite {
            rx,
            deadline: tokio::time::Instant::now() + Duration::from_millis(30),
        });
        let err = finish_write(&mut inflight).await.unwrap_err();
        assert!(inflight.is_none());
        assert!(err.downcast_ref::<CallTimeout>().is_some());
    }

    async fn spawn_simple_attach_server()
    -> (String, tokio::task::JoinHandle<(Vec<String>, Vec<Value>)>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (ctrl_tcp, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
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
                #[allow(
                    clippy::result_large_err,
                    reason = "tungstenite fixes the callback error type"
                )]
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

            let mut writes = Vec::new();
            let mut themes = Vec::new();
            while let Some(Ok(Message::Text(text))) = ctrl_ws.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap_or("");
                let method = req["method"].as_str().unwrap();
                if method == "block.event" {
                    continue;
                }
                if method == "com.superlogical.terminal.write" {
                    let data = req["payload"]["args"]["data"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned();
                    writes.push(data.clone());
                    ctrl_ws
                        .send(Message::Text(
                            json!({
                                "type": "response",
                                "id": id,
                                "payload": {"bytes_written": data.len()}
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
                    continue;
                }
                if method == "com.superlogical.terminal.set_theme" {
                    themes.push(req["payload"]["args"].clone());
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
                    "data.connect" => json!({
                        "ticket": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16])
                    }),
                    _ => json!({}),
                };
                ctrl_ws
                    .send(Message::Text(
                        json!({"type": "response", "id": id, "payload": result})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                if method == "session.detach" {
                    break;
                }
            }
            let _data_ws = data_task.await.unwrap();
            (writes, themes)
        });

        (format!("http://{addr}"), server)
    }

    #[test]
    fn replies_strips_mixed_konsole_st_bel_and_scheme_stream_across_arbitrary_chunk_sizes() {
        let mut expected_replies = Vec::new();
        expected_replies.extend_from_slice(
            b"\x1b]10;rgb:cdcd/d6d6/f4f4\x1b\\\x1b]11;rgb:1e1e/1e1e/2e2e\x1b\\\x1b[?997;1n",
        );
        for index in 0..PALETTE_LEN {
            expected_replies
                .extend_from_slice(format!("\x1b]4;{index};rgb:afaf/d7d7/5f5f\x07").as_bytes());
        }
        expected_replies.extend_from_slice(b"\x1b[?1;2c");

        let mut stream = expected_replies.clone();
        stream.push(0x04); // User presses Ctrl-D right behind the replies.

        for chunk_size in [1, 2, 3, 5, 7, 13, 29, 64, 1024] {
            let mut replies = Replies::default();
            replies.hold_probe(Vec::new(), true);
            let mut found = Vec::new();
            let mut typed = Vec::new();
            for chunk in stream.chunks(chunk_size) {
                let (r, t) = replies.push(chunk);
                found.extend_from_slice(&r);
                typed.extend_from_slice(&t);
            }
            assert_eq!(
                typed, b"\x04",
                "only Ctrl-D should reach PTY for chunk size {chunk_size}"
            );
            assert_eq!(
                found, expected_replies,
                "all host replies must be captured for chunk size {chunk_size}"
            );
            assert!(
                replies.due().is_none(),
                "no trailing fragment should remain for chunk size {chunk_size}"
            );
        }
    }

    #[test]
    fn probe_theme_with_stops_after_unresponsive_batch_zero_and_keeps_completed_batches() {
        use std::io::{Read, Write};

        // 1) Silent terminal: only batch 0 is sent, returns within idle timeout.
        let (mut in_rd, _in_wr) = std::io::pipe().unwrap();
        let mut out = Vec::new();
        let start = std::time::Instant::now();
        let probed = probe_theme_with(
            &mut out,
            &mut in_rd,
            Duration::from_millis(25),
            Duration::from_millis(200),
        );
        assert!(start.elapsed() < Duration::from_millis(120));
        assert!(!probed.da1_seen);
        assert!(probed.tail.is_empty());
        assert!(probed.theme.is_empty());
        assert_eq!(out, theme_query_batches(true)[0].as_bytes());

        // 2) Terminal answers batches 0 and 1, then cuts off mid-batch 2 before `5f\x07`.
        // Batch 3 must not be sent, batches 0..2's 128 colors are preserved, and
        // batch 2's partial tail is returned for Replies reassembly.
        let (mut query_rd, mut query_wr) = std::io::pipe().unwrap();
        let (mut reply_rd, mut reply_wr) = std::io::pipe().unwrap();
        let batches = theme_query_batches(true);
        let terminal = std::thread::spawn(move || {
            let mut read_buf = [0u8; 4096];
            for (batch_idx, expected) in batches.iter().take(3).enumerate() {
                let mut got = Vec::new();
                while got.len() < expected.len() {
                    let n = query_rd.read(&mut read_buf).unwrap();
                    assert!(n > 0);
                    got.extend_from_slice(&read_buf[..n]);
                }
                assert_eq!(got, expected.as_bytes());

                let mut resp = Vec::new();
                if batch_idx == 0 {
                    resp.extend_from_slice(b"\x1b]11;rgb:1e1e/1e1e/2e2e\x1b\\");
                }
                if batch_idx < 2 {
                    let start = batch_idx * PALETTE_BATCH;
                    let end = start + PALETTE_BATCH;
                    for index in start..end {
                        resp.extend_from_slice(
                            format!("\x1b]4;{index};rgb:0000/0000/5f5f\x07").as_bytes(),
                        );
                    }
                    resp.extend_from_slice(b"\x1b[?1;2c");
                    reply_wr.write_all(&resp).unwrap();
                } else {
                    reply_wr.write_all(b"\x1b]4;149;rgb:afaf/d7d7/5f").unwrap();
                    std::thread::sleep(Duration::from_millis(80));
                }
            }
            // Verify batch 3 was never sent.
            let mut extra = [0u8; 64];
            let n = query_rd.read(&mut extra).unwrap();
            assert_eq!(
                n, 0,
                "batch 3 should not be written after batch 2 timed out"
            );
        });

        let probed = probe_theme_with(
            &mut query_wr,
            &mut reply_rd,
            Duration::from_millis(25),
            Duration::from_millis(250),
        );
        drop(query_wr);
        terminal.join().unwrap();
        assert!(!probed.da1_seen);
        assert_eq!(probed.theme.background.as_deref(), Some("#1e1e2e"));
        assert_eq!(probed.theme.palette.len(), PALETTE_BATCH * 2);
        assert_eq!(probed.tail, b"\x1b]4;149;rgb:afaf/d7d7/5f");
    }

    #[test]
    fn probe_theme_with_recovers_cleanly_on_reattach_after_abandoned_probe_tail() {
        use std::io::{Read, Write};

        // Simulate detach -> reattach on the same stdin pipe: leftover `5f\x07`
        // and stale DA1 from an interrupted earlier attach sit in stdin when
        // the new attach probe begins.
        let (mut query_rd, mut query_wr) = std::io::pipe().unwrap();
        let (mut reply_rd, mut reply_wr) = std::io::pipe().unwrap();
        reply_wr.write_all(b"5f\x07\x1b[?1;2c").unwrap();

        let batches = theme_query_batches(true);
        let terminal = std::thread::spawn(move || {
            let mut read_buf = [0u8; 4096];
            for (batch_idx, expected) in batches.iter().enumerate() {
                let mut got = Vec::new();
                while got.len() < expected.len() {
                    let n = query_rd.read(&mut read_buf).unwrap();
                    assert!(n > 0);
                    got.extend_from_slice(&read_buf[..n]);
                }
                assert_eq!(got, expected.as_bytes());
                let mut resp = Vec::new();
                let start = batch_idx * PALETTE_BATCH;
                let end = (start + PALETTE_BATCH).min(PALETTE_LEN);
                for index in start..end {
                    resp.extend_from_slice(
                        format!("\x1b]4;{index};rgb:1111/2222/5f5f\x07").as_bytes(),
                    );
                }
                resp.extend_from_slice(b"\x1b[?1;2c");
                reply_wr.write_all(&resp).unwrap();
            }
        });

        let probed = probe_theme_with(
            &mut query_wr,
            &mut reply_rd,
            Duration::from_millis(100),
            Duration::from_millis(500),
        );
        drop(query_wr);
        terminal.join().unwrap();
        assert!(probed.da1_seen);
        assert!(probed.tail.is_empty());
        assert_eq!(probed.theme.palette.len(), PALETTE_LEN);
    }

    #[tokio::test]
    async fn attached_probe_tail_survives_slow_reattach_and_never_leaks_5f_bel_on_ctrl_d() {
        let (addr, server) = spawn_simple_attach_server().await;
        let address = addr.parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Selectors(None, None),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();

        // Startup probe cut off right before `5f\x07`, followed by a simulated
        // Tailscale RTT longer than REPLY_HOLD (50ms).
        attached
            .replies
            .hold_probe(b"\x1b]4;149;rgb:afaf/d7d7/5f".to_vec(), true);
        tokio::time::sleep(REPLY_HOLD + Duration::from_millis(30)).await;
        assert!(
            attached.replies.due().unwrap() > std::time::Instant::now(),
            "definite reply fragment must still be held past REPLY_HOLD"
        );

        // Late Konsole continuation arrives right before the user's Ctrl-D.
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(in_rx);
        in_tx.send(b"\x1b[?1;2c\x04".to_vec()).unwrap();
        let flow = attached
            .burst(b"5f\x07", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(flow, Flow::Continue);

        // Even if flush_held fires on a definite truncated fragment, nothing
        // is written to the remote PTY and a subsequent split reply is still caught.
        attached
            .replies
            .hold_probe(b"\x1b]4;150;rgb:afaf/d7d7/5f".to_vec(), true);
        assert_eq!(
            attached.flush_held(&mut input, &mut ctrl).await.unwrap(),
            Flow::Continue
        );
        let flow = attached
            .burst(b"\x1b", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(flow, Flow::Continue);
        let flow = attached
            .burst(b"]4;151;rgb:afaf/d7d7/5f5f\x07", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(flow, Flow::Continue);

        // A real user Escape keypress after a reply burst is still forwarded on stall.
        let flow = attached
            .burst(b"\x1b", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(flow, Flow::Continue);
        assert_eq!(
            attached.flush_held(&mut input, &mut ctrl).await.unwrap(),
            Flow::Continue
        );

        detach(&mut ctrl, &mut attached).await;
        let (writes, _) = server.await.unwrap();
        assert_eq!(writes.concat(), "\x04\x1b");
    }

    #[tokio::test]
    async fn refresh_theme_paces_all_batches_without_leaking_split_bel_and_preserves_typing() {
        use std::io::Read;

        let (addr, server) = spawn_simple_attach_server().await;
        let address = addr.parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Selectors(None, None),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();

        let (mut query_rd, mut query_wr) = std::io::pipe().unwrap();
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(in_rx);

        let expected_batches = theme_query_batches(false);
        let terminal = std::thread::spawn(move || {
            let mut read_buf = [0u8; 4096];
            for (batch_idx, expected) in expected_batches.iter().enumerate() {
                let mut got = Vec::new();
                while got.len() < expected.len() {
                    let n = query_rd.read(&mut read_buf).unwrap();
                    assert!(n > 0);
                    got.extend_from_slice(&read_buf[..n]);
                }
                assert_eq!(
                    got,
                    expected.as_bytes(),
                    "refresh batch {batch_idx} mismatch"
                );

                let mut resp = Vec::new();
                if batch_idx == 0 {
                    resp.extend_from_slice(
                        b"\x1b]10;rgb:1111/1111/1111\x1b\\\x1b]11;rgb:f0f0/f0f0/f0f0\x1b\\",
                    );
                }
                let start = batch_idx * PALETTE_BATCH;
                let end = (start + PALETTE_BATCH).min(PALETTE_LEN);
                for index in start..end {
                    resp.extend_from_slice(
                        format!("\x1b]4;{index};rgb:afaf/d7d7/5f5f\x07").as_bytes(),
                    );
                }
                resp.extend_from_slice(b"\x1b[?1;2c");
                // Split right before `5f\x07` on batch 2 and interleave user Ctrl-D after DA1.
                if batch_idx == 2 {
                    let cut = resp.windows(4).position(|w| w == b"5f5f").unwrap() + 2;
                    in_tx.send(resp[..cut].to_vec()).unwrap();
                    in_tx.send(resp[cut..].to_vec()).unwrap();
                    in_tx.send(b"\x04".to_vec()).unwrap();
                } else {
                    in_tx.send(resp).unwrap();
                }
            }
        });

        let flow = attached
            .refresh_theme(&mut query_wr, &mut input, &mut ctrl)
            .await
            .unwrap();
        drop(query_wr);
        terminal.join().unwrap();
        assert_eq!(flow, Flow::Continue);
        assert_eq!(attached.theme.background.as_deref(), Some("#f0f0f0"));
        assert_eq!(attached.theme.scheme.as_deref(), Some("light"));
        assert_eq!(attached.theme.palette.len(), PALETTE_LEN);

        // Drain any remaining queued input (the interleaved Ctrl-D).
        while let Some(bytes) = input.try_recv() {
            let flow = attached.burst(&bytes, &mut input, &mut ctrl).await.unwrap();
            assert_eq!(flow, Flow::Continue);
        }

        detach(&mut ctrl, &mut attached).await;
        let (writes, themes) = server.await.unwrap();
        assert_eq!(writes.concat(), "\x04");
        assert_eq!(themes.len(), 1);
        assert_eq!(themes[0]["scheme"], "light");
        assert_eq!(themes[0]["palette"].as_array().unwrap().len(), PALETTE_LEN);
    }

    #[tokio::test]
    async fn refresh_theme_detach_mid_osc_drops_partial_reply_and_keeps_typed_prefix() {
        let (addr, server) = spawn_simple_attach_server().await;
        let address = addr.parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Selectors(None, None),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();

        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(in_rx);
        // User types "ok", a Konsole OSC 4 reply gets cut off before `5f\x07`,
        // and the user hits Ctrl-\ in the same read.
        in_tx
            .send(b"ok\x1b]4;149;rgb:afaf/d7d7/5f\x1c".to_vec())
            .unwrap();

        let mut out = Vec::new();
        let flow = attached
            .refresh_theme(&mut out, &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(flow, Flow::Detach { double: false });

        detach(&mut ctrl, &mut attached).await;
        let (writes, _) = server.await.unwrap();
        assert_eq!(writes.concat(), "ok");
    }

    #[test]
    fn recognizes_custom_detach_keys_and_alt_passthrough_sequences() {
        let default_key = DetachKey::default();
        // Legacy, Kitty CSI-u, and xterm modifyOtherKeys Alt-Ctrl-\ map to PassThrough(0x1c)
        // and are never misclassified as detach.
        for seq in [
            b"\x1b\x1c".as_slice(),
            b"\x1b[92;7u".as_slice(),
            b"\x1b[92;7:1u".as_slice(),
            b"\x1b[92;7:2u".as_slice(),
            b"\x1b[92:124;7u".as_slice(),
            b"\x1b[27;7;92~".as_slice(),
        ] {
            assert_eq!(
                find_next_key_action(seq, default_key),
                Some((0, seq.len(), KeyAction::PassThrough(0x1c))),
                "expected pass-through for {seq:?}"
            );
            assert!(!contains_detach_for(seq, default_key));
        }
        // Kitty release event for Alt-Ctrl-\ is consumed without forwarding.
        assert_eq!(
            find_next_key_action(b"\x1b[92;7:3u", default_key),
            Some((0, 9, KeyAction::Ignore))
        );
        // Kitty release event for Ctrl-\ does not detach.
        assert_eq!(find_next_key_action(b"\x1b[92;5:3u", default_key), None);
        // Detach followed by Alt-Ctrl-\ is not a double-detach.
        assert_eq!(
            split_at_detach_for(b"\x1c\x1b\x1c", default_key),
            (b"".as_slice(), Some(b"\x1b\x1c".as_slice()))
        );
        assert!(!contains_detach_for(b"\x1b\x1c", default_key));

        // Custom detach key: Ctrl-] (0x1d). Ctrl-\ passes untouched.
        let ctrl_rbracket = DetachKey::Ctrl(0x1d);
        assert_eq!(find_next_key_action(b"\x1c", ctrl_rbracket), None);
        assert_eq!(
            find_next_key_action(b"\x1d", ctrl_rbracket),
            Some((0, 1, KeyAction::Detach))
        );
        assert_eq!(
            find_next_key_action(b"\x1b[93;5u", ctrl_rbracket),
            Some((0, 7, KeyAction::Detach))
        );
        assert_eq!(
            find_next_key_action(b"\x1b\x1d", ctrl_rbracket),
            Some((0, 2, KeyAction::PassThrough(0x1d)))
        );
        assert_eq!(
            find_next_key_action(b"\x1b[93;7u", ctrl_rbracket),
            Some((0, 7, KeyAction::PassThrough(0x1d)))
        );
        assert_eq!(
            find_next_key_action(b"\x1b[27;7;93~", ctrl_rbracket),
            Some((0, 10, KeyAction::PassThrough(0x1d)))
        );

        // Shifted symbol detach keys like Ctrl-^ (0x1e) match both Ctrl-^ and Ctrl-Shift-6.
        let ctrl_caret = DetachKey::Ctrl(0x1e);
        assert_eq!(
            find_next_key_action(b"\x1b[54:94;6u", ctrl_caret),
            Some((0, 10, KeyAction::Detach))
        );
        assert_eq!(
            find_next_key_action(b"\x1b[54:94;8u", ctrl_caret),
            Some((0, 10, KeyAction::PassThrough(0x1e)))
        );

        // DetachKey::None disables both detach and Alt pass-through.
        assert_eq!(find_next_key_action(b"\x1c\x1b\x1c", DetachKey::None), None);
    }

    #[tokio::test]
    async fn forwards_literal_ctrl_backslash_on_alt_ctrl_backslash_and_respects_custom_key() {
        let (addr, server) = spawn_simple_attach_server().await;
        let address = addr.parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Selectors(None, None),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();

        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(rx);

        // Legacy Alt-Ctrl-\, Kitty Alt-Ctrl-\ (press + release), and xterm modifyOtherKeys
        // all forward a single literal 0x1c each without detaching.
        let flow = attached
            .burst(
                b"a\x1b\x1cb\x1b[92;7:1u\x1b[92;7:3uc\x1b[27;7;92~d",
                &mut input,
                &mut ctrl,
            )
            .await
            .unwrap();
        assert_eq!(flow, Flow::Continue);

        // With detach_key = ctrl-], raw Ctrl-\ passes straight through to the remote block.
        attached.detach_key = DetachKey::Ctrl(0x1d);
        let flow = attached
            .burst(b"\x1c", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(flow, Flow::Continue);

        // With detach_key = ctrl-g (BEL), BEL-terminated OSC replies are still stripped
        // instead of falsely detaching.
        attached.detach_key = DetachKey::Ctrl(0x07);
        let flow = attached
            .burst(b"\x1b]4;0;rgb:0000/0000/0000\x07ok", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(flow, Flow::Continue);

        // Alt-Ctrl-G followed by Ctrl-G forwards 0x07 and detaches.
        let flow = attached
            .burst(b"\x1b\x07\x07", &mut input, &mut ctrl)
            .await
            .unwrap();
        assert_eq!(flow, Flow::Detach { double: false });

        detach(&mut ctrl, &mut attached).await;
        let (writes, _) = server.await.unwrap();
        assert_eq!(writes.concat(), "a\x1cb\x1cc\x1cd\x1cok\x07");
    }

    #[test]
    fn reset_modes_clears_kitty_keyboard_on_both_screens_and_foot_modes() {
        let reset = std::str::from_utf8(RESET_MODES).unwrap();
        assert!(reset.starts_with('\x18'));
        assert!(reset.contains("\x1b[?2048l"));
        assert!(reset.contains("\x1b[?1016l"));
        assert!(reset.contains("\x1b[?1049l\x1b[?1047l\x1b[?47l"));

        let leave_alt = reset.find("\x1b[?1049l").unwrap();
        let first_kitty = reset.find("\x1b[<99u\x1b[=0u").unwrap();
        let last_kitty = reset.rfind("\x1b[<99u\x1b[=0u").unwrap();
        assert!(first_kitty < leave_alt);
        assert!(last_kitty > leave_alt);
    }

    #[test]
    fn strips_decrpm_and_kitty_keyboard_query_replies() {
        let mixed = b"hi\x1b[?2026;2$y\x1b[?0u!";
        let (replies, typed) = split_replies(mixed);
        assert_eq!(replies, b"\x1b[?2026;2$y\x1b[?0u");
        assert_eq!(typed, b"hi!");

        let mut stateful = Replies::default();
        let (r1, t1) = stateful.push(b"\x1b[?2026;2$");
        assert!(r1.is_empty());
        assert!(t1.is_empty());
        let (r2, t2) = stateful.push(b"yok");
        assert_eq!(r2, b"\x1b[?2026;2$y");
        assert_eq!(t2, b"ok");
    }

    #[test]
    fn drain_after_reset_consumes_inflight_osc_and_stale_da1_until_dsr_reply() {
        use std::io::{Read, Write};

        let (mut query_rd, mut query_wr) = std::io::pipe().unwrap();
        let (mut reply_rd, mut reply_wr) = std::io::pipe().unwrap();

        let terminal = std::thread::spawn(move || {
            let mut expected = Vec::new();
            expected.extend_from_slice(RESET_MODES);
            expected.extend_from_slice(DSR_STATUS_QUERY);
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            while got.len() < expected.len() {
                let n = query_rd.read(&mut buf).unwrap();
                assert!(n > 0);
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, expected);

            // Simulate delayed SSH OSC 4 + stale DA1 from an earlier probe arriving
            // before the DSR 5 sentinel reply, plus a queued second Ctrl-\.
            reply_wr
                .write_all(b"\x1b]4;12;rgb:1111/2222/3333\x1b\\\x1b[?62;22c")
                .unwrap();
            std::thread::sleep(Duration::from_millis(10));
            reply_wr.write_all(b"\x1c").unwrap();
            reply_wr.write_all(DSR_STATUS_REPLY).unwrap();
        });

        let saw_detach = drain_after_reset_with(
            &mut query_wr,
            &mut reply_rd,
            DetachKey::default(),
            true,
            Duration::from_millis(200),
            Duration::from_millis(500),
        )
        .unwrap();
        terminal.join().unwrap();
        assert!(saw_detach);

        // When wait_for_dsr is false (e.g. terminal never answered queries), only RESET_MODES
        // is written and drain returns immediately without sending CSI 5 n.
        let mut out = Vec::new();
        let (mut dummy_rd, _dummy_wr) = std::io::pipe().unwrap();
        let saw_detach = drain_after_reset_with(
            &mut out,
            &mut dummy_rd,
            DetachKey::default(),
            false,
            Duration::from_millis(200),
            Duration::from_millis(500),
        )
        .unwrap();
        assert!(!saw_detach);
        assert_eq!(out, RESET_MODES);
    }

    #[tokio::test]
    async fn recover_detaches_immediately_during_hung_reconnect_attempt() {
        use super::{Recovered, recover};

        // First accept the initial attach, then accept subsequent TCP connections
        // and intentionally never respond (simulating a rebooting/black-holed host).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            // 1. Control connection for initial attach.
            let (stream, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
            let mut ws =
                tokio_tungstenite::accept_hdr_async(stream, |req: &Request, mut res: Response| {
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
                json!({"type": "welcome", "api_revision": crate::rex::proto::API_REVISION})
                    .to_string(),
            ))
            .await
            .unwrap();
            let (ctrl_done_tx, ctrl_done_rx) = tokio::sync::oneshot::channel::<()>();
            let ctrl_task = tokio::spawn(async move {
                let ticket_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([5u8; 16]);
                let mut done_tx = Some(ctrl_done_tx);
                while let Some(Ok(Message::Text(text))) = ws.next().await {
                    let req: Value = serde_json::from_str(&text).unwrap();
                    let id = req["id"].as_str().unwrap();
                    let payload = match req["method"].as_str().unwrap() {
                        "session.bootstrap" => json!({
                            "client_id": "client:1",
                            "selected_session": {
                                "session_id": "session:1",
                                "label": "work",
                                "view": {
                                    "active_window_id": "window:1",
                                    "windows": [{
                                        "window_id": "window:1",
                                        "label": "shell",
                                        "focused_block_id": "block:1",
                                        "layers": [{"blocks": [{"block_id": "block:1", "label": "shell"}]}]
                                    }]
                                }
                            }
                        }),
                        "data.connect" => json!({"ticket": ticket_b64}),
                        _ => json!({"ok": true}),
                    };
                    ws.send(Message::text(
                        json!({"type": "response", "id": id, "seq": 0, "payload": payload})
                            .to_string(),
                    ))
                    .await
                    .unwrap();
                    if req["method"].as_str() == Some("block.event") {
                        if let Some(tx) = done_tx.take() {
                            let _ = tx.send(());
                        }
                        break;
                    }
                }
                drop(ws);
            });

            // 2. Data connection for initial attach.
            let (dstream, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
            let mut dws =
                tokio_tungstenite::accept_hdr_async(dstream, |req: &Request, mut res: Response| {
                    if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                        res.headers_mut()
                            .insert("Sec-WebSocket-Protocol", proto.clone());
                    }
                    Ok(res)
                })
                .await
                .unwrap();
            let _ = dws.next().await;
            let mut welcome = vec![0x81u8];
            welcome.extend_from_slice(&[9u8; 16]);
            welcome.extend_from_slice(&[0u8; 7]);
            welcome.extend_from_slice(&42u64.to_le_bytes());
            dws.send(Message::Binary(welcome.into())).await.unwrap();
            dws.send(Message::Binary(snapshot_header().into()))
                .await
                .unwrap();

            // Wait for initial attach focus event, then drop initial sockets and
            // black-hole all subsequent TCP connections without answering.
            let _ = ctrl_done_rx.await;
            let _ = ctrl_task.await;
            drop(dws);
            let mut held = Vec::new();
            while let Ok((hung, _)) = listener.accept().await {
                held.push(hung);
            }
        });

        let address: crate::rex::ServerAddress = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, mut events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:1",
            &address,
            BlockSelection::Exact("block:1"),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();

        // Wait until the dropped control socket is detected, then enter recover()
        // while the server black-holes the reconnect TCP socket.
        assert!(events.recv().await.is_none());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(rx);
        let mut token = ctrl.reconnect_token.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Non-detach input is ignored without aborting recovery.
            let _ = tx.send(b"hello".to_vec());
            tokio::time::sleep(Duration::from_millis(30)).await;
            // Pressing Ctrl-\ detaches immediately even while reconnect is hung.
            let _ = tx.send(b"\x1c".to_vec());
        });

        let started = std::time::Instant::now();
        let recovered = recover(
            &mut token,
            &mut ctrl,
            &mut events,
            &mut attached,
            &mut input,
        )
        .await
        .unwrap();
        assert_eq!(recovered, Recovered::Detach { double: false });
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "detach waited {:?} during hung reconnect",
            started.elapsed()
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn recover_ends_session_when_restarted_server_lacks_original_session() {
        use super::{Recovered, recover};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            // Initial control + data setup.
            let (stream, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
            let mut ws =
                tokio_tungstenite::accept_hdr_async(stream, |req: &Request, mut res: Response| {
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
                json!({"type": "welcome", "api_revision": crate::rex::proto::API_REVISION})
                    .to_string(),
            ))
            .await
            .unwrap();
            let (ctrl_done_tx, ctrl_done_rx) = tokio::sync::oneshot::channel::<()>();
            let ctrl_task = tokio::spawn(async move {
                let ticket_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([6u8; 16]);
                let mut done_tx = Some(ctrl_done_tx);
                while let Some(Ok(Message::Text(text))) = ws.next().await {
                    let req: Value = serde_json::from_str(&text).unwrap();
                    let id = req["id"].as_str().unwrap();
                    let payload = match req["method"].as_str().unwrap() {
                        "session.bootstrap" => json!({
                            "client_id": "client:1",
                            "selected_session": {
                                "session_id": "session:old",
                                "label": "work",
                                "view": {
                                    "active_window_id": "window:1",
                                    "windows": [{
                                        "window_id": "window:1",
                                        "label": "shell",
                                        "focused_block_id": "block:1",
                                        "layers": [{"blocks": [{"block_id": "block:1", "label": "shell"}]}]
                                    }]
                                }
                            }
                        }),
                        "data.connect" => json!({"ticket": ticket_b64}),
                        _ => json!({"ok": true}),
                    };
                    ws.send(Message::text(
                        json!({"type": "response", "id": id, "seq": 0, "payload": payload})
                            .to_string(),
                    ))
                    .await
                    .unwrap();
                    if req["method"].as_str() == Some("block.event") {
                        if let Some(tx) = done_tx.take() {
                            let _ = tx.send(());
                        }
                        break;
                    }
                }
                drop(ws);
            });
            let (dstream, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
            let mut dws =
                tokio_tungstenite::accept_hdr_async(dstream, |req: &Request, mut res: Response| {
                    if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                        res.headers_mut()
                            .insert("Sec-WebSocket-Protocol", proto.clone());
                    }
                    Ok(res)
                })
                .await
                .unwrap();
            let _ = dws.next().await;
            let mut welcome = vec![0x81u8];
            welcome.extend_from_slice(&[9u8; 16]);
            welcome.extend_from_slice(&[0u8; 7]);
            welcome.extend_from_slice(&42u64.to_le_bytes());
            dws.send(Message::Binary(welcome.into())).await.unwrap();
            let _ = ctrl_done_rx.await;
            let _ = ctrl_task.await;
            drop(dws);

            // Reconnect after "reboot": server only has a different session now.
            let (stream2, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
            let mut ws2 =
                tokio_tungstenite::accept_hdr_async(stream2, |req: &Request, mut res: Response| {
                    if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                        res.headers_mut()
                            .insert("Sec-WebSocket-Protocol", proto.clone());
                    }
                    Ok(res)
                })
                .await
                .unwrap();
            let _ = ws2.next().await;
            ws2.send(Message::text(
                json!({"type": "welcome", "api_revision": crate::rex::proto::API_REVISION})
                    .to_string(),
            ))
            .await
            .unwrap();
            if let Some(Ok(Message::Text(text))) = ws2.next().await {
                let req: Value = serde_json::from_str(&text).unwrap();
                let id = req["id"].as_str().unwrap();
                ws2.send(Message::text(
                    json!({
                        "type": "response",
                        "id": id,
                        "seq": 0,
                        "payload": {
                            "client_id": "client:2",
                            "selected_session": {
                                "session_id": "session:brand-new",
                                "label": "fresh",
                                "view": {"windows": []}
                            }
                        }
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            }
        });

        let address: crate::rex::ServerAddress = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, mut events) = Control::connect(&address, None).await.unwrap();
        let mut attached = Attached::start(
            &mut ctrl,
            "session:old",
            &address,
            BlockSelection::Exact("block:1"),
            (80, 24),
            Theme::default(),
        )
        .await
        .unwrap();
        assert!(events.recv().await.is_none());

        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(rx);
        let mut token = ctrl.reconnect_token.clone();
        let recovered = recover(
            &mut token,
            &mut ctrl,
            &mut events,
            &mut attached,
            &mut input,
        )
        .await
        .unwrap();
        assert_eq!(recovered, Recovered::Ended(Ending::Session));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn input_reader_buffers_typing_during_live_rpc_and_interrupts_on_detach_or_cancel() {
        use super::{Interruptible, PreAttachOutcome};

        // 1. Live RPC: non-detach keystrokes are buffered in order while awaiting.
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut input = InputReader::from_channel(rx);
        tx.send(b"ab".to_vec()).unwrap();
        tx.send(b"cd".to_vec()).unwrap();
        let res = input
            .await_or_detach(DetachKey::default(), false, async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                42
            })
            .await;
        assert!(matches!(res, Interruptible::Done(42)));
        assert_eq!(input.recv().await, Some(b"ab".to_vec()));
        assert_eq!(input.recv().await, Some(b"cd".to_vec()));

        // 2. Live RPC hung on a dead link: detach key interrupts immediately.
        tx.send(b"x\x1c\x1c".to_vec()).unwrap();
        let res = input
            .await_or_detach(DetachKey::default(), false, std::future::pending::<()>())
            .await;
        assert!(matches!(res, Interruptible::Detach { double: true }));

        // 3. Pre-attach connect hung: Ctrl-\ cancels back to picker, Ctrl-C quits.
        tx.send(b"\x1c".to_vec()).unwrap();
        let res = input
            .await_or_cancel(DetachKey::default(), std::future::pending::<()>())
            .await;
        assert!(matches!(res, PreAttachOutcome::Cancelled { quit: false }));

        tx.send(b"\x03".to_vec()).unwrap();
        let res = input
            .await_or_cancel(DetachKey::default(), std::future::pending::<()>())
            .await;
        assert!(matches!(res, PreAttachOutcome::Cancelled { quit: true }));
    }

    #[tokio::test]
    async fn finish_inflight_times_out_with_call_timeout_and_clears_inflight() {
        use super::{InflightCall, finish_inflight};

        let (_tx, rx) = tokio::sync::oneshot::channel();
        let mut inflight = Some(InflightCall {
            method: "server.version",
            timeout: Duration::from_millis(20),
            rx,
            deadline: tokio::time::Instant::now() + Duration::from_millis(20),
        });
        let err = finish_inflight(&mut inflight).await.unwrap_err();
        assert!(inflight.is_none());
        assert!(err.downcast_ref::<CallTimeout>().is_some());
    }
}

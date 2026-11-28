use std::collections::HashMap;
use std::fmt;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use super::proto::{self, Incoming};
use super::{
    BlockRef, CONNECT_TIME, DEFAULT_LOOPBACK_ADDR, LOCAL_PROBE_TIME, ServerAddress, Socket,
    format_timeout, frame_with_timeout, local_socket_candidates,
};

pub const SUBPROTOCOL: &str = "rex.control.v1";

/// Upper bound on control RPCs so a connected-but-wedged server never hangs
/// attach or CLI commands indefinitely.
pub const CALL_TIME: Duration = CONNECT_TIME;

#[derive(Debug)]
pub struct CallTimeout(pub String);

impl fmt::Display for CallTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CallTimeout {}

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<Result<Value>>>>>;

pub struct Control {
    out: mpsc::UnboundedSender<Message>,
    pending: Pending,
    alive: Arc<AtomicBool>,
    reader: JoinHandle<()>,
    next_id: u64,
    pub reconnect_token: Option<String>,
}

pub type Events = mpsc::UnboundedReceiver<(String, Value)>;

impl Drop for Control {
    fn drop(&mut self) {
        // Release the reader's pong sender so the writer can finish after
        // draining queued messages, even if the server leaves its socket open.
        self.reader.abort();
    }
}

impl Control {
    pub async fn connect(
        server: &ServerAddress,
        reconnect_token: Option<&str>,
    ) -> Result<(Self, Events)> {
        let socket = server.open("/api/control", SUBPROTOCOL).await?;
        Self::handshake(socket, reconnect_token, CONNECT_TIME).await
    }

    pub async fn connect_once(
        server: &ServerAddress,
        reconnect_token: Option<&str>,
        timeout: Duration,
    ) -> Result<(Self, Events)> {
        let socket = server
            .endpoint("/api/control")
            .open_once(SUBPROTOCOL, timeout)
            .await?;
        Self::handshake(socket, reconnect_token, timeout).await
    }

    pub async fn connect_local_if_running(
        exclude: &[ServerAddress],
    ) -> Option<(ServerAddress, Self, Events)> {
        Self::connect_local_in(local_socket_candidates(), DEFAULT_LOOPBACK_ADDR, exclude).await
    }

    pub(super) async fn connect_local_in(
        candidates: impl IntoIterator<Item = PathBuf>,
        loopback: &str,
        exclude: &[ServerAddress],
    ) -> Option<(ServerAddress, Self, Events)> {
        for path in candidates {
            if !path.metadata().is_ok_and(|m| m.file_type().is_socket()) {
                continue;
            }
            let address = ServerAddress::Unix(path);
            if exclude.contains(&address) {
                // This local socket is already configured explicitly; do not
                // fall through to loopback TCP and risk listing the same local
                // server twice.
                return None;
            }
            if let Ok((ctrl, events)) = Self::connect_once(&address, None, LOCAL_PROBE_TIME).await {
                return Some((address, ctrl, events));
            }
        }
        let loopback = ServerAddress::Network(format!("ws://{loopback}"));
        if !exclude.contains(&loopback)
            && let Ok((ctrl, events)) = Self::connect_once(&loopback, None, LOCAL_PROBE_TIME).await
        {
            return Some((loopback, ctrl, events));
        }
        None
    }

    async fn handshake(
        mut socket: Socket,
        reconnect_token: Option<&str>,
        timeout: Duration,
    ) -> Result<(Self, Events)> {
        let hello = serde_json::to_string(&proto::hello(reconnect_token))?;
        tokio::time::timeout(timeout, socket.send(Message::text(hello)))
            .await
            .map_err(|_| {
                anyhow!(
                    "the server took no hello within {}",
                    format_timeout(timeout)
                )
            })??;

        let Some(message) = frame_with_timeout(&mut socket, "a welcome", timeout).await? else {
            bail!("the server closed the connection before the welcome");
        };
        let text = match message {
            Message::Text(text) => text,
            other => bail!("the server sent {other:?} instead of a welcome"),
        };
        let Incoming::Welcome(welcome) = serde_json::from_str::<Incoming>(&text)? else {
            bail!("the server's first message was not a welcome");
        };
        let revision = welcome.api_revision.unwrap_or(0);
        if revision < proto::API_REVISION {
            bail!(
                "the server speaks API revision {revision}, and zrex needs {}",
                proto::API_REVISION
            );
        }
        let reconnect_token = welcome
            .client
            .as_ref()
            .map(|client| client.reconnect_token.clone());

        let (mut sink, mut stream) = socket.split();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
        let (events_tx, events_rx) = mpsc::unbounded_channel();

        let writer_pending = Arc::clone(&pending);
        let writer_alive = Arc::clone(&alive);
        tokio::spawn(async move {
            while let Some(first) = out_rx.recv().await {
                if sink.feed(first).await.is_err() {
                    mark_dead_and_fail(
                        &writer_alive,
                        &writer_pending,
                        "the control connection closed",
                    );
                    break;
                }
                while let Ok(next) = out_rx.try_recv() {
                    if sink.feed(next).await.is_err() {
                        mark_dead_and_fail(
                            &writer_alive,
                            &writer_pending,
                            "the control connection closed",
                        );
                        return;
                    }
                }
                if sink.flush().await.is_err() {
                    mark_dead_and_fail(
                        &writer_alive,
                        &writer_pending,
                        "the control connection closed",
                    );
                    break;
                }
            }
        });

        let reader_pending = Arc::clone(&pending);
        let reader_alive = Arc::clone(&alive);
        let pong_tx = out_tx.clone();
        let reader = tokio::spawn(async move {
            let _mark = MarkDead(Arc::clone(&reader_alive));
            while let Some(message) = stream.next().await {
                let message = match message {
                    Ok(message) => message,
                    Err(error) => {
                        mark_dead_and_fail(&reader_alive, &reader_pending, &error.to_string());
                        break;
                    }
                };
                let parsed = match message {
                    Message::Text(text) => serde_json::from_str::<Incoming>(&text).ok(),
                    Message::Binary(bytes) => serde_json::from_slice::<Incoming>(&bytes).ok(),
                    Message::Ping(data) => {
                        let _ = pong_tx.send(Message::Pong(data));
                        None
                    }
                    Message::Close(_) => {
                        mark_dead_and_fail(
                            &reader_alive,
                            &reader_pending,
                            "the server closed the connection",
                        );
                        break;
                    }
                    _ => None,
                };
                match parsed {
                    Some(Incoming::Response {
                        id, payload, error, ..
                    }) => {
                        let waiter = reader_pending.lock().unwrap().remove(&id);
                        if let Some(waiter) = waiter {
                            let result = match error {
                                Some(error) => Err(anyhow::Error::new(error)),
                                None => Ok(payload),
                            };
                            let _ = waiter.send(result);
                        }
                    }
                    Some(Incoming::Event { payload }) => {
                        if let Some(event) = proto::unwrap_event(&payload) {
                            let _ = events_tx.send(event);
                        }
                    }
                    Some(Incoming::Welcome(_)) | Some(Incoming::Unknown) | None => {}
                }
            }
            mark_dead_and_fail(
                &reader_alive,
                &reader_pending,
                "the control connection ended",
            );
        });

        Ok((
            Self {
                out: out_tx,
                pending,
                alive,
                reader,
                next_id: 0,
                reconnect_token,
            },
            events_rx,
        ))
    }

    pub async fn call(&mut self, method: &str, payload: Value) -> Result<Value> {
        self.call_with_timeout(method, payload, CALL_TIME).await
    }

    pub async fn call_with_timeout(
        &mut self,
        method: &str,
        payload: Value,
        timeout: Duration,
    ) -> Result<Value> {
        let (id, rx) = self.start_call_with_id(method, payload)?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(received) => {
                received.map_err(|_| anyhow!("the control connection ended during {method}"))?
            }
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(anyhow::Error::new(CallTimeout(format!(
                    "the server did not answer {method} within {}",
                    format_timeout(timeout)
                ))))
            }
        }
    }

    pub fn start_call(
        &mut self,
        method: &str,
        payload: Value,
    ) -> Result<oneshot::Receiver<Result<Value>>> {
        let (_, rx) = self.start_call_with_id(method, payload)?;
        Ok(rx)
    }

    fn start_call_with_id(
        &mut self,
        method: &str,
        payload: Value,
    ) -> Result<(String, oneshot::Receiver<Result<Value>>)> {
        let id = self.next_request_id()?;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id.clone(), tx);
        if let Err(error) = self.send_request(&id, method, payload) {
            self.pending.lock().unwrap().remove(&id);
            return Err(error);
        }
        Ok((id, rx))
    }

    /// Fire-and-forget send for server-ordered methods such as `block.event`.
    /// Block methods like `com.superlogical.terminal.write` run concurrently on
    /// the server and must use `start_write` instead so writes stay ordered.
    pub fn post(&mut self, method: &str, payload: Value) -> Result<()> {
        let id = self.next_request_id()?;
        self.send_request(&id, method, payload)
    }

    fn next_request_id(&mut self) -> Result<String> {
        if !self.alive.load(Ordering::SeqCst) {
            bail!("the control connection is closed");
        }
        self.next_id += 1;
        Ok(self.next_id.to_string())
    }

    fn send_request(&self, id: &str, method: &str, payload: Value) -> Result<()> {
        let message = serde_json::to_string(&proto::request(id, method, payload))?;
        self.out.send(Message::text(message)).map_err(|_| {
            self.alive.store(false, Ordering::SeqCst);
            anyhow!("the control connection is closed")
        })
    }

    /// Starts a `com.superlogical.terminal.write` call and returns its reply
    /// channel. Rex runs block methods concurrently, so callers must wait for
    /// this reply before sending the next write to preserve input ordering.
    pub fn start_write(
        &mut self,
        block: BlockRef<'_>,
        data: &str,
    ) -> Result<oneshot::Receiver<Result<Value>>> {
        self.start_call(
            "com.superlogical.terminal.write",
            serde_json::json!({
                "session_id": block.session_id,
                "block_id": block.block_id,
                "args": { "data": data },
            }),
        )
    }

    pub fn post_event(&mut self, block: BlockRef<'_>, event: Value) -> Result<()> {
        self.post(
            "block.event",
            serde_json::json!({
                "session_id": block.session_id,
                "block_id": block.block_id,
                "event": event,
            }),
        )
    }

    pub fn is_lost(&self) -> bool {
        !self.alive.load(Ordering::SeqCst)
    }
}

/// Marks the connection dead when the reader task stops, so that calls fail
/// instead of waiting for a response that cannot come.
struct MarkDead(Arc<AtomicBool>);

impl Drop for MarkDead {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn mark_dead_and_fail(alive: &AtomicBool, pending: &Pending, reason: &str) {
    alive.store(false, Ordering::SeqCst);
    for (_, waiter) in pending.lock().unwrap().drain() {
        let _ = waiter.send(Err(anyhow!("{reason}")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    #[tokio::test]
    async fn connects_calls_methods_and_receives_events() {
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

            let Some(Ok(Message::Text(hello_text))) = ws.next().await else {
                panic!("expected hello");
            };
            let hello: Value = serde_json::from_str(&hello_text).unwrap();
            assert_eq!(hello["type"], "hello");
            assert_eq!(hello["reconnect_token"], "prev-tok");

            ws.send(Message::text(
                json!({
                    "type": "welcome",
                    "api_revision": proto::API_REVISION,
                    "client": {"reconnect_token": "next-tok"}
                })
                .to_string(),
            ))
            .await
            .unwrap();

            ws.send(Message::text(
                json!({
                    "type": "event",
                    "seq": 1,
                    "payload": {
                        "type": "session_destroyed",
                        "payload": {"session_id": "session:1"}
                    }
                })
                .to_string(),
            ))
            .await
            .unwrap();

            ws.send(Message::Ping(b"keepalive".to_vec().into()))
                .await
                .unwrap();
            let mut saw_pong = false;
            let req_text = loop {
                match ws.next().await {
                    Some(Ok(Message::Pong(data))) => {
                        if data.as_ref() == b"keepalive" {
                            saw_pong = true;
                        }
                    }
                    Some(Ok(Message::Text(text))) => break text,
                    other => panic!("unexpected frame: {other:?}"),
                }
            };
            assert!(saw_pong);
            let req: Value = serde_json::from_str(&req_text).unwrap();
            assert_eq!(req["method"], "server.version");
            ws.send(Message::text(
                json!({
                    "type": "response",
                    "id": req["id"],
                    "seq": 1,
                    "payload": {"version": "1.0"}
                })
                .to_string(),
            ))
            .await
            .unwrap();
        });

        let server = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, mut events) = Control::connect(&server, Some("prev-tok")).await.unwrap();
        assert_eq!(ctrl.reconnect_token.as_deref(), Some("next-tok"));

        let (name, _payload) = events.recv().await.unwrap();
        assert_eq!(name, "session_destroyed");

        let reply = ctrl.call("server.version", Value::Null).await.unwrap();
        assert_eq!(reply["version"], "1.0");
    }

    #[tokio::test]
    async fn connect_once_connects_and_rejects_unreachable_without_retrying() {
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

            let Some(Ok(Message::Text(_))) = ws.next().await else {
                panic!("expected hello");
            };
            ws.send(Message::text(
                json!({
                    "type": "welcome",
                    "api_revision": proto::API_REVISION,
                })
                .to_string(),
            ))
            .await
            .unwrap();
            // Keep socket open until client drops.
            let _ = ws.next().await;
        });

        let server: ServerAddress = format!("http://{addr}").parse().unwrap();
        let (ctrl, _events) = Control::connect_once(&server, None, Duration::from_secs(1))
            .await
            .unwrap();
        drop(ctrl);

        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr: ServerAddress = format!("http://{}", dead.local_addr().unwrap())
            .parse()
            .unwrap();
        drop(dead);
        assert!(
            Control::connect_once(&dead_addr, None, Duration::from_millis(200))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn call_with_timeout_fails_with_call_timeout_when_server_stays_silent() {
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
                json!({"type": "welcome", "api_revision": proto::API_REVISION}).to_string(),
            ))
            .await
            .unwrap();
            // Read request and intentionally never reply.
            let _ = ws.next().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let server: ServerAddress = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&server, None).await.unwrap();
        let err = ctrl
            .call_with_timeout("server.version", Value::Null, Duration::from_millis(40))
            .await
            .unwrap_err();
        assert!(err.downcast_ref::<CallTimeout>().is_some());
        assert!(ctrl.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn marks_control_lost_before_failing_pending_calls_on_close() {
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
                json!({"type": "welcome", "api_revision": proto::API_REVISION}).to_string(),
            ))
            .await
            .unwrap();
            // Read request and immediately drop the connection without replying.
            let _ = ws.next().await;
            let _ = ws.close(None).await;
        });

        let server: ServerAddress = format!("http://{addr}").parse().unwrap();
        let (mut ctrl, _events) = Control::connect(&server, None).await.unwrap();
        let err = ctrl.call("server.version", Value::Null).await.unwrap_err();
        assert!(
            ctrl.is_lost(),
            "expected is_lost() to be true on error: {err:#}"
        );
    }
}

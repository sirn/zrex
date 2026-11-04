use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

use super::proto::{self, Incoming};
use super::{CONNECT_TIME, control_url, frame, open};

pub const SUBPROTOCOL: &str = "rex.control.v1";

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<Result<Value>>>>>;

pub struct Control {
    out: mpsc::UnboundedSender<Message>,
    pending: Pending,
    alive: Arc<AtomicBool>,
    next_id: u64,
    pub reconnect_token: Option<String>,
}

pub type Events = mpsc::UnboundedReceiver<(String, Value)>;

impl Control {
    pub async fn connect(server: &str, reconnect_token: Option<&str>) -> Result<(Self, Events)> {
        let url = control_url(server)?;
        let mut socket = open(&url, SUBPROTOCOL).await?;

        let hello = serde_json::to_string(&proto::hello(reconnect_token))?;
        tokio::time::timeout(CONNECT_TIME, socket.send(Message::text(hello)))
            .await
            .map_err(|_| {
                anyhow!(
                    "the server took no hello within {}s",
                    CONNECT_TIME.as_secs()
                )
            })??;

        let Some(message) = frame(&mut socket, "a welcome").await? else {
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

        tokio::spawn(async move {
            while let Some(first) = out_rx.recv().await {
                if sink.feed(first).await.is_err() {
                    break;
                }
                while let Ok(next) = out_rx.try_recv() {
                    if sink.feed(next).await.is_err() {
                        return;
                    }
                }
                if sink.flush().await.is_err() {
                    break;
                }
            }
        });

        let reader_pending = Arc::clone(&pending);
        let reader_alive = Arc::clone(&alive);
        let pong_tx = out_tx.clone();
        tokio::spawn(async move {
            let _mark = MarkDead(reader_alive);
            while let Some(message) = stream.next().await {
                let message = match message {
                    Ok(message) => message,
                    Err(error) => {
                        fail_all(&reader_pending, &error.to_string());
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
                        fail_all(&reader_pending, "the server closed the connection");
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
            fail_all(&reader_pending, "the control connection ended");
        });

        Ok((
            Self {
                out: out_tx,
                pending,
                alive,
                next_id: 0,
                reconnect_token,
            },
            events_rx,
        ))
    }

    pub async fn call(&mut self, method: &str, payload: Value) -> Result<Value> {
        let rx = self.start_call(method, payload)?;
        rx.await
            .map_err(|_| anyhow!("the control connection ended during {method}"))?
    }

    pub fn start_call(
        &mut self,
        method: &str,
        payload: Value,
    ) -> Result<oneshot::Receiver<Result<Value>>> {
        let id = self.next_request_id()?;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id.clone(), tx);
        if let Err(error) = self.send_request(&id, method, payload) {
            self.pending.lock().unwrap().remove(&id);
            return Err(error);
        }
        Ok(rx)
    }

    /// Calls travel in order on one connection, so fire-and-forget writes stay
    /// ordered without waiting a round-trip per key.
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
        self.out
            .send(Message::text(message))
            .map_err(|_| anyhow!("the control connection is closed"))
    }

    pub fn post_write(&mut self, session_id: &str, block_id: &str, data: &str) -> Result<()> {
        self.post(
            "com.superlogical.terminal.write",
            serde_json::json!({
                "session_id": session_id,
                "block_id": block_id,
                "args": { "data": data },
            }),
        )
    }

    pub fn post_event(&mut self, session_id: &str, block_id: &str, event: Value) -> Result<()> {
        self.post(
            "block.event",
            serde_json::json!({
                "session_id": session_id,
                "block_id": block_id,
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

fn fail_all(pending: &Pending, reason: &str) {
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

        let server = format!("http://{addr}");
        let (mut ctrl, mut events) = Control::connect(&server, Some("prev-tok")).await.unwrap();
        assert_eq!(ctrl.reconnect_token.as_deref(), Some("next-tok"));

        let (name, _payload) = events.recv().await.unwrap();
        assert_eq!(name, "session_destroyed");

        let reply = ctrl.call("server.version", Value::Null).await.unwrap();
        assert_eq!(reply["version"], "1.0");
    }
}

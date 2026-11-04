use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::{CONNECT_TIME, data_url, frame, open as open_socket};

pub const SUBPROTOCOL: &str = "rex.data.terminal.v1";

const HELLO: u8 = 0x01;
const RESUME: u8 = 0x02;
const WELCOME: u8 = 0x81;
const REJECT: u8 = 0x82;

#[derive(Debug)]
pub struct StreamClosed {
    pub code: Option<u16>,
    pub reason: String,
}

impl StreamClosed {
    /// Status 4000 means the block closed on the server, so reconnecting cannot
    /// bring it back.
    pub fn is_block_closed(&self) -> bool {
        self.code == Some(4000) || self.reason.trim() == "block closed"
    }
}

impl std::fmt::Display for StreamClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(code) => write!(f, "the stream closed ({code}: {})", self.reason),
            None => write!(f, "the stream closed"),
        }
    }
}

impl std::error::Error for StreamClosed {}

pub struct Data {
    chunks: mpsc::UnboundedReceiver<Result<Vec<u8>>>,
    pub nonce: u64,
    pub token: [u8; 16],
    pub received: u64,
}

impl Data {
    pub async fn open(server: &str, ticket: &str) -> Result<Self> {
        Self::connect(server, encode_hello(ticket)?).await
    }

    pub async fn resume(server: &str, token: [u8; 16], received: u64) -> Result<Self> {
        Self::connect(server, encode_resume(token, received)).await
    }

    async fn connect(server: &str, handshake: Vec<u8>) -> Result<Self> {
        let url = data_url(server)?;
        let mut ws = open_socket(&url, SUBPROTOCOL).await?;
        tokio::time::timeout(CONNECT_TIME, ws.send(Message::Binary(handshake.into())))
            .await
            .map_err(|_| {
                anyhow!(
                    "the server took no data hello within {}s",
                    CONNECT_TIME.as_secs()
                )
            })??;

        let Some(message) = frame(&mut ws, "a data handshake").await? else {
            bail!("the server closed the data connection during the handshake");
        };
        let bytes = match message {
            Message::Binary(bytes) => bytes,
            other => bail!("the server sent {other:?} during the data handshake"),
        };
        let (nonce, token) = decode_handshake(&bytes)?;

        let (chunks_tx, chunks_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                match ws.next().await {
                    Some(Ok(Message::Binary(bytes))) => {
                        if chunks_tx.send(Ok(bytes.to_vec())).is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Close(frame))) => {
                        let closed = StreamClosed {
                            code: frame.as_ref().map(|frame| u16::from(frame.code)),
                            reason: frame
                                .as_ref()
                                .map(|frame| frame.reason.to_string())
                                .unwrap_or_default(),
                        };
                        let _ = chunks_tx.send(Err(closed.into()));
                        return;
                    }
                    Some(Ok(Message::Ping(_))) => {
                        if ws.flush().await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(error)) => {
                        let _ = chunks_tx.send(Err(error.into()));
                        return;
                    }
                    None => {
                        let _ = chunks_tx.send(Err(anyhow!("the data connection ended")));
                        return;
                    }
                }
            }
        });

        Ok(Self {
            chunks: chunks_rx,
            nonce,
            token,
            received: 0,
        })
    }

    pub async fn next_chunk(&mut self) -> Option<Result<Vec<u8>>> {
        let chunk = self.chunks.recv().await?;
        Some(self.record_chunk(chunk))
    }

    pub fn try_next_chunk(&mut self) -> Option<Result<Vec<u8>>> {
        let chunk = self.chunks.try_recv().ok()?;
        Some(self.record_chunk(chunk))
    }

    fn record_chunk(&mut self, chunk: Result<Vec<u8>>) -> Result<Vec<u8>> {
        match chunk {
            Ok(bytes) => {
                self.received += bytes.len() as u64;
                Ok(bytes)
            }
            Err(error) => Err(error),
        }
    }
}

fn encode_hello(ticket: &str) -> Result<Vec<u8>> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(ticket)?;
    if raw.len() != 16 {
        bail!("the data ticket is {} bytes, not 16", raw.len());
    }
    let mut hello = Vec::with_capacity(17);
    hello.push(HELLO);
    hello.extend_from_slice(&raw);
    Ok(hello)
}

fn encode_resume(token: [u8; 16], received: u64) -> Vec<u8> {
    let mut message = Vec::with_capacity(25);
    message.push(RESUME);
    message.extend_from_slice(&token);
    message.extend_from_slice(&received.to_le_bytes());
    message
}

fn decode_handshake(bytes: &[u8]) -> Result<(u64, [u8; 16])> {
    match bytes.first().copied() {
        Some(WELCOME) if bytes.len() >= 32 => {
            let mut token = [0u8; 16];
            token.copy_from_slice(&bytes[1..17]);
            // 0x81, the token, three zero bytes, the expiry in ms, then
            // the channel nonce.
            let nonce = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
            Ok((nonce, token))
        }
        Some(REJECT) => {
            let reason = bytes.get(1).copied().unwrap_or(0);
            bail!("the server rejected the data connection: {reason:#04x}")
        }
        _ => bail!("the server sent an unknown data handshake"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    #[tokio::test]
    async fn opens_and_resumes_data_stream() {
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
            let Some(Ok(Message::Binary(hello))) = ws.next().await else {
                panic!("expected binary hello");
            };
            assert_eq!(hello.len(), 17);
            assert_eq!(hello[0], HELLO);

            let mut welcome = vec![WELCOME];
            welcome.extend_from_slice(&[7u8; 16]);
            welcome.extend_from_slice(&[0u8; 7]);
            welcome.extend_from_slice(&12345u64.to_le_bytes());
            ws.send(Message::Binary(welcome.into())).await.unwrap();
            ws.send(Message::Binary(b"hello ".to_vec().into()))
                .await
                .unwrap();

            let (stream2, _) = listener.accept().await.unwrap();
            let mut ws2 = accept_hdr_async(stream2, |req: &Request, mut res: Response| {
                if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                    res.headers_mut()
                        .insert("Sec-WebSocket-Protocol", proto.clone());
                }
                Ok(res)
            })
            .await
            .unwrap();
            let Some(Ok(Message::Binary(resume))) = ws2.next().await else {
                panic!("expected binary resume");
            };
            assert_eq!(resume.len(), 25);
            assert_eq!(resume[0], RESUME);
            assert_eq!(&resume[1..17], &[7u8; 16]);
            assert_eq!(u64::from_le_bytes(resume[17..25].try_into().unwrap()), 6);

            let mut welcome2 = vec![WELCOME];
            welcome2.extend_from_slice(&[8u8; 16]);
            welcome2.extend_from_slice(&[0u8; 7]);
            welcome2.extend_from_slice(&12345u64.to_le_bytes());
            ws2.send(Message::Binary(welcome2.into())).await.unwrap();
            ws2.send(Message::Close(Some(CloseFrame {
                code: CloseCode::Library(4000),
                reason: "block closed".into(),
            })))
            .await
            .unwrap();
        });

        let server = format!("http://{addr}");
        let ticket = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 16]);
        let mut data = Data::open(&server, &ticket).await.unwrap();
        assert_eq!(data.nonce, 12345);
        assert_eq!(data.token, [7u8; 16]);

        let chunk = data.next_chunk().await.unwrap().unwrap();
        assert_eq!(chunk, b"hello ");
        assert_eq!(data.received, 6);

        let mut resumed = Data::resume(&server, data.token, data.received)
            .await
            .unwrap();
        assert_eq!(resumed.token, [8u8; 16]);
        let err = resumed.next_chunk().await.unwrap().unwrap_err();
        let closed = err.downcast_ref::<StreamClosed>().unwrap();
        assert_eq!(closed.code, Some(4000));
        assert_eq!(closed.reason, "block closed");
    }
}

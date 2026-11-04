use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use futures_util::StreamExt;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};

pub mod control;
pub mod data;
pub mod proto;
pub mod stream;

pub type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A network can drop packets without telling either end, so every handshake
/// step has a timeout.
pub const CONNECT_TIME: Duration = Duration::from_secs(10);

const OPEN_TRIES: u32 = 3;

pub fn control_url(server: &str) -> Result<String> {
    endpoint(server, "/api/control")
}

pub fn data_url(server: &str) -> Result<String> {
    endpoint(server, "/api/data")
}

fn endpoint(server: &str, path: &str) -> Result<String> {
    let (scheme, rest) = match server.split_once("://") {
        Some((scheme, rest)) => (scheme.to_lowercase(), rest.trim_end_matches('/')),
        None => ("http".to_owned(), server.trim_end_matches('/')),
    };
    if rest.is_empty() {
        bail!("no server address");
    }
    let scheme = match scheme.as_str() {
        "https" | "wss" => "wss",
        "http" | "ws" => "ws",
        other => bail!("unknown server scheme {other}"),
    };
    Ok(format!("{scheme}://{rest}{path}"))
}

/// Retry initial socket opens here because mobile links often drop the first
/// SYN or TLS packet.
pub async fn open(url: &str, protocol: &'static str) -> Result<Socket> {
    let mut last = None;
    for try_number in 1..=OPEN_TRIES {
        if try_number > 1 {
            tokio::time::sleep(Duration::from_millis(200 * u64::from(try_number))).await;
        }
        match try_open(url, protocol).await {
            Ok(socket) => return Ok(socket),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("could not reach {url}")))
}

async fn try_open(url: &str, protocol: &'static str) -> Result<Socket> {
    let mut request = url.into_client_request()?;
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", HeaderValue::from_static(protocol));
    let (socket, _response) =
        tokio::time::timeout(CONNECT_TIME, connect_async_with_config(request, None, true))
            .await
            .map_err(|_| anyhow!("{url} did not answer within {}s", CONNECT_TIME.as_secs()))??;
    Ok(socket)
}

pub async fn frame(
    socket: &mut (
             impl futures_util::Stream<Item = tokio_tungstenite::tungstenite::Result<Message>> + Unpin
         ),
    what: &str,
) -> Result<Option<Message>> {
    match tokio::time::timeout(CONNECT_TIME, socket.next()).await {
        Ok(Some(frame)) => Ok(Some(frame?)),
        Ok(None) => Ok(None),
        Err(_) => bail!(
            "the server sent no {what} within {}s",
            CONNECT_TIME.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_control_and_data_urls() {
        assert_eq!(
            control_url("http://127.0.0.1:7297/").unwrap(),
            "ws://127.0.0.1:7297/api/control"
        );
        assert_eq!(
            data_url("https://example.com/").unwrap(),
            "wss://example.com/api/data"
        );
        assert_eq!(
            control_url("127.0.0.1:7297").unwrap(),
            "ws://127.0.0.1:7297/api/control"
        );
        assert_eq!(
            data_url("wss://example.com").unwrap(),
            "wss://example.com/api/data"
        );
        assert!(control_url("").is_err());
        assert!(control_url("ftp://example.com").is_err());
    }
}

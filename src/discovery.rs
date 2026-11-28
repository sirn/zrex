use anyhow::{Context, Result, anyhow, bail};
use futures_util::future::join_all;
use tokio::time::{Instant, timeout_at};

use crate::config::Server;
use crate::rex::{ServerAddress, control::Control};
use crate::text::clean_one_line;

pub const NO_SERVER_FOUND: &str = "no Rex server found; start a local Rex server, pass --server / set REX_SERVER, or configure ~/.config/zrex/config.toml";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalDiscovery {
    None,
    Optional,
    Required,
}

pub struct FanOutOutcome<T> {
    pub entries: Vec<(Server, Result<T>)>,
    pub local_error: Option<String>,
}

pub async fn probe_local(
    mode: LocalDiscovery,
    excluded: &[ServerAddress],
) -> Result<Option<(ServerAddress, Control)>> {
    match mode {
        LocalDiscovery::None => Ok(None),
        LocalDiscovery::Optional => Ok(Control::connect_local_if_running(excluded)
            .await
            .map(|(address, ctrl, _events)| (address, ctrl))),
        LocalDiscovery::Required => match Control::connect_local_if_running(&[]).await {
            Some((address, ctrl, _events)) => Ok(Some((address, ctrl))),
            None => bail!("local: server is not running"),
        },
    }
}

/// Probes the local server in parallel with saved servers, deduplicating by
/// normalized server address so a local server already listed in `servers` is
/// queried only once under its saved name.
pub async fn fan_out<T, P, F, Fut>(
    servers: Vec<Server>,
    local_mode: LocalDiscovery,
    local_probe: P,
    deadline: Instant,
    timeout_context: &'static str,
    query: F,
) -> FanOutOutcome<T>
where
    P: AsyncFnOnce(&[ServerAddress]) -> Result<Option<(ServerAddress, Control)>>,
    F: Fn(Server, Control, Instant) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let query = &query;
    let saved_addresses: Vec<ServerAddress> = servers
        .iter()
        .map(|server| server.address.clone())
        .collect();

    let local_future = async {
        if local_mode == LocalDiscovery::None {
            return Ok(None);
        }
        let found = timeout_at(deadline, local_probe(&saved_addresses))
            .await
            .map_err(|_| anyhow!("local server detection timed out"))??;
        let Some((address, ctrl)) = found else {
            return match local_mode {
                LocalDiscovery::Optional => Ok(None),
                LocalDiscovery::Required => bail!("local: server is not running"),
                LocalDiscovery::None => unreachable!(),
            };
        };
        if saved_addresses.contains(&address) {
            return Ok(None);
        }
        let server = Server {
            name: "local".to_owned(),
            address,
        };
        let result = query(server.clone(), ctrl, deadline).await;
        Ok::<_, anyhow::Error>(Some((server, result)))
    };

    let saved_future = join_all(servers.iter().cloned().map(|server| async move {
        let ctrl = match timeout_at(deadline, Control::connect(&server.address, None))
            .await
            .context(timeout_context)
        {
            Ok(Ok((ctrl, _events))) => ctrl,
            Ok(Err(error)) | Err(error) => return Err(error),
        };
        query(server, ctrl, deadline).await
    }));

    let (local_outcome, saved_results) = tokio::join!(local_future, saved_future);

    let mut entries = Vec::with_capacity(servers.len() + 1);
    let mut local_error = None;
    match local_outcome {
        Ok(Some((server, result))) => entries.push((server, result)),
        Ok(None) => {}
        Err(error) => local_error = Some(clean_one_line(&format!("{error:#}"))),
    }
    entries.extend(servers.into_iter().zip(saved_results));

    FanOutOutcome {
        entries,
        local_error,
    }
}

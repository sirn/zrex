mod app;
mod rex;
mod session;

use anyhow::Result;

use crate::rex::control::Control;

const DEFAULT_SERVER: &str = "http://127.0.0.1:7297";

const USAGE: &str = "\
zrex: use a session on a Rex server from a terminal

Usage:
  zrex [--server ADDRESS] ls
  zrex [--server ADDRESS] a|attach [SESSION] [--window SELECTOR] [--block SELECTOR]
  zrex [--server ADDRESS] kill SESSION
  zrex --version

The server address comes from --server, or from REX_SERVER, and defaults to
http://127.0.0.1:7297. a is short for attach. SESSION is a label, a full ID, or
the last four or more characters of an ID. When no session matches, attach makes
one with that label, so the same command opens a session and returns to it
later. Without SESSION, attach uses the first session. --window, or -w, picks
the window: its number from one, its label, window.block (such as 1.2), or - for
a new window with the label Rex picks. A label that no window has makes a window
with that label, with one shell in it. --block, or -b, picks a block inside the
window by its number from one, its label, or its ID. Without --window the client
shows the window the session already has, and never changes it, leaving what
Rex.app shows alone. ls lists every session, its windows, and any splits (1.1,
1.2, ...) with a star on the active window and block.

While attached:
  Ctrl-backslash          detach, and leave the session running

Terminal output streams directly to your terminal, so your terminal's own
scrollback, mouse selection, and clipboard work as they always do.";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    List,
    Attach {
        target: Option<String>,
        window: Option<String>,
        block: Option<String>,
    },
    Kill {
        target: String,
    },
    Unknown(String),
}

fn parse_args<I>(args: I, env_server: Option<String>) -> Result<(String, Command)>
where
    I: IntoIterator<Item = String>,
{
    let mut server = env_server.unwrap_or_else(|| DEFAULT_SERVER.to_owned());
    let mut command: Option<String> = None;
    let mut target: Option<String> = None;
    let mut window: Option<String> = None;
    let mut block: Option<String> = None;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok((server, Command::Help)),
            "-V" | "--version" => return Ok((server, Command::Version)),
            "-S" | "--server" => match args.next() {
                Some(value) => server = value,
                None => anyhow::bail!("--server needs an address"),
            },
            "-w" | "--window" => match args.next() {
                Some(value) => window = Some(value),
                None => anyhow::bail!("--window needs a window number, a label, or -"),
            },
            "-b" | "--block" => match args.next() {
                Some(value) => block = Some(value),
                None => anyhow::bail!("--block needs a block number, a label, or an ID"),
            },
            other if command.is_none() => command = Some(other.to_owned()),
            other if target.is_none() => target = Some(other.to_owned()),
            other => anyhow::bail!("unexpected argument {other}"),
        }
    }

    let cmd = match command.as_deref() {
        Some("ls") => Command::List,
        Some("a" | "attach") => Command::Attach {
            target,
            window,
            block,
        },
        Some("kill") => match target {
            Some(target) => Command::Kill { target },
            None => anyhow::bail!("kill needs a session"),
        },
        Some(other) => Command::Unknown(other.to_owned()),
        None => Command::Help,
    };
    Ok((server, cmd))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server, command) = parse_args(std::env::args().skip(1), std::env::var("REX_SERVER").ok())?;

    match command {
        Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Command::Version => {
            println!("zrex {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::List => list(&server).await,
        Command::Attach {
            target,
            window,
            block,
        } => app::attach(&server, target, window, block).await,
        Command::Kill { target } => kill(&server, &target).await,
        Command::Unknown(other) => {
            eprintln!("unknown command {other}\n\n{USAGE}");
            std::process::exit(2);
        }
    }
}

async fn list(server: &str) -> Result<()> {
    let (mut ctrl, _events) = Control::connect(server, None).await?;
    let sessions = session::list_all(&mut ctrl).await?;
    if sessions.is_empty() {
        println!("no sessions");
        return Ok(());
    }
    let width = sessions
        .iter()
        .map(|session| session::label_of(session).chars().count())
        .max()
        .unwrap_or(0);
    for entry in sessions {
        let id = session::id_of(&entry);
        let view = session::view(&mut ctrl, &id).await.ok();
        for line in format_session(&entry, view.as_ref(), width) {
            println!("{line}");
        }
    }
    Ok(())
}

fn format_session(
    entry: &serde_json::Value,
    view: Option<&serde_json::Value>,
    width: usize,
) -> Vec<String> {
    let id = session::id_of(entry);
    let mut lines = vec![format!("{:width$}  {id}", session::label_of(entry))];
    let Some(view) = view else {
        return lines;
    };
    let active = session::active_window_id(view);
    for (number, window) in session::windows(view).iter().enumerate() {
        let win_num = number + 1;
        let mark = if active == Some(window.id.as_str()) {
            "*"
        } else {
            " "
        };
        lines.push(format!("  {mark} {win_num}  {}", window.label));
        if window.blocks.len() > 1 {
            for (b_idx, block) in window.blocks.iter().enumerate() {
                let b_mark = if window.active_block_id.as_deref() == Some(block.id.as_str()) {
                    "*"
                } else {
                    " "
                };
                lines.push(format!(
                    "    {b_mark} {win_num}.{}  {}",
                    b_idx + 1,
                    block.label
                ));
            }
        }
    }
    lines
}

async fn kill(server: &str, target: &str) -> Result<()> {
    let (mut ctrl, _events) = Control::connect(server, None).await?;
    let id = session::pick(&mut ctrl, Some(target)).await?;
    session::destroy(&mut ctrl, &id).await?;
    println!("destroyed {id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_cli_flags_and_commands() {
        let (server, cmd) = parse_args(args(&["ls"]), None).unwrap();
        assert_eq!(server, DEFAULT_SERVER);
        assert_eq!(cmd, Command::List);

        let (server, cmd) = parse_args(
            args(&["-S", "https://example.com", "a", "work", "-w", "1.2"]),
            Some("http://env:7297".to_owned()),
        )
        .unwrap();
        assert_eq!(server, "https://example.com");
        assert_eq!(
            cmd,
            Command::Attach {
                target: Some("work".to_owned()),
                window: Some("1.2".to_owned()),
                block: None,
            }
        );

        let (_, cmd) = parse_args(
            args(&["attach", "work", "--window", "1", "--block", "2"]),
            None,
        )
        .unwrap();
        assert_eq!(
            cmd,
            Command::Attach {
                target: Some("work".to_owned()),
                window: Some("1".to_owned()),
                block: Some("2".to_owned()),
            }
        );

        let (server, cmd) =
            parse_args(args(&["kill", "work"]), Some("http://env:7297".to_owned())).unwrap();
        assert_eq!(server, "http://env:7297");
        assert_eq!(
            cmd,
            Command::Kill {
                target: "work".to_owned()
            }
        );

        assert!(parse_args(args(&["kill"]), None).is_err());
        assert!(parse_args(args(&["-S"]), None).is_err());
        assert!(parse_args(args(&["-w"]), None).is_err());
        assert!(parse_args(args(&["-b"]), None).is_err());
        assert!(parse_args(args(&["a", "one", "two"]), None).is_err());
    }

    #[test]
    fn formats_sessions_windows_and_splits_for_ls() {
        let entry = json!({"session_id": "session:1", "label": "work"});
        let view = json!({
            "active_window_id": "window:1",
            "windows": [
                {
                    "window_id": "window:1",
                    "label": "Window one",
                    "focused_block_id": "block:2",
                    "layers": [{
                        "layer_id": "layer:1",
                        "blocks": [
                            {"block_id": "block:1", "label": "Block one"},
                            {"block_id": "block:2", "label": "Block two"},
                        ]
                    }]
                },
                {
                    "window_id": "window:2",
                    "label": "Window two",
                    "focused_block_id": "block:3",
                    "layers": [{
                        "layer_id": "layer:2",
                        "blocks": [
                            {"block_id": "block:3", "label": "Block three"},
                        ]
                    }]
                }
            ]
        });
        let lines = format_session(&entry, Some(&view), 4);
        assert_eq!(
            lines,
            vec![
                "work  session:1",
                "  * 1  Window one",
                "      1.1  Block one",
                "    * 1.2  Block two",
                "    2  Window two",
            ]
        );
    }
}

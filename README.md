# zrex

A lightweight command-line client for a [Rex](https://www.superlogical.com/rex/docs) server.

`zrex` attaches your terminal to one block of a Rex session in the pass-through style of [`zmx`](https://zmx.sh): no local tab bar, no split borders, no alternate-screen hijacking, and no client-side terminal re-rendering. Rex keeps your sessions, windows, layouts, and blocks running on the server; `zrex` rehydrates the block's scrollback and screen on attach and streams raw VT input and output directly through your terminal.

## Features

- **Session management**: List, create, attach to, and destroy sessions by label, full ID, or 4+ character ID suffix.
- **Window and split selection**: List windows and split panes (`1.1`, `1.2`, ...), attach to any window or split with `--window` (`-w`) and `--block` (`-b`), or create new windows on demand without changing the active window shown in Rex.app.
- **Direct terminal pass-through**: Runs in your terminal's normal screen buffer so native scrollback, native mouse text selection, clickable URLs, Kitty graphics, and OSC escape sequences work directly without an intermediate renderer.
- **Full state rehydration**: Restores scrollback history, cursor state, colors, and terminal modes from the server on attach, and resets terminal modes cleanly on detach.
- **Automatic reconnection**: Reconnects when the network drops and resumes the terminal stream from the last received byte.

## Requirements

- Rust (`cargo`). A Nix flake (`nix develop`) is also available.
- A Rex server reachable over HTTP or HTTPS.

## Build

```sh
cargo build --release
```

## Usage

```sh
# List sessions, windows, and split blocks
zrex -S https://server.example ls

# Attach to a session (creates it if no session matches)
zrex -S https://server.example a work

# Attach to a specific window by number or label
zrex -S https://server.example a work --window 2
zrex -S https://server.example a work --window build

# Attach to a specific split block inside a window
zrex -S https://server.example a work --window 1.2
zrex -S https://server.example a work --window 1 --block 2
zrex -S https://server.example a work --block 2

# Create a new window with a server-chosen label and attach to it
zrex -S https://server.example a work -w -

# Destroy a session
zrex -S https://server.example kill work
```

### Server Address

The server address is read from `--server` (`-S`), then `REX_SERVER`, and defaults to `http://127.0.0.1:7297`.

### Selecting Sessions, Windows, and Blocks

- **`SESSION`**: Matches a session label, full ID, or the last 4+ characters of an ID. On `attach` (`a`), if no session matches, `zrex` creates a new session with that label. If omitted, `zrex` attaches to the first session on the server.
- **`--window` (`-w`)**: Selects a window by its 1-based number from `zrex ls`, its `window.block` index (such as `1.2`), its label, or `-` for a new window with a default Rex label. Passing a label that no window has creates a new window with that label and one shell block.
- **`--block` (`-b`)**: Selects a block within the target (or active) window by its 1-based number, label, full ID, or 4+ character ID suffix.

## Controls While Attached

| Input | Action |
| --- | --- |
| `Ctrl-\` | Detach and leave the session running |

All other input—including keys, bracketed paste, Kitty keyboard sequences, and mouse events when requested by a running program—is passed directly to the remote block. Scrollback, search, and text selection are handled natively by your host terminal.

To switch to another window or split block, detach with `Ctrl-\` and attach again with `--window` or `--block`.

## Documentation

See [`docs/architecture.md`](docs/architecture.md) for codebase structure, Rex protocol details, and the stream rehydration architecture.

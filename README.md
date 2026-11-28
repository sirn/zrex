# zrex

A lightweight command-line client for a [Rex](https://www.superlogical.com/rex/docs) server.

`zrex` attaches your terminal to one block of a Rex session in the pass-through style of [`zmx`](https://zmx.sh): no local tab bar, no split borders, no alternate-screen hijacking, and no client-side terminal re-rendering. Rex keeps your sessions, windows, layouts, and blocks running on the server; `zrex` rehydrates the block's scrollback and screen on attach and streams raw VT input and output directly through your terminal.

## Features

- **Session management**: List, create, attach to, and destroy sessions by label, full ID, or 4+ character ID suffix.
- **Attach picker**: Fuzzy-search existing sessions, windows, and splits across saved Rex servers, switch to an attention-sorted **Agents** view (`Ctrl-G`), create new sessions (`Ctrl-N`) and windows (`Ctrl-T`), and rename (`Ctrl-R`) or kill (`Ctrl-K`) sessions, windows, or blocks on the fly.
- **Window and split selection**: List windows and split panes (`1.1`, `1.2`, ...), attach to any window or split with `--window` (`-w`) and `--block` (`-b`), or create new windows on demand without changing the active window shown in Rex.app.
- **Direct terminal pass-through**: Runs in your terminal's normal screen buffer so native scrollback, native mouse text selection, clickable URLs, Kitty graphics, and OSC escape sequences work directly without an intermediate renderer (OSC 0/2 window titles are prefixed with `zrex:` while attached and restored on detach).
- **Full state rehydration**: Restores scrollback history, cursor state, colors, and terminal modes from the server on attach, and resets terminal modes cleanly on detach.
- **Automatic reconnection**: Reconnects when the network drops and resumes the terminal stream from the last received byte.

## Requirements

- Rust (`cargo`). A Nix flake (`nix develop`) is also available.
- A Rex server reachable over HTTP, HTTPS, or a Unix socket.

## Build

```sh
cargo build --release
```

## Usage

```sh
# Fuzzy-pick an existing session, window, or split (`zrex p` is short for `zrex pick`)
zrex pick

# List sessions, windows, split blocks, and terminal titles
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

The server is read from `--server` (`-S`), then `REX_SERVER`. It may be a saved server name from `~/.config/zrex/config.toml` (or `$XDG_CONFIG_HOME/zrex/config.toml`), `local` for the local Rex server, an HTTP(S) URL, or a Unix socket address such as `unix:///Users/you/Library/Application%20Support/rex/server.sock`. Without either, `zrex` uses a local Rex server's Unix socket when one is running, and otherwise defaults to `http://127.0.0.1:7297`. An address without a port uses the scheme's default port: 80 for HTTP, 443 for HTTPS.

```sh
# Use a saved server alias from config.toml with any command
zrex -S office ls
zrex -S office a work
zrex -S office pick
zrex -S office kill work

# Target only the local server. The name `local` is reserved (case-insensitive);
# use another alias for a saved server.
zrex -S local ls
```

To reach a Rex server on another machine over Tailscale, use the HTTPS address that `rex server status` reports (for example `https://my-mac.tail1234.ts.net`). The Tailscale node serves HTTPS on port 443, so a bare IP with no port falls back to HTTP on port 80 and is refused.

### Attach Picker

Run `zrex pick` (or `zrex p`), type to filter, and use the arrow keys (or `Tab`/`Shift-Tab`) and Enter to attach in the same terminal. Press `Ctrl-G` to toggle the **Agents** view, which filters to panes reporting OSC 7501 program status or running a known coding agent process and sorts them by attention priority (`blocked`, `error`, `working`, `done`, `idle`, then statusless agents). Detaching (`Ctrl-\`) from a session attached via the picker returns you to the picker—staying in the Agents view if you attached from it—with a refreshed view, and pressing `Ctrl-\` in the picker quits back to your shell—so a double `Ctrl-\` detaches all the way out. Press `Ctrl-N` to create a new session (optionally choosing a server and name, or pressing Enter for the default), `Ctrl-T` to create a new window in a session (defaulting to the highlighted target's session), `Ctrl-R` to rename the highlighted session, window, or block (clearing with `Ctrl-U` restores the server default), or `Ctrl-K` to kill a session, window, or block (use `Tab`/arrows or `s`/`w`/`b` to choose the scope, and `Enter`/`y` to confirm). Renames and kills update the picker in place so you can keep working without leaving it. `Ctrl-U` clears the current input, `Esc` backs out of a prompt (or the Agents view) or quits the picker, and `Ctrl-C` or `Ctrl-\` quits immediately from any prompt.

Use `Alt/Option-←` and `Alt/Option-→` to move by word. `Ctrl-←`/`Ctrl-→` and `Alt-B`/`Alt-F` also work, depending on what your terminal sends. `Home`/`End` or `Ctrl-A`/`Ctrl-E` go to the start or end of the query.

Each row shows the server, session, window/split index, foreground process (and any custom window or split label), plus the terminal title and OSC 7501 program status when Rex has them. You can search the displayed text, for example `blocked`, `zsh`, or `zrex 22`. If a pane reports multiple statuses, the picker shows the one that most needs attention. Metadata is fetched when the picker opens.

To search multiple servers, save their names and addresses in `~/.config/zrex/config.toml` (or `$XDG_CONFIG_HOME/zrex/config.toml`):

```toml
[servers]
office = "https://office.example.com"
lab = "https://lab.example.com"
```

Each choice shows its server name. `zrex pick` (or `zrex p`) opens immediately and queries saved servers alongside a running local server (or `REX_SERVER`, if set) in parallel, displaying each server's sessions as it connects and showing a notification in the status banner if a server times out or cannot be reached. If no local server is running, it is silently skipped when saved servers are configured, and `zrex pick` exits with an error when no local or saved server is available. Use `zrex -S SERVER pick` (or `zrex -S SERVER p`, with a saved server name, `local`, or a URL) to search just one server.

`zrex ls` (without `--server` or `REX_SERVER`) likewise lists sessions from any running local server and saved servers in `config.toml`, silently skipping an absent local server when saved servers are configured and exiting with an error when no local or saved server is available.

### Selecting Sessions, Windows, and Blocks

- **`SESSION`**: Matches a session label, full ID, or the last 4+ characters of an ID. On `attach` (`a`), if no session matches, `zrex` creates a new session with that label. If omitted, `zrex` attaches to the first session on the server.
- **`--window` (`-w`)**: Selects a window by its 1-based number from `zrex ls`, its `window.block` index (such as `1.2`), its label, or `-` for a new window with a default Rex label. Passing a label that no window has creates a new window with that label and one shell block.
- **`--block` (`-b`)**: Selects a block within the target (or active) window by its 1-based number, label, full ID, or 4+ character ID suffix.

`ls` prints each window's label and, beside it, the live terminal title its focused block reports (falling back to the foreground process name when no live title is set).

### Shell Completion

`zrex completion` prints a script that completes saved server names for `--server` (`-S`), plus session labels, window numbers and labels, and block numbers and labels from the live server.

```sh
# zsh (after compinit, in ~/.zshrc)
source <(zrex completion zsh)

# bash (in ~/.bashrc)
source <(zrex completion bash)

# fish
zrex completion fish | source
```

You can also install the completion file directly with `--install` (or `--install --dir DIR` to choose a target directory):

```sh
# Installs to ~/.local/share/bash-completion/completions/zrex (or $XDG_DATA_HOME)
zrex completion bash --install

# Installs to ~/.config/fish/completions/zrex.fish (or $XDG_CONFIG_HOME)
zrex completion fish --install

# Installs to ~/.local/share/zsh/site-functions/_zrex (or $XDG_DATA_HOME);
# prints the fpath + compinit snippet if that directory is not already in $fpath.
zrex completion zsh --install
```

## Controls While Attached

| Input | Action |
| --- | --- |
| `Ctrl-\` | Detach and leave the session running (returns to the picker if launched from it; press `Ctrl-\` again to quit to your shell) |
| `Alt-Ctrl-\` | Forward a literal `Ctrl-\` to the remote block (for detaching a nested `zrex` session) |

You can change or disable the detach key with `--detach-key` (`-d`), `ZREX_DETACH_KEY`, or `detach_key` in `~/.config/zrex/config.toml` (e.g. `ctrl-]`, `ctrl-^`, or `none`). When customized, `Alt` with that key forwards the literal control byte to the remote block, and detaching from a nested `zrex` can also be done by re-attaching the outer session with `--detach-key ctrl-]` or `--detach-key none`.

All other input—including keys, bracketed paste, Kitty keyboard sequences, and mouse events when requested by a running program—is passed directly to the remote block. Scrollback, search, and text selection are handled natively by your host terminal.

To switch to another window or split block, detach with `Ctrl-\` to pick another target (or re-attach directly with `--window` or `--block`).

## Documentation

See [`docs/architecture.md`](docs/architecture.md) for codebase structure, Rex protocol details, and the stream rehydration architecture.

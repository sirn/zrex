# Architecture and Implementation Notes

`zrex` connects a local terminal to a single block on a [Rex](https://www.superlogical.com/rex/docs) server using a [`zmx`](https://zmx.sh/architecture)-style pass-through architecture. The Rex server maintains sessions, windows, layouts, blocks, and server-side `libghostty-vt` terminal state; `zrex` primes the local terminal from the server's VT formatter on attach and then passes raw terminal bytes between `stdin`/`stdout` and the remote block.

## Code Layout

| File | Role |
| --- | --- |
| `src/main.rs` | CLI parsing (`ls`, `p`/`pick`, `a`/`attach`, `kill`, `completion`), single- and multi-server session/window/split listing with terminal titles, and shell completion |
| `src/config.rs` | Saved-server config (`config.toml`) loading and server alias resolution shared across CLI commands, `zrex ls`, and the picker |
| `src/discovery.rs` | Parallel local + saved server discovery fan-out, address deduplication, and deadline handling shared by `zrex ls` and the picker |
| `src/text.rs` | One-line control-character sanitization, display-width truncation, percent-decoding, and home-path shortening helpers shared across CLI, config, session, app, and picker |
| `src/picker.rs` | Streaming parallel session discovery (`DiscoveryStream`), target/status formatting, instant-start picker loop with incremental server updates and post-detach refresh, and in-place session/window/block management (`rename`/`kill`) for `zrex pick` (`zrex p`) |
| `src/picker/prompt.rs` | Alternate-screen fuzzy prompt UI, raw-mode guard (`RawModeGuard`) and queued quit-key check, incremental async discovery stepping (`Screen::step_until`), key/word navigation, and rendering for the picker |
| `src/app.rs` | Attach lifecycle: interruptible pre-attach connect, bootstrap, block ownership, sizing, VT stream priming, raw I/O pass-through, non-blocking liveness probes, events, and detach-interruptible reconnection |
| `src/session.rs` | Session lookup/creation, `session.view` queries, terminal title/process derivation, and session/window/block mutation helpers |
| `src/rex/mod.rs` | Server address parsing, `BlockRef` addressing, local socket discovery, WebSocket connection setup, and frame helpers |
| `src/rex/proto.rs` | Control connection JSON messages, responses, and event envelope unwrapping |
| `src/rex/control.rs` | Multiplexed `/api/control` client with background reader/writer tasks and bounded RPC timeouts |
| `src/rex/data.rs` | `/api/data` stream client, binary handshake (`HELLO`/`WELCOME`), and `RESUME` support |
| `src/rex/stream.rs` | `GHOSTSNP` snapshot framing, in-band Rex APC message extraction, and `zrex:` OSC 0/2 window-title prefixing |

## Protocol Overview

Every Rex server serves its own protocol and schema documentation:

```sh
curl https://server.example/llms.txt      # protocol guide
curl https://server.example/api/help      # method reference and JSON schemas
```

A client uses two WebSockets, over TCP/TLS or a Unix socket:

1. **Control (`/api/control`, subprotocol `rex.control.v1`)**:
   Carries JSON messages (`hello`, `welcome`, `request`, `response`, and `event`). All RPC method calls and server/session events travel over this connection.
2. **Data (`/api/data`, subprotocol `rex.data.terminal.v1`)**:
   Streams a single block's output. Opened using a one-time 16-byte ticket from `data.connect`. Uses a binary handshake:
   - Client sends a 17-byte `HELLO` (`0x01` + 16-byte ticket) or a 25-byte `RESUME` (`0x02` + 16-byte token + 8-byte little-endian byte offset).
   - Server replies with a 32-byte `WELCOME` (`0x81`, 16-byte reconnect token, 3 zero bytes, 4-byte expiry, and 8-byte channel nonce) or a `REJECT` (`0x82` + reason byte).

## Pass-Through I/O and Rehydration

Rather than entering the alternate screen or re-rendering cells through a second client-side terminal emulator, `zrex` keeps the host terminal in its normal buffer with raw mode enabled:

1. **Initial VT Rehydration (`Attached::prime`)**:
   Every new `/api/data` stream begins with a binary `GHOSTSNP` (version 1) snapshot header. `rex::stream::snapshot_len` scans chunk headers until tag `6` (`FINISH`) marks the end of the binary snapshot, then `Attached::prime` calls `com.superlogical.terminal.format` (`format: "vt"`, `trim: false`, and all `extra_*` state flags) to fetch the block's scrollback, screen, cursor state, and modes as standard VT escape sequences and writes them to `stdout`.
2. **Live Output Pass-Through (`Attached::feed`)**:
   Subsequent `/api/data` chunks pass through `rex::stream::Filter` and are written directly to `stdout`. `Filter` performs two targeted transforms: (a) it strips in-band Rex APC control sequences (`ESC _ rex1;<NONCE>;<JSON> ESC \`) whose `<NONCE>` matches the 64-bit channel nonce from the data connection's `WELCOME` frame (passing foreign APC sequences through untouched), and (b) it prefixes OSC 0 and OSC 2 window-title sequences with `zrex: ` (or `zrex` when empty) via `format_osc_title` so the host terminal identifies the attached pane (passing all other OSC sequences—such as OSC 52 clipboard and OSC 8 hyperlinks—through untouched).
3. **Raw Input Forwarding (`Attached::burst`)**:
   `stdin` bytes are read directly and scanned for the configured detach key (default `Ctrl-\`: `0x1c`, Kitty CSI-u `\x1b[92;5u`, or xterm `modifyOtherKeys` `\x1b[27;5;92~`; configurable via `--detach-key` / `-d`, `ZREX_DETACH_KEY`, or `detach_key` in `config.toml`, including `none`), even when batched with preceding input bytes in the same read. `Alt` + the detach key (legacy `\x1b<ctrl>`, Kitty CSI-u mod 7, or xterm `modifyOtherKeys` mod 7) forwards the literal control byte to the remote block so nested `zrex` sessions can be detached. Two categories of `stdin` bytes are intercepted locally instead of forwarded: (a) detach / `Alt`-pass-through sequences, and (b) host terminal query replies (`split_replies` / `Replies`), specifically `OSC 4/10/11/12` color replies, DA1/DA2 (`CSI ?/> ... c`), DECRPM (`CSI ? ... $ y`), Kitty keyboard query replies (`CSI ? ... u`), and DECSET 2031 color-scheme reports (`CSI ? 997 ; ... n`). Ambiguous bare openers (`Esc`, `Alt+[`, `Alt+]`) right after a reply burst are held briefly (`50ms`) before forwarding as typing, while definite partial host replies are held longer (`2s`) so delayed continuations still reassemble and are dropped rather than injected into the remote PTY on stall or detach. All other input bytes—including UTF-8 text, escape sequences, bracketed paste, Kitty keyboard reports, and mouse reports requested by programs running inside the block—are forwarded via `com.superlogical.terminal.write`. Because Rex runs block methods concurrently rather than in arrival order, `zrex` keeps at most one `com.superlogical.terminal.write` request in flight at a time (bounded by `CALL_TIME` so a stalled server triggers recovery) and coalesces any input arriving while it is in flight into the next write, ensuring escape sequences and bracketed-paste delimiters (`\x1b[200~` … `\x1b[201~`) always reach the remote PTY in strict order without blocking output; on detach, any in-flight or queued writes (including bytes typed before a batched detach key) are drained under a short deadline before `session.detach`.
4. **Mode Cleanup on Detach (`Screen::enter` / `Screen::leave_and_drain`)**:
   On attach, `Screen::enter` clears leftover host color overrides (`OSC 104/110/111/112`) and pushes the host window title onto the terminal title stack (`CSI 22 ; 0 t`) before probing theme colors. When detaching or exiting, `Screen::leave_and_drain` emits CAN (`0x18`) to abort any partial sequence, resets terminal modes that a remote program may have enabled while attached (synchronized output, Kitty keyboard stack `<99u`/`=0u` and `modifyOtherKeys` both before and after leaving the alternate screen `?1049l`/`?1047l`/`?47l` because terminals like `foot`, Kitty, and Ghostty keep per-screen keyboard stacks, mouse tracking including SGR-Pixels `?1016l`, focus reporting, bracketed paste, color-scheme reporting, in-band resize `?2048l`, cursor keys, origin/wrap/insert modes, scroll region, custom palette/default colors `OSC 104/110/111/112`, saved window title pop `CSI 23 ; 0 t`, cursor visibility, and SGR attributes), and—when the host terminal has answered queries—sends a DSR status barrier (`CSI 5 n`) and drains stdin in raw mode until `CSI 0 n` arrives (bounded by short deadlines) so delayed SSH replies cannot leak into the parent shell or picker; standalone attaches (`TerminalMode::RestoreOnLeave`) then disable raw mode, while picker-launched attaches (`TerminalMode::KeepRawOnLeave`) keep raw mode enabled across the return-to-picker handoff until `picker::prompt::RawModeGuard` drops on exit so a second detach key cannot trigger cooked-mode `SIGQUIT`.

## Host Theme Bridge

Programs in a block ask the server, not the host terminal, for colors: the server answers `OSC 4`, `OSC 10`/`11`/`12`, DA1, and `CSI ? 996 n` from the block's own theme, and it answers the first three only once a theme exists. `zrex` keeps that theme equal to the host terminal's:

1. **Attach probe (`Screen::probe_theme`)**: `theme_query_batches` asks the host for its default foreground, background, and cursor colors and all 256 palette entries using ST-terminated (`ESC \`) OSC queries split into 64-color batches, each terminated by a DA1 (`CSI c`) sentinel. Waiting for each batch's DA1 (under `100ms` idle / `500ms` total deadlines) keeps in-flight replies under 2 KiB—well below a 4 KiB kernel PTY buffer. Batch 0 also enables `WATCH_SCHEME` before its DA1 sentinel so any immediate `CSI ? 997 ; n` report is drained during the probe.
2. **Scheme reports (`WATCH_SCHEME`)**: `CSI ? 2031 h` makes the host report light and dark switches. A `CSI ? 997 ; n` report marks the theme dirty, and `Attached::refresh_theme` re-runs the same DA1-paced `theme_query_batches` probe and forwards the new theme to `com.superlogical.terminal.set_theme`; the server then tells programs that subscribed to scheme reports.
3. **Ownership**: a block takes its size and colors from its owner, and the server gives it to the client that claimed it most recently. `zrex` claims with `session.own_block` (`mode: "take"`) when the user attaches or types in the block, and then applies its size and theme. It never claims in response to `block_owner_changed`, so two clients cannot trade a block forever; while another client owns it, `zrex` holds its size and theme for the next claim. A reconnect claims only when no other client owns the block. Every path that changes the size or the colors (attach, resize, scheme change, claim, ownership gained) publishes through one rule, which pushes only while this client holds the block.

## Protocol Details and Quirks

### Event Envelopes and Scope
- Session events arrive nested inside a `session_event` envelope:
  ```json
  {
    "type": "event",
    "payload": {
      "type": "session_event",
      "payload": {
        "session_id": "session:...",
        "event": {
          "type": "block_closed",
          "payload": { "block_id": "block:..." }
        }
      }
    }
  }
  ```
  Server-level events (such as `session_destroyed`) arrive with their fields directly under `payload.payload`. `rex::proto::unwrap_event` normalizes both into `(event_name, body)` with `session_id` attached.
- `session.bootstrap` with `event_scope: "session"` omits `block_event`, which prevents bell and OSC 52 clipboard events from arriving. `zrex` always bootstraps with `event_scope: "all"`.

### Windows, Splits, and Block Ownership
- No RPC attaches to a window directly. A client attaches to a session, and `session.view` returns the session's windows, their labels, their `focused_block_id` / `zoomed_block_id`, and their layers' `blocks`.
- A block streams regardless of which window is active in the session. `--window` and `--block` resolve the target block from `session.view` without calling `session.focus_window`. Because `active_window_id` is shared across the session, calling `session.focus_window` would switch the active tab for every other attached client (including Rex.app).
- Mutating window or block state (such as `session.new_window` or `session.own_block`) fails with `conflict` (HTTP 409) until the control connection is attached to the session via `session.attach` or `session.bootstrap`.
- To size a block to the local terminal, the client must first claim ownership with `session.own_block` (`mode: "take"`) before calling `com.superlogical.terminal.resize`.

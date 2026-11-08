# Architecture and Implementation Notes

`zrex` connects a local terminal to a single block on a [Rex](https://www.superlogical.com/rex/docs) server using a [`zmx`](https://zmx.sh/architecture)-style pass-through architecture. The Rex server maintains sessions, windows, layouts, blocks, and server-side `libghostty-vt` terminal state; `zrex` primes the local terminal from the server's VT formatter on attach and then passes raw terminal bytes between `stdin`/`stdout` and the remote block.

## Code Layout

| File | Role |
| --- | --- |
| `src/main.rs` | CLI parsing (`ls`, `a`/`attach`, `kill`) and session/window/split listing |
| `src/app.rs` | Attach lifecycle: bootstrap, block ownership, sizing, VT stream priming, raw I/O pass-through, events, and reconnection |
| `src/session.rs` | Session lookup/creation and `session.view` queries for windows and split blocks |
| `src/rex/mod.rs` | WebSocket connection setup, URL construction, and frame helpers |
| `src/rex/proto.rs` | Control connection JSON messages, responses, and event envelope unwrapping |
| `src/rex/control.rs` | Multiplexed `/api/control` client with background reader and writer tasks |
| `src/rex/data.rs` | `/api/data` stream client, binary handshake (`HELLO`/`WELCOME`), and `RESUME` support |
| `src/rex/stream.rs` | `GHOSTSNP` snapshot framing and in-band Rex APC message extraction |

## Protocol Overview

Every Rex server serves its own protocol and schema documentation:

```sh
curl https://server.example/llms.txt      # protocol guide
curl https://server.example/api/help      # method reference and JSON schemas
```

A client uses two WebSockets:

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
   Subsequent `/api/data` chunks pass through `rex::stream::Filter` to strip in-band Rex APC control sequences (`ESC _ rex1;<NONCE>;<JSON> ESC \`) and are written directly to `stdout`. Only APC sequences whose `<NONCE>` matches the 64-bit channel nonce from the data connection's `WELCOME` frame are stripped; foreign APC sequences pass through untouched.
3. **Raw Input Forwarding (`Attached::burst`)**:
   `stdin` bytes are read directly and checked for `Ctrl-\` (`0x1c`, Kitty CSI-u `\x1b[92;5u`, or xterm `modifyOtherKeys` `\x1b[27;5;92~`). All other input bytes—including UTF-8 text, escape sequences, bracketed paste, Kitty keyboard reports, and mouse reports requested by programs running inside the block—are forwarded without waiting via `com.superlogical.terminal.write`.
4. **Mode Cleanup on Detach (`Screen::leave`)**:
   When detaching or exiting, `Screen::leave` resets terminal modes that a remote program may have enabled while attached (synchronized output, Kitty keyboard stack, `modifyOtherKeys`, mouse tracking, focus reporting, bracketed paste, cursor keys, alternate screen `?1049l`, scroll region, cursor visibility, and SGR attributes) before disabling raw mode.

## Host Theme Bridge

Programs in a block ask the server, not the host terminal, for colors: the server answers `OSC 4`, `OSC 10`/`11`/`12`, DA1, and `CSI ? 996 n` from the block's own theme, and it answers the first three only once a theme exists. `zrex` keeps that theme equal to the host terminal's:

1. **Attach probe (`Screen::probe_theme`)**: `theme_query` asks the host for its default foreground, background, and cursor colors and for all 256 palette entries, with DA1 as the completion sentinel.
2. **Scheme reports (`WATCH_SCHEME`)**: `CSI ? 2031 h` makes the host report light and dark switches. A `CSI ? 997 ; n` report marks the theme dirty, and `Attached::refresh_theme` asks the host for its colors again and forwards the new theme to `com.superlogical.terminal.set_theme`; the server then tells programs that subscribed to scheme reports.
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

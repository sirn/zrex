//! Each Rex in-band message is an APC escape sequence:
//! `ESC _ rex1;NONCE;JSON ESC \`. A program inside the terminal can print a
//! look-alike, so only a matching channel nonce counts.

use anyhow::{Result, bail};

pub fn snapshot_len(bytes: &[u8]) -> Result<Option<usize>> {
    const MAGIC: &[u8; 8] = b"GHOSTSNP";
    if bytes.len() < 10 {
        return Ok(None);
    }
    if &bytes[..8] != MAGIC {
        bail!("the stream does not start with a terminal snapshot");
    }
    let mut offset = 10;
    loop {
        if bytes.len() < offset + 10 {
            return Ok(None);
        }
        let tag = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let len = u32::from_le_bytes([
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
        ]) as usize;
        let end = offset + 10 + len;
        if bytes.len() < end {
            return Ok(None);
        }
        offset = end;
        // Tag 6 is FINISH, the end of the snapshot.
        if tag == 6 {
            return Ok(Some(offset));
        }
    }
}

enum State {
    Ground,
    SawEsc,
    InApc { data: Vec<u8>, saw_esc: bool },
}

pub struct Filter {
    nonce: String,
    state: State,
    out: Vec<u8>,
}

impl Filter {
    pub fn new(nonce: u64) -> Self {
        Self {
            nonce: nonce.to_string(),
            state: State::Ground,
            out: Vec::new(),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        for &byte in bytes {
            self.byte(byte);
        }
        std::mem::take(&mut self.out)
    }

    fn byte(&mut self, byte: u8) {
        match &mut self.state {
            State::Ground => {
                if byte == 0x1b {
                    self.state = State::SawEsc;
                } else {
                    self.out.push(byte);
                }
            }
            State::SawEsc => {
                if byte == b'_' {
                    self.state = State::InApc {
                        data: Vec::new(),
                        saw_esc: false,
                    };
                } else {
                    self.out.push(0x1b);
                    self.out.push(byte);
                    self.state = State::Ground;
                }
            }
            State::InApc { data, saw_esc } => {
                if *saw_esc && byte == b'\\' {
                    let body = std::mem::take(data);
                    self.state = State::Ground;
                    self.message(&body);
                } else {
                    if *saw_esc {
                        data.push(0x1b);
                    }
                    *saw_esc = byte == 0x1b;
                    if !*saw_esc {
                        data.push(byte);
                    }
                }
            }
        }
    }

    fn message(&mut self, body: &[u8]) {
        if let Some(rest) = body.strip_prefix(b"rex1;")
            && let Some(rest) = rest.strip_prefix(self.nonce.as_bytes())
            && rest.starts_with(b";")
        {
            return;
        }
        // Another application's APC: pass it on untouched.
        self.out.extend_from_slice(b"\x1b_");
        self.out.extend_from_slice(body);
        self.out.extend_from_slice(b"\x1b\\");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_matching_rex_apc_and_preserves_terminal_bytes() {
        let mut filter = Filter::new(42);
        let input = b"hello \x1b_rex1;42;{\"type\":\"resize\",\"cols\":80,\"rows\":24}\x1b\\world";
        let out = filter.push(input);
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn handles_split_chunks_spoofed_nonce_and_foreign_apc() {
        let mut filter = Filter::new(99);
        let chunks: &[&[u8]] = &[
            b"a\x1b[31mred\x1b_rex1;",
            b"99;{\"type\":\"child_exited\"}\x1b\\",
            b"\x1b_rex1;0;{\"type\":\"spoof\"}\x1b\\",
            b"\x1b_other;pay\x1bload\x1b\\z",
        ];
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend_from_slice(&filter.push(chunk));
        }
        assert_eq!(
            out,
            b"a\x1b[31mred\x1b_rex1;0;{\"type\":\"spoof\"}\x1b\\\x1b_other;pay\x1bload\x1b\\z"
        );
    }

    #[test]
    fn measures_terminal_snapshot_length() {
        assert_eq!(snapshot_len(b"GHOST").unwrap(), None);
        assert!(snapshot_len(b"NOTASNAP00").is_err());

        let mut buf = Vec::from(&b"GHOSTSNP\x01\x00"[..]);
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(b"abcd");
        assert_eq!(snapshot_len(&buf).unwrap(), None);

        buf.extend_from_slice(&6u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        let expected = buf.len();
        buf.extend_from_slice(b"live stream");
        assert_eq!(snapshot_len(&buf).unwrap(), Some(expected));
    }
}

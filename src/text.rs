use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Server- and program-provided text must not send terminal escapes or span
/// multiple lines.
pub fn clean_one_line(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

pub fn clean_truncated(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let cleaned = clean_one_line(text);
    let mut chars = cleaned.chars();
    let mut short: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        short.pop();
        short.push('…');
    }
    short
}

pub fn prefix_to_columns(text: &str, max_columns: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let ch_width = ch.width().unwrap_or(0);
        if used + ch_width > max_columns {
            break;
        }
        out.push(ch);
        used += ch_width;
    }
    out
}

/// Truncates `text` to fit within `max_columns` display columns, reserving room
/// for a trailing `…` when truncated. Returns `(visible_prefix, was_truncated)`.
pub fn truncate_to_columns(text: &str, max_columns: usize) -> (String, bool) {
    if max_columns == 0 || text.is_empty() {
        return (String::new(), false);
    }
    if text.width() <= max_columns {
        return (text.to_owned(), false);
    }
    let ellipsis_width = '…'.width().unwrap_or(1);
    let visible = prefix_to_columns(text, max_columns.saturating_sub(ellipsis_width));
    (visible, max_columns >= ellipsis_width)
}

pub fn truncate_with_ellipsis(text: &str, max_columns: usize) -> String {
    let (mut visible, truncated) = truncate_to_columns(text, max_columns);
    if truncated {
        visible.push('…');
    }
    visible
}

pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn shorten_home(path: &str) -> String {
    let home = std::env::var_os("HOME");
    shorten_home_with(path, home.as_deref().and_then(std::ffi::OsStr::to_str))
}

fn shorten_home_with(path: &str, home: Option<&str>) -> String {
    let Some(home) = home
        .map(|h| h.trim_end_matches('/'))
        .filter(|h| !h.is_empty())
    else {
        return path.to_owned();
    };
    if path == home {
        "~".to_owned()
    } else if let Some(rest) = path.strip_prefix(home)
        && rest.starts_with('/')
    {
        format!("~{rest}")
    } else {
        path.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_one_line_replaces_control_chars_and_trims() {
        assert_eq!(clean_one_line("  π - release  "), "π - release");
        assert_eq!(clean_one_line("a\x1b[2Jb"), "a [2Jb");
        assert_eq!(clean_one_line("\u{7}\u{9}"), "");
    }

    #[test]
    fn clean_truncated_handles_zero_and_long_inputs() {
        assert_eq!(clean_truncated("abc", 0), "");
        assert_eq!(clean_truncated("", 0), "");
        assert_eq!(clean_truncated("abc", 1), "…");
        assert_eq!(clean_truncated(&"x".repeat(100), 80).chars().count(), 80);
    }

    #[test]
    fn truncate_to_columns_respects_display_width() {
        assert_eq!(truncate_to_columns("πππ", 5), ("πππ".to_owned(), false));
        assert_eq!(truncate_to_columns("πππ", 2), ("π".to_owned(), true));
        assert_eq!(truncate_to_columns("πππ", 1), (String::new(), true));
        assert_eq!(truncate_to_columns("πππ", 0), (String::new(), false));
        assert_eq!(truncate_with_ellipsis("你好世界", 4), "你…");
        assert_eq!(truncate_with_ellipsis("你好世界", 0), "");
    }

    #[test]
    fn shorten_home_handles_root_and_boundary_prefixes() {
        assert_eq!(shorten_home_with("/Users/jack", Some("/Users/jack")), "~");
        assert_eq!(
            shorten_home_with("/Users/jack/Projects/zrex", Some("/Users/jack/")),
            "~/Projects/zrex"
        );
        assert_eq!(
            shorten_home_with("/Users/jackson/work", Some("/Users/jack")),
            "/Users/jackson/work"
        );
        assert_eq!(shorten_home_with("/tmp/foo", Some("/")), "/tmp/foo");
        assert_eq!(shorten_home_with("/", Some("/")), "/");
        assert_eq!(shorten_home_with("/tmp/foo", None), "/tmp/foo");
    }
}

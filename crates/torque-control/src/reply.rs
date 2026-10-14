use crate::error::{Error, Result};

/// One line of a reply. `data` holds the payload of a `250+key=...` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyLine {
    pub text: String,
    pub data: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<ReplyLine>,
}

impl Reply {
    pub fn is_ok(&self) -> bool {
        matches!(self.code, 250 | 251)
    }

    /// Converts a non-success status code into [`Error::Status`].
    pub fn into_ok(self) -> Result<Self> {
        if self.is_ok() {
            Ok(self)
        } else {
            Err(Error::Status {
                code: self.code,
                text: self.first_text().to_owned(),
            })
        }
    }

    pub fn first_text(&self) -> &str {
        self.lines.first().map_or("", |line| line.text.as_str())
    }

    /// Value of a `key=value` line, as returned by `GETINFO` and `GETCONF`.
    pub fn value(&self, key: &str) -> Option<&str> {
        self.lines
            .iter()
            .find_map(|line| line.text.strip_prefix(key)?.strip_prefix('='))
    }

    /// Payload of a multi-line `key=` block, as returned by `GETINFO md/...`.
    pub fn data(&self, key: &str) -> Option<&str> {
        self.lines
            .iter()
            .find(|line| line.text == key || line.text.starts_with(&format!("{key}=")))
            .and_then(|line| line.data.as_deref())
    }
}

/// Incremental reply parser: fed one raw line at a time, yields a [`Reply`]
/// once the terminating `<code><space>` line arrives.
#[derive(Debug, Default)]
pub(crate) struct ReplyBuilder {
    code: Option<u16>,
    lines: Vec<ReplyLine>,
    /// Text and accumulated payload of the `+` block currently being read.
    pending: Option<(String, String)>,
}

impl ReplyBuilder {
    pub(crate) fn push(&mut self, raw: &str) -> Result<Option<Reply>> {
        let line = raw.trim_end_matches('\r');

        if self.pending.is_some() {
            if line == "." {
                let (text, data) = self.pending.take().expect("pending checked above");
                self.lines.push(ReplyLine {
                    text,
                    data: Some(data),
                });
            } else {
                // A leading dot is doubled on the wire; undo that.
                let chunk = line.strip_prefix('.').unwrap_or(line);
                let (_, data) = self.pending.as_mut().expect("pending checked above");
                data.push_str(chunk);
                data.push('\n');
            }
            return Ok(None);
        }

        if line.len() < 4 {
            return Err(Error::Protocol(format!("reply line too short: {line:?}")));
        }

        let (code_text, rest) = line.split_at(3);
        let code = code_text
            .parse::<u16>()
            .map_err(|_| Error::Protocol(format!("non-numeric status code: {code_text:?}")))?;
        if let Some(previous) = self.code
            && previous != code
        {
            return Err(Error::Protocol(format!(
                "status code changed mid-reply: {previous} then {code}"
            )));
        }
        self.code = Some(code);

        let mut chars = rest.chars();
        let separator = chars.next().expect("rest is non-empty: line.len() >= 4");
        let text = chars.as_str();

        match separator {
            '-' => {
                self.lines.push(ReplyLine {
                    text: text.to_owned(),
                    data: None,
                });
                Ok(None)
            }
            '+' => {
                self.pending = Some((text.to_owned(), String::new()));
                Ok(None)
            }
            ' ' => {
                self.lines.push(ReplyLine {
                    text: text.to_owned(),
                    data: None,
                });
                self.code = None;
                Ok(Some(Reply {
                    code,
                    lines: std::mem::take(&mut self.lines),
                }))
            }
            other => Err(Error::Protocol(format!(
                "unknown reply separator {other:?}"
            ))),
        }
    }
}

/// Quotes a value for use as a control-protocol argument.
pub fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(lines: &[&str]) -> Reply {
        let mut builder = ReplyBuilder::default();
        let mut result = None;
        for line in lines {
            result = builder.push(line).expect("valid reply");
        }
        result.expect("reply terminated")
    }

    #[test]
    fn parses_single_line_reply() {
        let reply = feed(&["250 OK\r"]);
        assert_eq!(reply.code, 250);
        assert_eq!(reply.first_text(), "OK");
        assert!(reply.is_ok());
    }

    #[test]
    fn parses_multi_line_reply() {
        let reply = feed(&["250-version=0.4.8.12", "250 OK"]);
        assert_eq!(reply.value("version"), Some("0.4.8.12"));
    }

    #[test]
    fn parses_data_block_and_unescapes_dots() {
        let reply = feed(&["250+config-text=", "SocksPort 9050", "..hidden", ".", "250 OK"]);
        assert_eq!(
            reply.data("config-text"),
            Some("SocksPort 9050\n.hidden\n")
        );
    }

    #[test]
    fn surfaces_error_codes() {
        let reply = feed(&["515 Authentication failed"]);
        assert!(!reply.is_ok());
        assert!(matches!(
            reply.into_ok(),
            Err(Error::Status { code: 515, .. })
        ));
    }

    #[test]
    fn rejects_malformed_lines() {
        let mut builder = ReplyBuilder::default();
        assert!(builder.push("25").is_err());
    }

    #[test]
    fn quotes_special_characters() {
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
    }
}

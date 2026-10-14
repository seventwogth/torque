//! Parsing of asynchronous (`650`) control-protocol events.
//!
//! The variants here are the ones the UI actually renders: bootstrap progress,
//! the bandwidth graph, the circuit list and the stream-to-circuit mapping.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Notice,
    Warn,
    Err,
}

impl LogLevel {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "DEBUG" => Self::Debug,
            "INFO" => Self::Info,
            "NOTICE" => Self::Notice,
            "WARN" => Self::Warn,
            "ERR" => Self::Err,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// `BW` — bytes read and written in the last second.
    Bandwidth { read: u64, written: u64 },
    /// `STATUS_CLIENT ... BOOTSTRAP` — what the progress bar shows.
    Bootstrap {
        progress: u8,
        tag: String,
        summary: String,
    },
    Circuit(CircuitEvent),
    Stream(StreamEvent),
    Log { level: LogLevel, message: String },
    /// Any event we subscribed to but do not model yet.
    Other { kind: String, body: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitEvent {
    pub id: String,
    pub status: String,
    /// Relays as `$fingerprint~Nickname`, in order.
    pub path: Vec<String>,
    pub purpose: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEvent {
    pub id: String,
    pub status: String,
    pub circuit_id: String,
    pub target: String,
}

impl Event {
    pub fn parse(body: &str) -> Self {
        let (kind, rest) = body.split_once(' ').unwrap_or((body, ""));
        match kind {
            "BW" => parse_bandwidth(rest).unwrap_or_else(|| other(kind, rest)),
            "STATUS_CLIENT" => parse_status_client(rest).unwrap_or_else(|| other(kind, rest)),
            "CIRC" => parse_circuit(rest).unwrap_or_else(|| other(kind, rest)),
            "STREAM" => parse_stream(rest).unwrap_or_else(|| other(kind, rest)),
            _ => match LogLevel::parse(kind) {
                Some(level) => Self::Log {
                    level,
                    message: rest.to_owned(),
                },
                None => other(kind, rest),
            },
        }
    }
}

fn other(kind: &str, body: &str) -> Event {
    Event::Other {
        kind: kind.to_owned(),
        body: body.to_owned(),
    }
}

fn parse_bandwidth(rest: &str) -> Option<Event> {
    let (read, written) = rest.split_once(' ')?;
    Some(Event::Bandwidth {
        read: read.parse().ok()?,
        written: written.trim().parse().ok()?,
    })
}

fn parse_status_client(rest: &str) -> Option<Event> {
    // <severity> <action> [key=value ...]
    let tokens = tokenize(rest);
    if tokens.len() < 2 || tokens[1] != "BOOTSTRAP" {
        return None;
    }
    let pairs = key_values(&tokens[2..]);
    Some(Event::Bootstrap {
        progress: lookup(&pairs, "PROGRESS")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        tag: lookup(&pairs, "TAG").unwrap_or_default().to_owned(),
        summary: lookup(&pairs, "SUMMARY").unwrap_or_default().to_owned(),
    })
}

fn parse_circuit(rest: &str) -> Option<Event> {
    let tokens = tokenize(rest);
    let id = tokens.first()?.clone();
    let status = tokens.get(1)?.clone();

    // The path appears only once the circuit has relays, and is the only
    // positional field that can follow the status.
    let mut index = 2;
    let path = match tokens.get(index) {
        Some(token) if !token.contains('=') => {
            index += 1;
            token.split(',').map(str::to_owned).collect()
        }
        _ => Vec::new(),
    };

    let pairs = key_values(&tokens[index.min(tokens.len())..]);
    Some(Event::Circuit(CircuitEvent {
        id,
        status,
        path,
        purpose: lookup(&pairs, "PURPOSE").map(str::to_owned),
        reason: lookup(&pairs, "REASON").map(str::to_owned),
    }))
}

fn parse_stream(rest: &str) -> Option<Event> {
    let tokens = tokenize(rest);
    Some(Event::Stream(StreamEvent {
        id: tokens.first()?.clone(),
        status: tokens.get(1)?.clone(),
        circuit_id: tokens.get(2)?.clone(),
        target: tokens.get(3)?.clone(),
    }))
}

fn lookup<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn key_values(tokens: &[String]) -> Vec<(String, String)> {
    tokens
        .iter()
        .filter_map(|token| {
            let (key, value) = token.split_once('=')?;
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Splits on whitespace, honouring the protocol's double-quoted strings so
/// that `SUMMARY="Connecting to directory server"` survives as one token.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quoted = false;
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if quoted => escaped = true,
            '"' => {
                quoted = !quoted;
                started = true;
            }
            ch if ch.is_whitespace() && !quoted => {
                if started {
                    tokens.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            ch => {
                current.push(ch);
                started = true;
            }
        }
    }
    if started {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bandwidth() {
        assert_eq!(
            Event::parse("BW 1024 2048"),
            Event::Bandwidth {
                read: 1024,
                written: 2048
            }
        );
    }

    #[test]
    fn parses_bootstrap_with_quoted_summary() {
        let event = Event::parse(
            r#"STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=45 TAG=requesting_descriptors SUMMARY="Asking for relay descriptors""#,
        );
        assert_eq!(
            event,
            Event::Bootstrap {
                progress: 45,
                tag: "requesting_descriptors".to_owned(),
                summary: "Asking for relay descriptors".to_owned(),
            }
        );
    }

    #[test]
    fn parses_circuit_with_path() {
        let Event::Circuit(circuit) = Event::parse(
            "CIRC 1000 EXTENDED $AAAA~guard,$BBBB~middle BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL",
        ) else {
            panic!("expected a circuit event");
        };
        assert_eq!(circuit.id, "1000");
        assert_eq!(circuit.status, "EXTENDED");
        assert_eq!(circuit.path, ["$AAAA~guard", "$BBBB~middle"]);
        assert_eq!(circuit.purpose.as_deref(), Some("GENERAL"));
    }

    #[test]
    fn parses_circuit_without_path() {
        let Event::Circuit(circuit) = Event::parse("CIRC 1001 LAUNCHED PURPOSE=GENERAL") else {
            panic!("expected a circuit event");
        };
        assert!(circuit.path.is_empty());
        assert_eq!(circuit.purpose.as_deref(), Some("GENERAL"));
    }

    #[test]
    fn parses_stream() {
        let Event::Stream(stream) = Event::parse("STREAM 42 SUCCEEDED 1000 example.com:443") else {
            panic!("expected a stream event");
        };
        assert_eq!(stream.circuit_id, "1000");
        assert_eq!(stream.target, "example.com:443");
    }

    #[test]
    fn parses_log_lines() {
        assert_eq!(
            Event::parse("NOTICE Bootstrapped 100%"),
            Event::Log {
                level: LogLevel::Notice,
                message: "Bootstrapped 100%".to_owned(),
            }
        );
    }

    #[test]
    fn keeps_unknown_events() {
        assert_eq!(
            Event::parse("ADDRMAP example.com 1.2.3.4 NEVER"),
            Event::Other {
                kind: "ADDRMAP".to_owned(),
                body: "example.com 1.2.3.4 NEVER".to_owned(),
            }
        );
    }
}

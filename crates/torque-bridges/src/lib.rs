//! Bridge lines and the pluggable transports they imply.
//!
//! A bridge line is what the user pastes from BridgeDB, Telegram or a
//! `moat` response:
//!
//! ```text
//! obfs4 192.0.2.1:443 0123...CDEF cert=BASE64 iat-mode=0
//! snowflake 192.0.2.3:80 2B28...9B3F fingerprint=... url=https://...
//! 192.0.2.7:9001 0123...CDEF
//! ```
//!
//! Validating it here, before it reaches tor, is what lets the UI say *why* a
//! line is wrong instead of surfacing a generic `SETCONF` failure.

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("the bridge line is empty")]
    Empty,
    #[error("no address: a bridge line needs at least `IP:port`")]
    MissingAddress,
    #[error("`{0}` is not a valid IP:port address")]
    InvalidAddress(String),
    #[error("`{0}` is not a valid transport name")]
    InvalidTransport(String),
    #[error("`{0}` is not a valid 40-character hex fingerprint")]
    InvalidFingerprint(String),
    #[error("`{0}` is neither a fingerprint nor a key=value parameter")]
    UnexpectedToken(String),
}

/// One parsed `Bridge` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeLine {
    /// `None` for a vanilla bridge (a plain relay, no transport).
    pub transport: Option<String>,
    pub address: SocketAddr,
    /// Relay identity. Optional in tor's grammar, but its absence means the
    /// connection cannot be authenticated, so the UI should warn.
    pub fingerprint: Option<String>,
    /// Transport-specific parameters, order preserved (`cert`, `iat-mode`,
    /// `url`, `front`, ...). They are opaque to us and passed through verbatim.
    pub parameters: Vec<(String, String)>,
}

impl BridgeLine {
    /// True when the line carries no relay identity.
    pub fn is_unauthenticated(&self) -> bool {
        self.fingerprint.is_none()
    }

    /// Renders the value for `Bridge=` in torrc or `SETCONF`.
    pub fn to_bridge_value(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for BridgeLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(transport) = &self.transport {
            write!(f, "{transport} ")?;
        }
        write!(f, "{}", self.address)?;
        if let Some(fingerprint) = &self.fingerprint {
            write!(f, " {fingerprint}")?;
        }
        for (key, value) in &self.parameters {
            write!(f, " {key}={value}")?;
        }
        Ok(())
    }
}

impl FromStr for BridgeLine {
    type Err = ParseError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        // Tolerate a pasted `Bridge ` prefix from a torrc snippet.
        let line = line.trim();
        let line = line
            .strip_prefix("Bridge ")
            .or_else(|| line.strip_prefix("bridge "))
            .unwrap_or(line)
            .trim();
        if line.is_empty() {
            return Err(ParseError::Empty);
        }

        let mut tokens = line.split_whitespace().peekable();
        let first = tokens.next().ok_or(ParseError::Empty)?;

        // The first token is either the address or a transport name.
        let (transport, address_token) = match first.parse::<SocketAddr>() {
            Ok(_) => (None, first),
            Err(_) => {
                validate_transport(first)?;
                let address = tokens.next().ok_or(ParseError::MissingAddress)?;
                (Some(first.to_owned()), address)
            }
        };

        let address = address_token
            .parse::<SocketAddr>()
            .map_err(|_| ParseError::InvalidAddress(address_token.to_owned()))?;

        // An optional fingerprint, then key=value parameters.
        let mut fingerprint = None;
        if let Some(token) = tokens.peek()
            && !token.contains('=')
        {
            let token = tokens.next().expect("peeked above");
            fingerprint = Some(validate_fingerprint(token)?);
        }

        let mut parameters = Vec::new();
        for token in tokens {
            let (key, value) = token
                .split_once('=')
                .ok_or_else(|| ParseError::UnexpectedToken(token.to_owned()))?;
            parameters.push((key.to_owned(), value.to_owned()));
        }

        Ok(Self {
            transport,
            address,
            fingerprint,
            parameters,
        })
    }
}

fn validate_transport(name: &str) -> Result<(), ParseError> {
    let valid = !name.is_empty()
        && name.chars().next().is_some_and(|ch| ch.is_ascii_alphabetic())
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
    if valid {
        Ok(())
    } else {
        Err(ParseError::InvalidTransport(name.to_owned()))
    }
}

fn validate_fingerprint(token: &str) -> Result<String, ParseError> {
    let cleaned = token.trim_start_matches('$').replace(' ', "");
    if cleaned.len() == 40 && cleaned.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Ok(cleaned.to_ascii_uppercase())
    } else {
        Err(ParseError::InvalidFingerprint(token.to_owned()))
    }
}

/// The distinct transports a bridge set needs, in first-seen order.
///
/// This drives which `ClientTransportPlugin` lines go into torrc and which
/// helper binaries must exist in `vendor/`.
pub fn required_transports(bridges: &[BridgeLine]) -> Vec<String> {
    let mut transports: Vec<String> = Vec::new();
    for bridge in bridges {
        if let Some(transport) = &bridge.transport
            && !transports.iter().any(|known| known == transport)
        {
            transports.push(transport.clone());
        }
    }
    transports
}

/// Parses a multi-line paste, reporting each bad line with its index so the
/// UI can mark it in place rather than rejecting the whole paste.
pub fn parse_many(input: &str) -> (Vec<BridgeLine>, Vec<(usize, ParseError)>) {
    let mut bridges = Vec::new();
    let mut errors = Vec::new();
    for (index, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match trimmed.parse::<BridgeLine>() {
            Ok(bridge) => bridges.push(bridge),
            Err(error) => errors.push((index, error)),
        }
    }
    (bridges, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

    #[test]
    fn parses_obfs4_line() {
        let line = format!("obfs4 192.0.2.1:443 {FINGERPRINT} cert=abc+/= iat-mode=0");
        let bridge: BridgeLine = line.parse().expect("valid obfs4 line");
        assert_eq!(bridge.transport.as_deref(), Some("obfs4"));
        assert_eq!(bridge.address, "192.0.2.1:443".parse().unwrap());
        assert_eq!(bridge.fingerprint.as_deref(), Some(FINGERPRINT));
        assert_eq!(
            bridge.parameters,
            [
                ("cert".to_owned(), "abc+/=".to_owned()),
                ("iat-mode".to_owned(), "0".to_owned()),
            ]
        );
        assert_eq!(bridge.to_bridge_value(), line);
    }

    #[test]
    fn parses_vanilla_line_without_transport() {
        let bridge: BridgeLine = format!("192.0.2.7:9001 {FINGERPRINT}")
            .parse()
            .expect("valid vanilla line");
        assert!(bridge.transport.is_none());
        assert!(!bridge.is_unauthenticated());
    }

    #[test]
    fn parses_ipv6_address() {
        let bridge: BridgeLine = format!("obfs4 [2001:db8::1]:443 {FINGERPRINT}")
            .parse()
            .expect("valid ipv6 line");
        assert_eq!(bridge.address.port(), 443);
        assert!(bridge.address.is_ipv6());
    }

    #[test]
    fn accepts_dollar_prefixed_fingerprint_and_normalizes_case() {
        let bridge: BridgeLine = "obfs4 192.0.2.1:443 $0123456789abcdef0123456789abcdef01234567"
            .parse()
            .expect("valid line");
        assert_eq!(bridge.fingerprint.as_deref(), Some(FINGERPRINT));
    }

    #[test]
    fn accepts_line_without_fingerprint_but_flags_it() {
        let bridge: BridgeLine = "obfs4 192.0.2.1:443 cert=abc".parse().expect("valid line");
        assert!(bridge.is_unauthenticated());
        assert_eq!(bridge.parameters.len(), 1);
    }

    #[test]
    fn tolerates_torrc_prefix() {
        let bridge: BridgeLine = format!("Bridge obfs4 192.0.2.1:443 {FINGERPRINT}")
            .parse()
            .expect("valid line");
        assert_eq!(bridge.transport.as_deref(), Some("obfs4"));
    }

    #[test]
    fn rejects_missing_port() {
        assert_eq!(
            "obfs4 192.0.2.1".parse::<BridgeLine>(),
            Err(ParseError::InvalidAddress("192.0.2.1".to_owned()))
        );
    }

    #[test]
    fn rejects_short_fingerprint() {
        assert_eq!(
            "obfs4 192.0.2.1:443 DEADBEEF".parse::<BridgeLine>(),
            Err(ParseError::InvalidFingerprint("DEADBEEF".to_owned()))
        );
    }

    #[test]
    fn rejects_transport_with_no_address() {
        assert_eq!(
            "obfs4".parse::<BridgeLine>(),
            Err(ParseError::MissingAddress)
        );
    }

    #[test]
    fn rejects_empty_line() {
        assert_eq!("   ".parse::<BridgeLine>(), Err(ParseError::Empty));
    }

    #[test]
    fn collects_required_transports_in_order() {
        let input = format!(
            "obfs4 192.0.2.1:443 {FINGERPRINT}\n\
             # a comment\n\
             snowflake 192.0.2.3:80 {FINGERPRINT}\n\
             obfs4 192.0.2.2:443 {FINGERPRINT}\n\
             192.0.2.7:9001 {FINGERPRINT}\n"
        );
        let (bridges, errors) = parse_many(&input);
        assert!(errors.is_empty());
        assert_eq!(bridges.len(), 4);
        assert_eq!(required_transports(&bridges), ["obfs4", "snowflake"]);
    }

    #[test]
    fn reports_bad_lines_by_index() {
        let input = format!("obfs4 192.0.2.1:443 {FINGERPRINT}\nnonsense\n");
        let (bridges, errors) = parse_many(&input);
        assert_eq!(bridges.len(), 1);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, 1);
    }
}

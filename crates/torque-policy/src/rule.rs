use serde::{Deserialize, Serialize};

use crate::cidr::Cidr;
use crate::flow::{Flow, Protocol};

/// What to do with a flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// Through Tor. `isolation` becomes the SOCKS username, and tor isolates
    /// circuits by SOCKS credentials with `IsolateSOCKSAuth` on by default —
    /// so two rules with different tags never share a circuit or an exit.
    Tor { isolation: Option<String> },
    /// Straight out of the physical interface, bypassing Tor.
    Direct,
    Block,
}

impl Action {
    pub fn tor() -> Self {
        Self::Tor { isolation: None }
    }

    pub fn isolated(tag: impl Into<String>) -> Self {
        Self::Tor {
            isolation: Some(tag.into()),
        }
    }

    pub fn is_tor(&self) -> bool {
        matches!(self, Self::Tor { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMatch {
    /// The whole path to the executable.
    Path(String),
    /// Just the file name, e.g. `firefox.exe`.
    Name(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainMatch {
    Exact(String),
    /// The domain and everything under it: `example.com` covers
    /// `a.example.com`, but never `notexample.com`.
    Suffix(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    pub fn new(start: u16, end: u16) -> Self {
        Self {
            start: start.min(end),
            end: start.max(end),
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

// Externally tagged on purpose: an internally tagged enum cannot hold a
// newtype variant whose payload is a string or a sequence, which `Ip`,
// `Protocol` and `All` all are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Matcher {
    /// Matches every flow. Spelled out rather than left as an empty `All`,
    /// because a catch-all should be obvious in a rule list.
    Always,
    /// Cannot match a flow whose process is unknown. That is the point: see
    /// [`crate::Policy::decide`].
    Process(ProcessMatch),
    /// Cannot match a flow that went straight to an address.
    Domain(DomainMatch),
    Ip(Cidr),
    Port(PortRange),
    Protocol(Protocol),
    All(Vec<Matcher>),
    Any(Vec<Matcher>),
    Not(Box<Matcher>),
}

impl Matcher {
    pub fn matches(&self, flow: &Flow) -> bool {
        match self {
            Self::Always => true,

            Self::Process(wanted) => {
                let Some(process) = &flow.process else {
                    return false;
                };
                match wanted {
                    ProcessMatch::Path(path) => process
                        .executable
                        .as_deref()
                        .is_some_and(|actual| same_path(actual, path)),
                    ProcessMatch::Name(name) => process
                        .file_name()
                        .is_some_and(|actual| actual.eq_ignore_ascii_case(name)),
                }
            }

            Self::Domain(wanted) => {
                let Some(host) = flow.destination.host() else {
                    return false;
                };
                let host = normalize_host(host);
                match wanted {
                    DomainMatch::Exact(domain) => host == normalize_host(domain),
                    DomainMatch::Suffix(domain) => {
                        let domain = normalize_host(domain);
                        host == domain || host.ends_with(&format!(".{domain}"))
                    }
                }
            }

            Self::Ip(range) => flow
                .destination
                .address()
                .is_some_and(|address| range.contains(address)),

            Self::Port(range) => range.contains(flow.port),

            Self::Protocol(protocol) => flow.protocol == *protocol,

            // An empty `All` is vacuously true and an empty `Any` vacuously
            // false, which is what the iterator adapters already give us.
            Self::All(matchers) => matchers.iter().all(|matcher| matcher.matches(flow)),
            Self::Any(matchers) => matchers.iter().any(|matcher| matcher.matches(flow)),
            Self::Not(matcher) => !matcher.matches(flow),
        }
    }

    /// Walks the tree, skipping the inside of `Not`. Used by the advisory
    /// lints, where descending into a negation would invert their meaning.
    pub(crate) fn visit_positive(&self, visit: &mut impl FnMut(&Matcher)) {
        visit(self);
        match self {
            Self::All(matchers) | Self::Any(matchers) => {
                for matcher in matchers {
                    matcher.visit_positive(visit);
                }
            }
            Self::Not(_)
            | Self::Always
            | Self::Process(_)
            | Self::Domain(_)
            | Self::Ip(_)
            | Self::Port(_)
            | Self::Protocol(_) => {}
        }
    }
}

/// Paths are compared case-insensitively, with separators normalised.
///
/// Deliberately uniform across platforms rather than following the host's
/// rules. On Windows the filesystem is case-insensitive, so a case-sensitive
/// comparison would let a rule silently fail to apply — and a rule that
/// silently does not apply is the failure mode that leaks. Two files on Linux
/// differing only in case is the pathological case, and over-matching there is
/// the safer error.
fn same_path(left: &str, right: &str) -> bool {
    let normalize = |path: &str| path.replace('\\', "/").to_ascii_lowercase();
    normalize(left) == normalize(right)
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Free-text label for the UI; not used in matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub matcher: Matcher,
    pub action: Action,
}

fn enabled_by_default() -> bool {
    true
}

impl Rule {
    pub fn new(matcher: Matcher, action: Action) -> Self {
        Self {
            enabled: true,
            label: None,
            matcher,
            action,
        }
    }

    pub fn labelled(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

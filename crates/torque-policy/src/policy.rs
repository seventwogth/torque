use serde::{Deserialize, Serialize};

use crate::flow::{Flow, Protocol};
use crate::rule::{Action, DomainMatch, Matcher, Rule};

/// What should happen to a flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Tor { isolation: Option<String> },
    Direct,
    Blocked { reason: BlockReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// A rule, or the default, said so.
    Policy,
    /// The rule routes through Tor, and Tor carries no UDP. Distinguished from
    /// `Policy` so the UI and the log can say *why* an app went quiet, which
    /// is otherwise the hardest thing about this mode to debug.
    TorCarriesNoUdp,
}

/// A decision plus where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub decision: Decision,
    /// Index of the rule that matched, or `None` when the default applied.
    pub rule: Option<usize>,
}

/// An ordered rule list and what to do when none of them match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Applied to any flow no rule matched — including every flow whose
    /// process we failed to identify. Defaults to Tor, and anything else
    /// should be an explicit choice by the user.
    #[serde(default = "Action::tor")]
    pub default: Action,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default: Action::tor(),
        }
    }
}

impl Policy {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules,
            ..Self::default()
        }
    }

    pub fn with_default(mut self, action: Action) -> Self {
        self.default = action;
        self
    }

    /// First enabled matching rule wins; otherwise [`Self::default`].
    ///
    /// The important property is what happens when we could not tell which
    /// program opened the flow: no process rule can match it, so it falls
    /// through to the default — which is Tor. The flow we cannot identify is
    /// exactly the one that would leak if it defaulted to direct, so that
    /// case is handled by the matcher returning false rather than by a check
    /// somewhere that can be forgotten.
    pub fn decide(&self, flow: &Flow) -> Outcome {
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.enabled && rule.matcher.matches(flow) {
                return Outcome {
                    decision: decide_action(&rule.action, flow),
                    rule: Some(index),
                };
            }
        }
        Outcome {
            decision: decide_action(&self.default, flow),
            rule: None,
        }
    }

    /// Advisory checks for the rules editor. Deliberately conservative: it
    /// only reports what it is sure of, since a noisy warning list gets
    /// ignored and then the real warning goes unread.
    pub fn lints(&self) -> Vec<Lint> {
        let mut lints = Vec::new();

        if !self.default.is_tor() {
            lints.push(Lint::DefaultLeavesTor);
        }

        let mut catch_all: Option<usize> = None;
        for (index, rule) in self.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }

            if let Some(shadowed_by) = catch_all {
                lints.push(Lint::Unreachable { index, shadowed_by });
            }

            let mut mentions_udp = false;
            let mut mentions_onion = false;
            let mut is_catch_all = false;
            rule.matcher.visit_positive(&mut |matcher| match matcher {
                Matcher::Always => is_catch_all = true,
                Matcher::Protocol(Protocol::Udp) => mentions_udp = true,
                Matcher::Domain(DomainMatch::Exact(domain) | DomainMatch::Suffix(domain)) => {
                    if domain.trim_end_matches('.').to_ascii_lowercase().ends_with("onion") {
                        mentions_onion = true;
                    }
                }
                _ => {}
            });

            if mentions_udp && rule.action.is_tor() {
                lints.push(Lint::UdpThroughTor { index });
            }
            if mentions_onion && !rule.action.is_tor() {
                lints.push(Lint::OnionOutsideTor { index });
            }
            if is_catch_all && catch_all.is_none() {
                catch_all = Some(index);
            }
        }

        lints
    }
}

fn decide_action(action: &Action, flow: &Flow) -> Decision {
    match action {
        // Tor is TCP-only. Surfacing this as its own reason beats letting the
        // caller discover it, or worse, letting the packet quietly vanish.
        Action::Tor { .. } if flow.protocol == Protocol::Udp => Decision::Blocked {
            reason: BlockReason::TorCarriesNoUdp,
        },
        Action::Tor { isolation } => Decision::Tor {
            isolation: isolation.clone(),
        },
        Action::Direct => Decision::Direct,
        Action::Block => Decision::Blocked {
            reason: BlockReason::Policy,
        },
    }
}

/// Serializable so the service can hand its lints to the UI rather than each
/// side carrying its own copy of the checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Lint {
    #[error("traffic matching no rule will leave outside Tor")]
    DefaultLeavesTor,

    #[error("rule {index} can never match: rule {shadowed_by} matches everything before it")]
    Unreachable { index: usize, shadowed_by: usize },

    #[error("rule {index} routes UDP through Tor, which carries TCP only, so that traffic is dropped")]
    UdpThroughTor { index: usize },

    #[error("rule {index} routes an onion address outside Tor, where it cannot resolve")]
    OnionOutsideTor { index: usize },
}

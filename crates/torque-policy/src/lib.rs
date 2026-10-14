//! Per-app and per-host routing rules — "ProxyBridge".
//!
//! Pure logic: given a flow, which way does it go. No sockets, no OS calls,
//! no I/O, so the decision that governs whether traffic leaks is testable in
//! isolation.
//!
//! Deciding per program cannot be done at the firewall on Windows without a
//! kernel driver — `ALE_CONNECT_REDIRECT` is a callout-only layer — so the
//! decision happens in userspace instead, where the TUN device has already
//! captured every flow. This crate is that decision; `torque-router` and the
//! flow engine are what feed it. See ARCHITECTURE.md.
//!
//! Two properties are load-bearing:
//!
//! - **Unidentified flows go through Tor.** A process rule cannot match a
//!   flow whose process is unknown, so it falls through to the default, which
//!   is Tor. The flow we cannot attribute is exactly the one that would leak.
//! - **Tor carries no UDP, and the decision says so.** Routing UDP through
//!   Tor yields [`Decision::Blocked`] with
//!   [`BlockReason::TorCarriesNoUdp`], not a silent drop.
//!
//! This crate is shared across the GUI/service boundary on purpose: it is a
//! leaf with no I/O, so it is a vocabulary both halves can agree on rather
//! than an implementation leaking across.
//!
//! ```
//! use torque_policy::{Action, Flow, Matcher, Policy, ProcessInfo, ProcessMatch, Rule};
//!
//! let policy = Policy::new(vec![
//!     Rule::new(
//!         Matcher::Process(ProcessMatch::Name("curl.exe".into())),
//!         Action::Direct,
//!     ),
//! ]);
//!
//! let flow = Flow::tcp("example.com", 443)
//!     .with_process(ProcessInfo::new(42, r"C:\tools\curl.exe"));
//! assert_eq!(policy.decide(&flow).rule, Some(0));
//!
//! // Same destination, unknown program: no process rule can match, so the
//! // default applies and it goes through Tor.
//! let unattributed = Flow::tcp("example.com", 443);
//! assert_eq!(policy.decide(&unattributed).rule, None);
//! ```

mod cidr;
mod flow;
mod policy;
mod rule;

pub use cidr::{Cidr, CidrError};
pub use flow::{Destination, Flow, ProcessInfo, Protocol};
pub use policy::{BlockReason, Decision, Lint, Outcome, Policy};
pub use rule::{Action, DomainMatch, Matcher, PortRange, ProcessMatch, Rule};

#[cfg(test)]
mod tests {
    use super::*;

    fn firefox() -> ProcessInfo {
        ProcessInfo::new(100, r"C:\Program Files\Mozilla Firefox\firefox.exe")
    }

    fn tor_decision() -> Decision {
        Decision::Tor { isolation: None }
    }

    #[test]
    fn an_empty_policy_sends_everything_through_tor() {
        let outcome = Policy::default().decide(&Flow::tcp("example.com", 443));
        assert_eq!(outcome.decision, tor_decision());
        assert_eq!(outcome.rule, None);
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let policy = Policy::new(vec![
            Rule::new(Matcher::Port(PortRange::single(443)), Action::Direct),
            Rule::new(Matcher::Always, Action::Block),
        ]);
        let outcome = policy.decide(&Flow::tcp("example.com", 443));
        assert_eq!(outcome.decision, Decision::Direct);
        assert_eq!(outcome.rule, Some(0));
    }

    #[test]
    fn disabled_rules_are_skipped_without_shifting_indices() {
        let policy = Policy::new(vec![
            Rule::new(Matcher::Always, Action::Direct).disabled(),
            Rule::new(Matcher::Always, Action::Block),
        ]);
        let outcome = policy.decide(&Flow::tcp("example.com", 443));
        assert_eq!(
            outcome.decision,
            Decision::Blocked {
                reason: BlockReason::Policy
            }
        );
        assert_eq!(outcome.rule, Some(1));
    }

    #[test]
    fn an_unattributed_flow_cannot_match_a_process_rule() {
        // The leak-safety property: a flow we could not attribute falls
        // through to the default rather than inheriting a Direct rule.
        let policy = Policy::new(vec![Rule::new(
            Matcher::Process(ProcessMatch::Name("firefox.exe".into())),
            Action::Direct,
        )]);

        let attributed = Flow::tcp("example.com", 443).with_process(firefox());
        assert_eq!(policy.decide(&attributed).decision, Decision::Direct);

        let unattributed = Flow::tcp("example.com", 443);
        assert_eq!(policy.decide(&unattributed).decision, tor_decision());
        assert_eq!(policy.decide(&unattributed).rule, None);
    }

    #[test]
    fn process_names_and_paths_ignore_case_and_separator_style() {
        let by_name = Policy::new(vec![Rule::new(
            Matcher::Process(ProcessMatch::Name("FIREFOX.EXE".into())),
            Action::Direct,
        )]);
        let by_path = Policy::new(vec![Rule::new(
            Matcher::Process(ProcessMatch::Path(
                "c:/program files/mozilla firefox/firefox.exe".into(),
            )),
            Action::Direct,
        )]);

        let flow = Flow::tcp("example.com", 443).with_process(firefox());
        assert_eq!(by_name.decide(&flow).decision, Decision::Direct);
        assert_eq!(by_path.decide(&flow).decision, Decision::Direct);
    }

    #[test]
    fn a_domain_suffix_matches_only_on_a_label_boundary() {
        let policy = Policy::new(vec![Rule::new(
            Matcher::Domain(DomainMatch::Suffix("example.com".into())),
            Action::Direct,
        )]);

        for host in ["example.com", "a.example.com", "A.Example.Com.", "x.y.example.com"] {
            assert_eq!(
                policy.decide(&Flow::tcp(host, 443)).decision,
                Decision::Direct,
                "{host} should match"
            );
        }
        for host in ["notexample.com", "example.com.evil.test", "example.org"] {
            assert_eq!(
                policy.decide(&Flow::tcp(host, 443)).decision,
                tor_decision(),
                "{host} should not match"
            );
        }
    }

    #[test]
    fn domain_rules_cannot_reach_a_raw_address_connection() {
        // Nothing resolved it through us, so there is no name to match on.
        let policy = Policy::new(vec![Rule::new(
            Matcher::Domain(DomainMatch::Suffix("example.com".into())),
            Action::Direct,
        )]);
        let flow = Flow::tcp_to("192.0.2.1".parse().unwrap(), 443);
        assert_eq!(policy.decide(&flow).decision, tor_decision());
    }

    #[test]
    fn address_rules_see_the_address_a_name_resolved_to() {
        let policy = Policy::new(vec![Rule::new(
            Matcher::Ip("192.0.2.0/24".parse().unwrap()),
            Action::Block,
        )]);
        let flow = Flow::tcp("example.com", 443).with_address("192.0.2.9".parse().unwrap());
        assert_eq!(
            policy.decide(&flow).decision,
            Decision::Blocked {
                reason: BlockReason::Policy
            }
        );
    }

    #[test]
    fn udp_through_tor_is_blocked_with_its_own_reason() {
        let policy = Policy::default();
        let flow = Flow::tcp("example.com", 443).with_protocol(Protocol::Udp);
        assert_eq!(
            policy.decide(&flow).decision,
            Decision::Blocked {
                reason: BlockReason::TorCarriesNoUdp
            }
        );
    }

    #[test]
    fn udp_can_still_go_direct() {
        let policy = Policy::new(vec![Rule::new(
            Matcher::Protocol(Protocol::Udp),
            Action::Direct,
        )]);
        let flow = Flow::tcp("example.com", 443).with_protocol(Protocol::Udp);
        assert_eq!(policy.decide(&flow).decision, Decision::Direct);
    }

    #[test]
    fn isolation_tags_travel_with_the_decision() {
        let policy = Policy::new(vec![Rule::new(
            Matcher::Process(ProcessMatch::Name("firefox.exe".into())),
            Action::isolated("browser"),
        )]);
        let flow = Flow::tcp("example.com", 443).with_process(firefox());
        assert_eq!(
            policy.decide(&flow).decision,
            Decision::Tor {
                isolation: Some("browser".to_owned())
            }
        );
    }

    #[test]
    fn combinators_compose() {
        let policy = Policy::new(vec![Rule::new(
            Matcher::All(vec![
                Matcher::Process(ProcessMatch::Name("firefox.exe".into())),
                Matcher::Not(Box::new(Matcher::Domain(DomainMatch::Suffix(
                    "internal.test".into(),
                )))),
                Matcher::Any(vec![
                    Matcher::Port(PortRange::single(80)),
                    Matcher::Port(PortRange::new(443, 8443)),
                ]),
            ]),
            Action::Direct,
        )]);

        let outside = Flow::tcp("example.com", 8000).with_process(firefox());
        assert_eq!(policy.decide(&outside).decision, Decision::Direct);

        let internal = Flow::tcp("api.internal.test", 8000).with_process(firefox());
        assert_eq!(policy.decide(&internal).decision, tor_decision());

        let wrong_port = Flow::tcp("example.com", 9000).with_process(firefox());
        assert_eq!(policy.decide(&wrong_port).decision, tor_decision());
    }

    #[test]
    fn lints_flag_a_default_that_leaves_tor() {
        let policy = Policy::default().with_default(Action::Direct);
        assert!(policy.lints().contains(&Lint::DefaultLeavesTor));
        assert!(Policy::default().lints().is_empty());
    }

    #[test]
    fn lints_flag_rules_a_catch_all_has_shadowed() {
        let policy = Policy::new(vec![
            Rule::new(Matcher::Always, Action::tor()),
            Rule::new(Matcher::Port(PortRange::single(443)), Action::Direct),
        ]);
        assert!(policy.lints().contains(&Lint::Unreachable {
            index: 1,
            shadowed_by: 0
        }));
    }

    #[test]
    fn a_disabled_catch_all_shadows_nothing() {
        let policy = Policy::new(vec![
            Rule::new(Matcher::Always, Action::tor()).disabled(),
            Rule::new(Matcher::Port(PortRange::single(443)), Action::Direct),
        ]);
        assert!(!policy
            .lints()
            .iter()
            .any(|lint| matches!(lint, Lint::Unreachable { .. })));
    }

    #[test]
    fn lints_flag_udp_routed_into_tor_and_onions_routed_out_of_it() {
        let policy = Policy::new(vec![
            Rule::new(Matcher::Protocol(Protocol::Udp), Action::tor()),
            Rule::new(
                Matcher::Domain(DomainMatch::Suffix("onion".into())),
                Action::Direct,
            ),
        ]);
        let lints = policy.lints();
        assert!(lints.contains(&Lint::UdpThroughTor { index: 0 }));
        assert!(lints.contains(&Lint::OnionOutsideTor { index: 1 }));
    }

    #[test]
    fn lints_do_not_descend_into_a_negation() {
        // `not udp` is a TCP rule; reporting it as "UDP through Tor" would be
        // exactly backwards.
        let policy = Policy::new(vec![Rule::new(
            Matcher::Not(Box::new(Matcher::Protocol(Protocol::Udp))),
            Action::tor(),
        )]);
        assert!(policy.lints().is_empty());
    }

    #[test]
    fn a_policy_round_trips_through_json() {
        let policy = Policy::new(vec![
            Rule::new(
                Matcher::All(vec![
                    Matcher::Process(ProcessMatch::Name("firefox.exe".into())),
                    Matcher::Ip("10.0.0.0/8".parse().unwrap()),
                    Matcher::Protocol(Protocol::Tcp),
                ]),
                Action::isolated("browser"),
            )
            .labelled("Browser to the intranet"),
            Rule::new(Matcher::Always, Action::Block).disabled(),
        ])
        .with_default(Action::tor());

        let json = serde_json::to_string(&policy).expect("serializable");
        assert_eq!(
            serde_json::from_str::<Policy>(&json).expect("deserializable"),
            policy
        );
    }

    #[test]
    fn rules_are_enabled_when_the_field_is_absent() {
        let rule: Rule =
            serde_json::from_str(r#"{"matcher":"always","action":{"action":"direct"}}"#)
                .expect("deserializable");
        assert!(rule.enabled);
    }
}

//! A client for the service, so the IPC path can be exercised without the UI.
//!
//! This is the thing to reach for when the UI and the service disagree: it
//! speaks the same protocol with nothing else in the way.

use anyhow::{Context, Result, bail};
use torque_core::format::human_rate;
use torque_ipc::{PROTOCOL_VERSION, Request, Response, StartRequest};

pub const USAGE: &str = "\
torque-cli service <command>

  status              what the service is doing (default)
  start               start tor
  stop                stop tor
  newnym              request a new identity
  bridges <file>      replace the bridge set, one line per bridge
  policy              print the stored routing rules and their warnings";

pub async fn run(args: &[String]) -> Result<()> {
    let mut connection = torque_ipc::connect().await.with_context(|| {
        format!(
            "connecting to {} — is torque-service running?",
            torque_ipc::endpoint()
        )
    })?;

    match connection
        .request(&Request::Hello {
            version: PROTOCOL_VERSION,
        })
        .await?
    {
        Response::Hello {
            service_version, ..
        } => println!("service {service_version}, protocol {PROTOCOL_VERSION}"),
        Response::Error { message } => bail!("handshake rejected: {message}"),
        other => bail!("unexpected handshake reply: {other:?}"),
    }

    let request = match args.first().map(String::as_str) {
        None | Some("status") => Request::Status,
        Some("start") => Request::Start(StartRequest::default()),
        Some("stop") => Request::Stop,
        Some("newnym") => Request::NewIdentity,
        Some("policy") => Request::GetPolicy,
        Some("bridges") => {
            let path = args
                .get(1)
                .context("`bridges` needs a file of bridge lines")?;
            let text = tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("reading {path}"))?;
            Request::SetBridges {
                lines: text
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(str::to_owned)
                    .collect(),
            }
        }
        Some(other) => bail!("unknown command `{other}`\n\n{USAGE}"),
    };

    report(connection.request(&request).await?);
    Ok(())
}

fn report(response: Response) {
    match response {
        Response::Ok => println!("ok"),

        Response::Status(status) => {
            println!(
                "tor:      {}",
                if status.running { "running" } else { "stopped" }
            );
            println!(
                "bootstrap: {}% {}",
                status.bootstrap_progress, status.bootstrap_summary
            );
            println!("routing:  {:?}", status.routing);
            println!(
                "guards:   kill switch {}, rules {}",
                enabled(status.kill_switch_active),
                enabled(status.policy_enforced)
            );
            println!(
                "traffic:  down {} up {}",
                human_rate(status.bandwidth.read),
                human_rate(status.bandwidth.written)
            );
            println!("circuits: {}", status.circuits.len());
            for circuit in &status.circuits {
                println!(
                    "  {} {} {}",
                    circuit.id,
                    circuit.status,
                    circuit.path.join(" -> ")
                );
            }
        }

        Response::Policy { policy, lints } => {
            println!("default:  {:?}", policy.default);
            println!("rules:    {}", policy.rules.len());
            for (index, rule) in policy.rules.iter().enumerate() {
                println!(
                    "  {index} {}{} {:?}",
                    rule.label.as_deref().unwrap_or("(unlabelled)"),
                    if rule.enabled { "" } else { " [disabled]" },
                    rule.action
                );
            }
            for lint in &lints {
                println!("  warning: {lint}");
            }
        }

        Response::InvalidBridges { errors } => {
            for error in &errors {
                println!("line {}: {}", error.index + 1, error.message);
            }
        }

        Response::Error { message } => println!("error: {message}"),

        Response::Hello { .. } => println!("unexpected second handshake"),
    }
}

fn enabled(active: bool) -> &'static str {
    if active { "on" } else { "off" }
}

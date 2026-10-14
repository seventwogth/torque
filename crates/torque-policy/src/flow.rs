use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// The program that opened a flow, as far as the OS would tell us.
///
/// `executable` is the full path when we have it. Attribution can fail — a
/// short-lived flow can leave the port table before we read it — and when it
/// does, this is `None` on the [`Flow`], which no process rule can match. See
/// [`crate::ProcessMatch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub executable: Option<String>,
}

impl ProcessInfo {
    pub fn new(pid: u32, executable: impl Into<String>) -> Self {
        Self {
            pid,
            executable: Some(executable.into()),
        }
    }

    /// The file name of the executable, which is what a rule written as
    /// `firefox.exe` compares against.
    pub fn file_name(&self) -> Option<&str> {
        let path = self.executable.as_deref()?;
        let tail = path.rsplit(['/', '\\']).next().unwrap_or(path);
        (!tail.is_empty()).then_some(tail)
    }
}

/// Where a flow is headed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    /// A name, because we resolved it ourselves — we own DNS in transparent
    /// mode. `address` is the address handed back, which for `.onion` is a
    /// virtual one from tor's automapped range.
    Name {
        host: String,
        address: Option<IpAddr>,
    },
    /// A connection straight to an address: nothing resolved it through us,
    /// so only address rules can speak to it.
    Address(IpAddr),
}

impl Destination {
    pub fn host(&self) -> Option<&str> {
        match self {
            Self::Name { host, .. } => Some(host),
            Self::Address(_) => None,
        }
    }

    pub fn address(&self) -> Option<IpAddr> {
        match self {
            Self::Name { address, .. } => *address,
            Self::Address(address) => Some(*address),
        }
    }
}

/// One connection, at the moment we have to decide what to do with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow {
    pub protocol: Protocol,
    pub destination: Destination,
    pub port: u16,
    pub process: Option<ProcessInfo>,
}

impl Flow {
    /// A TCP flow to a resolved name.
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self {
            protocol: Protocol::Tcp,
            destination: Destination::Name {
                host: host.into(),
                address: None,
            },
            port,
            process: None,
        }
    }

    /// A TCP flow to a bare address.
    pub fn tcp_to(address: IpAddr, port: u16) -> Self {
        Self {
            protocol: Protocol::Tcp,
            destination: Destination::Address(address),
            port,
            process: None,
        }
    }

    pub fn with_process(mut self, process: ProcessInfo) -> Self {
        self.process = Some(process);
        self
    }

    pub fn with_address(mut self, address: IpAddr) -> Self {
        if let Destination::Name {
            address: slot,
            host: _,
        } = &mut self.destination
        {
            *slot = Some(address);
        } else {
            self.destination = Destination::Address(address);
        }
        self
    }

    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_file_name_from_either_separator() {
        assert_eq!(
            ProcessInfo::new(1, r"C:\Program Files\Mozilla Firefox\firefox.exe").file_name(),
            Some("firefox.exe")
        );
        assert_eq!(
            ProcessInfo::new(1, "/usr/bin/curl").file_name(),
            Some("curl")
        );
        assert_eq!(ProcessInfo::new(1, "curl").file_name(), Some("curl"));
    }

    #[test]
    fn unknown_executables_have_no_file_name() {
        let process = ProcessInfo {
            pid: 7,
            executable: None,
        };
        assert_eq!(process.file_name(), None);
    }

    #[test]
    fn a_bare_address_destination_has_no_host() {
        let flow = Flow::tcp_to("192.0.2.1".parse().unwrap(), 443);
        assert_eq!(flow.destination.host(), None);
        assert!(flow.destination.address().is_some());
    }

    #[test]
    fn a_resolved_name_keeps_both_name_and_address() {
        let flow = Flow::tcp("example.com", 443).with_address("192.0.2.1".parse().unwrap());
        assert_eq!(flow.destination.host(), Some("example.com"));
        assert_eq!(
            flow.destination.address(),
            Some("192.0.2.1".parse().unwrap())
        );
    }
}

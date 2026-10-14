use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CidrError {
    #[error("`{0}` is not an IP address")]
    Address(String),
    #[error("`{0}` is not a prefix length")]
    Prefix(String),
    #[error("prefix /{prefix} is too long for {family}")]
    PrefixTooLong { prefix: u8, family: &'static str },
}

/// An address range, as written in a rule: `10.0.0.0/8`, `2001:db8::/32`, or
/// a bare address meaning a single host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Cidr {
    address: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn new(address: IpAddr, prefix: u8) -> Result<Self, CidrError> {
        let (max, family) = match address {
            IpAddr::V4(_) => (32, "IPv4"),
            IpAddr::V6(_) => (128, "IPv6"),
        };
        if prefix > max {
            return Err(CidrError::PrefixTooLong { prefix, family });
        }
        Ok(Self { address, prefix })
    }

    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Addresses of a different family never match, rather than being coerced
    /// through a v4-mapped form — a rule written for one family should not
    /// quietly govern the other.
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = mask_u32(self.prefix);
                network.to_bits() & mask == candidate.to_bits() & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = mask_u128(self.prefix);
                network.to_bits() & mask == candidate.to_bits() & mask
            }
            _ => false,
        }
    }
}

/// `u32::MAX << 32` is undefined, so a /0 mask is spelled out.
fn mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let Some((address, prefix)) = text.split_once('/') else {
            // A bare address is the single-host range.
            let address: IpAddr = text
                .parse()
                .map_err(|_| CidrError::Address(text.to_owned()))?;
            let prefix = if address.is_ipv4() { 32 } else { 128 };
            return Self::new(address, prefix);
        };

        let address: IpAddr = address
            .parse()
            .map_err(|_| CidrError::Address(address.to_owned()))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| CidrError::Prefix(prefix.to_owned()))?;
        Self::new(address, prefix)
    }
}

impl From<Cidr> for String {
    fn from(cidr: Cidr) -> Self {
        cidr.to_string()
    }
}

impl TryFrom<String> for Cidr {
    type Error = CidrError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        text.parse().expect("valid cidr")
    }

    #[test]
    fn matches_inside_an_ipv4_range() {
        let range = cidr("10.0.0.0/8");
        assert!(range.contains("10.1.2.3".parse().unwrap()));
        assert!(!range.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn a_bare_address_is_a_single_host() {
        let range = cidr("192.0.2.5");
        assert_eq!(range.prefix(), 32);
        assert!(range.contains("192.0.2.5".parse().unwrap()));
        assert!(!range.contains("192.0.2.6".parse().unwrap()));
    }

    #[test]
    fn prefix_zero_matches_everything_in_its_family() {
        let range = cidr("0.0.0.0/0");
        assert!(range.contains("8.8.8.8".parse().unwrap()));
        // …but still not the other family.
        assert!(!range.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn matches_inside_an_ipv6_range() {
        let range = cidr("2001:db8::/32");
        assert!(range.contains("2001:db8:1234::1".parse().unwrap()));
        assert!(!range.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn families_never_cross() {
        assert!(!cidr("::/0").contains("1.2.3.4".parse().unwrap()));
        assert!(!cidr("10.0.0.0/8").contains("::1".parse().unwrap()));
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(
            "nonsense".parse::<Cidr>(),
            Err(CidrError::Address("nonsense".to_owned()))
        );
        assert_eq!(
            "10.0.0.0/x".parse::<Cidr>(),
            Err(CidrError::Prefix("x".to_owned()))
        );
        assert_eq!(
            "10.0.0.0/33".parse::<Cidr>(),
            Err(CidrError::PrefixTooLong {
                prefix: 33,
                family: "IPv4"
            })
        );
        assert!("2001:db8::/129".parse::<Cidr>().is_err());
    }

    #[test]
    fn serializes_as_the_text_a_user_would_write() {
        let range = cidr("10.0.0.0/8");
        let json = serde_json::to_string(&range).expect("serializable");
        assert_eq!(json, r#""10.0.0.0/8""#);
        assert_eq!(
            serde_json::from_str::<Cidr>(&json).expect("deserializable"),
            range
        );
    }
}

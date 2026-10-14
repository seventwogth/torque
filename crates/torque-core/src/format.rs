//! Formatting shared by every front end, so the CLI and the UI never disagree
//! about what a number means.

/// Formats a per-second byte rate.
pub fn human_rate(bytes_per_second: u64) -> String {
    const UNITS: [&str; 4] = ["B/s", "KiB/s", "MiB/s", "GiB/s"];
    let mut value = bytes_per_second as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes_per_second} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Shortens a relay as reported by tor — `$FINGERPRINT~Nickname` — to the
/// nickname, which is what a circuit list should show.
pub fn relay_nickname(hop: &str) -> &str {
    hop.split_once('~')
        .map_or(hop, |(_, nickname)| nickname)
        .trim_start_matches('$')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_rates_without_decimals_for_bytes() {
        assert_eq!(human_rate(0), "0 B/s");
        assert_eq!(human_rate(999), "999 B/s");
    }

    #[test]
    fn scales_to_larger_units() {
        assert_eq!(human_rate(1024), "1.0 KiB/s");
        assert_eq!(human_rate(1024 * 1024 * 3 / 2), "1.5 MiB/s");
        assert_eq!(human_rate(1024 * 1024 * 1024), "1.0 GiB/s");
    }

    #[test]
    fn caps_at_the_largest_unit() {
        assert!(human_rate(u64::MAX).ends_with("GiB/s"));
    }

    #[test]
    fn extracts_nicknames_from_relay_identifiers() {
        assert_eq!(relay_nickname("$ABCD~Unnamed"), "Unnamed");
        // Tor omits the nickname when it does not know it.
        assert_eq!(relay_nickname("$ABCD"), "ABCD");
        assert_eq!(relay_nickname("Unnamed"), "Unnamed");
    }
}

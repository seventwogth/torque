use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Where Torque keeps its own state, and where the bundled binaries live.
#[derive(Debug, Clone)]
pub struct Layout {
    /// Tor's `DataDirectory`, the generated torrc, the control-port file.
    pub data_dir: PathBuf,
    /// Directory holding `tor`, `lyrebird`, `snowflake-client`, geoip data.
    pub vendor_dir: PathBuf,
}

impl Layout {
    /// Per-user layout: state under the OS data dir, binaries next to the
    /// executable (where the installer puts them).
    pub fn discover() -> Result<Self> {
        let project = directories::ProjectDirs::from("", "", "torque")
            .ok_or_else(|| Error::Layout("no home directory for this user".to_owned()))?;
        Ok(Self {
            data_dir: project.data_local_dir().join("tor"),
            vendor_dir: vendor_dir_next_to_executable()?,
        })
    }

    pub fn torrc(&self) -> PathBuf {
        self.data_dir.join("torrc")
    }

    /// Tor writes the port it actually bound here, which is how `ControlPort
    /// auto` stays usable: no fixed port to collide with a system tor.
    pub fn control_port_file(&self) -> PathBuf {
        self.data_dir.join("control-port")
    }

    pub fn cookie(&self) -> PathBuf {
        self.data_dir.join("control_auth_cookie")
    }

    pub fn tor_binary(&self) -> PathBuf {
        self.vendor_dir.join(executable_name("tor"))
    }

    pub fn vendor_binary(&self, stem: &str) -> PathBuf {
        self.vendor_dir.join(executable_name(stem))
    }

    pub fn geoip(&self) -> PathBuf {
        self.vendor_dir.join("geoip")
    }

    pub fn geoip6(&self) -> PathBuf {
        self.vendor_dir.join("geoip6")
    }

    pub async fn ensure_data_dir(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.data_dir).await?;
        Ok(())
    }
}

fn vendor_dir_next_to_executable() -> Result<PathBuf> {
    // Falls back to ./vendor so `cargo run` works from a checkout.
    let fallback = PathBuf::from("vendor");
    let Ok(exe) = std::env::current_exe() else {
        return Ok(fallback);
    };
    Ok(exe
        .parent()
        .map(|dir| dir.join("vendor"))
        .unwrap_or(fallback))
}

pub fn executable_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_owned()
    }
}

/// Renders a path for torrc.
///
/// Backslashes are escape characters inside tor's quoted strings, so Windows
/// paths are emitted with forward slashes — which tor accepts — rather than
/// doubled separators.
pub fn torrc_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_windows_separators_for_torrc() {
        let rendered = torrc_path(Path::new(r"C:\Users\me\AppData\torque\tor"));
        assert_eq!(rendered, "C:/Users/me/AppData/torque/tor");
    }

    #[test]
    fn executable_name_matches_platform() {
        let name = executable_name("tor");
        if cfg!(windows) {
            assert_eq!(name, "tor.exe");
        } else {
            assert_eq!(name, "tor");
        }
    }
}

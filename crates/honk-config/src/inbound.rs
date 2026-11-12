//! Inbound proxy listeners (`inbound { ... }`).
//!
//! These are process-scoped server sockets that accept proxied traffic from
//! the LAN, authenticate it, and feed it into the same routing and outbound
//! machinery as transparently intercepted flows.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Top-level `inbound { ... }` section. Empty by default: no listener is
/// served unless the operator declares one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InboundConfig {
    /// SOCKS5 listeners, one per `socks5 { ... }` block, in file order.
    #[serde(default)]
    pub socks5: Vec<Socks5Inbound>,
}

impl InboundConfig {
    /// Structural validation shared by every config entry path (dae text,
    /// serde/native assembly). The parser adds spans where it has them.
    /// Errors carry the offending listener index for diagnostics.
    pub fn validate(&self) -> Result<(), (usize, &'static str)> {
        for (index, listener) in self.socks5.iter().enumerate() {
            listener.validate().map_err(|reason| (index, reason))?;
        }
        Ok(())
    }
}

/// One SOCKS5 server socket with RFC 1929 username/password authentication.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Inbound {
    /// `host:port` to listen on. A hostname is resolved at bind time, exactly
    /// like `dns.bind`.
    pub bind: String,
    /// Authentication users. A listener with no user is rejected: an
    /// unauthenticated SOCKS5 open relay is never the intended default.
    #[serde(default)]
    pub users: Vec<Socks5User>,
}

/// Deliberately manual: `Debug` must never print the password.
impl std::fmt::Debug for Socks5Inbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5Inbound")
            .field("bind", &self.bind)
            .field("users", &self.users)
            .finish()
    }
}

/// One `username: password` entry of a `users { ... }` block.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5User {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for Socks5User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5User")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

impl Socks5Inbound {
    fn validate(&self) -> Result<(), &'static str> {
        if !bind_is_well_formed(&self.bind) {
            return Err("bind must be a host:port address with a non-zero port");
        }
        if self.users.is_empty() {
            return Err("a socks5 inbound requires at least one user");
        }
        let mut seen = HashSet::new();
        for user in &self.users {
            // RFC 1929 encodes both fields as a single length byte.
            if user.username.is_empty() {
                return Err("user name must not be empty");
            }
            if user.username.len() > 255 || user.password.len() > 255 {
                return Err("user name and password must be at most 255 bytes (RFC 1929)");
            }
            if !seen.insert(user.username.as_str()) {
                return Err("duplicate user name in one socks5 listener");
            }
        }
        Ok(())
    }
}

/// Syntax-only check; resolution happens at bind time like `dns.bind`.
fn bind_is_well_formed(bind: &str) -> bool {
    if let Ok(addr) = bind.trim().parse::<std::net::SocketAddr>() {
        return addr.port() != 0;
    }
    bind.trim()
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(bind: &str, users: &[(&str, &str)]) -> Socks5Inbound {
        Socks5Inbound {
            bind: bind.to_string(),
            users: users
                .iter()
                .map(|(username, password)| Socks5User {
                    username: (*username).to_string(),
                    password: (*password).to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn accepts_well_formed_listeners() {
        assert!(
            InboundConfig {
                socks5: vec![listener("0.0.0.0:7894", &[("alice", "pw")])],
            }
            .validate()
            .is_ok()
        );
        assert!(
            listener("[::1]:7894", &[("alice", "pw")])
                .validate()
                .is_ok()
        );
        assert!(
            listener("example.invalid:7894", &[("alice", "pw")])
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn rejects_unauthenticated_or_malformed_listeners() {
        assert!(listener("0.0.0.0:7894", &[]).validate().is_err());
        assert!(listener("", &[("alice", "pw")]).validate().is_err());
        assert!(
            listener("0.0.0.0:0", &[("alice", "pw")])
                .validate()
                .is_err()
        );
        assert!(
            listener("0.0.0.0:70000", &[("alice", "pw")])
                .validate()
                .is_err()
        );
        assert!(listener("0.0.0.0:7894", &[("", "pw")]).validate().is_err());
        assert!(
            listener("0.0.0.0:7894", &[("alice", "pw"), ("alice", "other")])
                .validate()
                .is_err()
        );
        assert!(
            listener("0.0.0.0:7894", &[("x".repeat(256).as_str(), "pw")])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn debug_redacts_passwords() {
        let text = format!("{:?}", listener("0.0.0.0:7894", &[("alice", "hunter2")]));
        assert!(!text.contains("hunter2"));
        assert!(text.contains("alice"));
    }
}

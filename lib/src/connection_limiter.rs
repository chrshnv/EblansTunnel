use crate::tls_demultiplexer::Protocol;
use crate::user_store::UserRegistry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct ClientEntry {
    http2_count: u32,
    http3_count: u32,
}

/// Tracks active connections per client and enforces per-client limits.
pub(crate) struct ConnectionLimiter {
    users: Arc<UserRegistry>,
    clients: Mutex<HashMap<String, ClientEntry>>,
    default_max_http2: Option<u32>,
    default_max_http3: Option<u32>,
}

/// RAII guard that decrements the connection count when dropped.
pub(crate) struct ConnectionGuard {
    limiter: Arc<ConnectionLimiter>,
    username: String,
    protocol: Protocol,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.limiter.release(&self.username, self.protocol);
    }
}

impl ConnectionLimiter {
    pub fn new(
        users: Arc<UserRegistry>,
        default_max_http2: Option<u32>,
        default_max_http3: Option<u32>,
    ) -> Self {
        Self {
            users,
            clients: Mutex::new(HashMap::new()),
            default_max_http2,
            default_max_http3,
        }
    }

    /// Try to acquire a connection slot for the given authenticated user and protocol.
    ///
    /// Returns `Some(guard)` on success — the guard releases the slot on drop.
    /// Returns `None` if the per-client limit is exceeded or the user is unknown.
    pub fn try_acquire(
        self: &Arc<Self>,
        username: &str,
        protocol: Protocol,
    ) -> Option<ConnectionGuard> {
        let (max_http2, max_http3) = self.users.get_connection_limits(username)?;
        let mut clients = self.clients.lock().unwrap();
        let entry = clients.entry(username.to_owned()).or_default();

        let (current, limit) = match protocol {
            Protocol::Http1 | Protocol::Http2 => {
                let limit = max_http2.or(self.default_max_http2);
                (&mut entry.http2_count, limit)
            }
            Protocol::Http3 => {
                let limit = max_http3.or(self.default_max_http3);
                (&mut entry.http3_count, limit)
            }
        };

        if let Some(max) = limit {
            if *current >= max {
                return None;
            }
        }

        *current += 1;
        Some(ConnectionGuard {
            limiter: self.clone(),
            username: username.to_owned(),
            protocol,
        })
    }

    fn release(&self, username: &str, protocol: Protocol) {
        let mut clients = self.clients.lock().unwrap();
        if let Some(entry) = clients.get_mut(username) {
            match protocol {
                Protocol::Http1 | Protocol::Http2 => {
                    entry.http2_count = entry.http2_count.saturating_sub(1);
                }
                Protocol::Http3 => {
                    entry.http3_count = entry.http3_count.saturating_sub(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::registry_based::Client;
    use crate::settings::{Http1Settings, ListenProtocolSettings, Settings};
    use std::net::Ipv4Addr;

    fn make_client(username: &str, password: &str) -> Client {
        Client {
            username: username.into(),
            password: password.into(),
            max_http2_conns: None,
            max_http3_conns: None,
        }
    }

    fn make_client_with_limits(
        username: &str,
        password: &str,
        h2: Option<u32>,
        h3: Option<u32>,
    ) -> Client {
        Client {
            username: username.into(),
            password: password.into(),
            max_http2_conns: h2,
            max_http3_conns: h3,
        }
    }

    fn make_registry(clients: Vec<Client>) -> Arc<UserRegistry> {
        let settings = Settings::builder()
            .listen_address((Ipv4Addr::LOCALHOST, 8443))
            .unwrap()
            .listen_protocols(ListenProtocolSettings {
                http1: Some(Http1Settings::builder().build()),
                ..Default::default()
            })
            .clients(clients)
            .build()
            .unwrap();
        UserRegistry::from_settings(&settings).unwrap().unwrap()
    }

    #[test]
    fn no_limits_always_passes() {
        let registry = make_registry(vec![make_client("u", "p")]);
        let limiter = Arc::new(ConnectionLimiter::new(registry, None, None));
        let g1 = limiter.try_acquire("u", Protocol::Http2).unwrap();
        let g2 = limiter.try_acquire("u", Protocol::Http2).unwrap();
        let g3 = limiter.try_acquire("u", Protocol::Http3).unwrap();
        drop((g1, g2, g3));
    }

    #[test]
    fn global_http2_limit_enforced() {
        let registry = make_registry(vec![make_client("u", "p")]);
        let limiter = Arc::new(ConnectionLimiter::new(registry, Some(2), None));

        let g1 = limiter.try_acquire("u", Protocol::Http2).unwrap();
        let g2 = limiter.try_acquire("u", Protocol::Http2).unwrap();
        assert!(
            limiter.try_acquire("u", Protocol::Http2).is_none(),
            "must be denied at limit=2"
        );

        drop(g1);
        let g3 = limiter.try_acquire("u", Protocol::Http2).unwrap();
        drop((g2, g3));
    }

    #[test]
    fn global_http3_limit_enforced() {
        let registry = make_registry(vec![make_client("u", "p")]);
        let limiter = Arc::new(ConnectionLimiter::new(registry, None, Some(1)));

        let g1 = limiter.try_acquire("u", Protocol::Http3).unwrap();
        assert!(
            limiter.try_acquire("u", Protocol::Http3).is_none(),
            "must be denied at limit=1"
        );

        drop(g1);
        limiter.try_acquire("u", Protocol::Http3).unwrap();
    }

    #[test]
    fn http2_and_http3_counters_are_independent() {
        let registry = make_registry(vec![make_client("u", "p")]);
        let limiter = Arc::new(ConnectionLimiter::new(registry, Some(1), Some(1)));

        let _g2 = limiter.try_acquire("u", Protocol::Http2).unwrap();
        let _g3 = limiter.try_acquire("u", Protocol::Http3).unwrap();
        assert!(
            limiter.try_acquire("u", Protocol::Http2).is_none(),
            "http2 must be at limit"
        );
        assert!(
            limiter.try_acquire("u", Protocol::Http3).is_none(),
            "http3 must be at limit"
        );
    }

    #[test]
    fn per_client_override_takes_precedence_over_global() {
        let clients = vec![
            make_client_with_limits("alice", "pass", Some(5), None),
            make_client("bob", "pass"),
        ];
        let registry = make_registry(clients);
        let limiter = Arc::new(ConnectionLimiter::new(registry, Some(1), None));

        let _a1 = limiter.try_acquire("alice", Protocol::Http2).unwrap();
        let _a2 = limiter.try_acquire("alice", Protocol::Http2).unwrap();
        let _a3 = limiter.try_acquire("alice", Protocol::Http2).unwrap();
        let _a4 = limiter.try_acquire("alice", Protocol::Http2).unwrap();
        let _a5 = limiter.try_acquire("alice", Protocol::Http2).unwrap();
        assert!(
            limiter.try_acquire("alice", Protocol::Http2).is_none(),
            "alice: must be denied at override limit=5"
        );

        let _b1 = limiter.try_acquire("bob", Protocol::Http2).unwrap();
        assert!(
            limiter.try_acquire("bob", Protocol::Http2).is_none(),
            "bob: must be denied at global limit=1"
        );
    }

    #[test]
    fn limits_are_per_client_not_shared() {
        let clients = vec![make_client("alice", "pass"), make_client("bob", "pass")];
        let registry = make_registry(clients);
        let limiter = Arc::new(ConnectionLimiter::new(registry, Some(1), None));

        let _ga = limiter.try_acquire("alice", Protocol::Http2).unwrap();
        let _gb = limiter.try_acquire("bob", Protocol::Http2).unwrap();
        assert!(
            limiter.try_acquire("alice", Protocol::Http2).is_none(),
            "alice at limit"
        );
        assert!(
            limiter.try_acquire("bob", Protocol::Http2).is_none(),
            "bob at limit"
        );
    }

    #[test]
    fn unknown_user_denied() {
        let registry = make_registry(vec![make_client("u", "p")]);
        let limiter = Arc::new(ConnectionLimiter::new(registry, None, None));
        assert!(limiter.try_acquire("unknown", Protocol::Http2).is_none());
    }
}

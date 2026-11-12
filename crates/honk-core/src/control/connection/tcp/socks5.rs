//! SOCKS5 inbound sessions: RFC 1929 username/password authentication and
//! the CONNECT relay onto the ordinary outbound machinery.
//!
//! This lives inside the TCP connection module tree on purpose: an
//! authenticated session is one more TCP flow that reaches its outbound
//! through the same score plan, candidate race, and relay helpers that
//! intercepted traffic uses, and those helpers stay `pub(super)` here.
//! The authenticated username is carried as the flow's routing user, so
//! `user()` rules select its outbound like mihomo's `in-user`.

use super::*;
use crate::relay::{RelayProgress, relay_proxy};
use honk_config::inbound::Socks5User;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Bound on the client-driven handshake before dialing; a session that
/// stalls in the handshake is dropped instead of holding admission permits.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

// RFC 1928 reply codes this inbound emits.
const REP_GENERAL: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_COMMAND_UNSUPPORTED: u8 = 0x07;
const REP_ADDRESS_UNSUPPORTED: u8 = 0x08;

/// Client-requested destination before local name resolution.
enum Socks5Request {
    Address(SocketAddr),
    Domain { domain: String, port: u16 },
}

fn encode_reply(rep: u8, bound: SocketAddr) -> Vec<u8> {
    let mut reply = Vec::with_capacity(26);
    reply.extend_from_slice(&[5, rep, 0]);
    reply.push(match bound {
        SocketAddr::V4(_) => 1,
        SocketAddr::V6(_) => 4,
    });
    match bound {
        SocketAddr::V4(address) => reply.extend_from_slice(&address.ip().octets()),
        SocketAddr::V6(address) => reply.extend_from_slice(&address.ip().octets()),
    }
    reply.extend_from_slice(&bound.port().to_be_bytes());
    reply
}

/// Failure replies carry no meaningful binding; echo the zeros reference
/// servers do and let the client read the reply field.
async fn write_failure(stream: &mut TcpStream, rep: u8) {
    let _ = stream.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]).await;
}

impl ControlPlaneHandle {
    /// Serve one accepted SOCKS5 session end to end. A rejected
    /// authentication or a policy refusal completes with `Ok(())` after
    /// sending the protocol-level failure reply; `Err` is reserved for
    /// transport and runtime failures the supervisor logs.
    pub(in crate::control) async fn serve_socks5(
        &self,
        mut stream: TcpStream,
        client_addr: SocketAddr,
        users: &[Socks5User],
    ) -> anyhow::Result<()> {
        let Some((user, request)) = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            self.socks5_handshake(&mut stream, client_addr, users),
        )
        .await??
        else {
            return Ok(());
        };

        let (target_addr, domain) = match request {
            Socks5Request::Address(address) => (address, None),
            Socks5Request::Domain { domain, port } => {
                // The client handed us a name instead of the IP its own
                // resolver saw (intercepted flows dial an already-resolved
                // IP), so resolve it through honk's DNS to keep dip/geoip
                // routing and direct dials honest. Proxies still resolve
                // remotely through `target_domain` below.
                let resolved = match self
                    .dns_resolver
                    .resolve_for_source(&domain, client_addr)
                    .await
                {
                    Ok(resolved) => resolved,
                    Err(error) => {
                        debug!(%error, %domain, "SOCKS5 target resolution failed");
                        write_failure(&mut stream, REP_HOST_UNREACHABLE).await;
                        return Ok(());
                    }
                };
                let Some(address) = resolved
                    .ipv4
                    .first()
                    .or_else(|| resolved.ipv6.first())
                    .copied()
                else {
                    write_failure(&mut stream, REP_HOST_UNREACHABLE).await;
                    return Ok(());
                };
                (SocketAddr::new(address, port), Some(domain))
            }
        };

        let (dial_mode, connect_timeout, overall_dial_timeout) = {
            let config = self.config.read().await;
            let connect_timeout = Duration::from_millis(config.global.connect_timeout_ms);
            (
                config
                    .global
                    .dial_mode
                    .parse::<DialMode>()
                    .map_err(|_| anyhow::anyhow!("invalid global.dial_mode"))?,
                connect_timeout,
                overall_dial_timeout(connect_timeout),
            )
        };
        let conn_info = crate::routing::ConnectionInfo {
            domain: domain.clone(),
            dst_ip: target_addr.ip(),
            dst_port: target_addr.port(),
            src_ip: client_addr.ip(),
            src_port: client_addr.port(),
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
            user: Some(user.clone()),
        };
        let mut observation = ConnectionObservation::begin(
            self.native.as_deref(),
            crate::observe::vocab::Network::Tcp,
            client_addr,
            target_addr,
        );
        // The client named the destination itself, so the domain is verified.
        let mut route = self
            .prepare_routing(
                dial_mode,
                &conn_info,
                true,
                None,
                #[cfg(feature = "native-api")]
                observation.is_recording(),
            )
            .await;
        let mode_decision = self.apply_mode_override(&mut route).await;
        let outbound_name = mode_decision.name;
        let mode_constraint = mode_decision.constraint;

        // Config's publication guard pins the group and runtime handles.
        let (generation_config, generation_group_manager, runtime_generation) = {
            let config = self.config.read().await;
            (
                Arc::clone(&config),
                self.group_manager.read().clone(),
                self.runtime_registry.read().clone(),
            )
        };
        let outbound_kind =
            crate::stats::OutboundKind::routed(&generation_group_manager, &outbound_name);
        let outbound_guard = self.stats.track_connection(&outbound_name, outbound_kind);

        let ipver = if target_addr.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let (
            mut candidates,
            selection_mode,
            mut score_feedback,
            selection_chains,
            _final_owners,
            health_ipver,
        ) = {
            let context = tcp_score_context(target_addr, domain.as_deref(), ipver);
            let plan = observation.observe_tcp_plan(None, || {
                crate::control::reload::resolve_outbound_plan_for_target(
                    &generation_config,
                    &generation_group_manager,
                    &outbound_name,
                    &context,
                    mode_constraint,
                )
            });
            unpack_tcp_score_plan(plan)
        };
        // Same speculation bound as intercepted TCP: only a cold URLTest
        // group may race more than one candidate.
        if selection_mode == SelectionPlanMode::ColdUrlTest {
            candidates.truncate(3);
        } else {
            candidates.truncate(1);
        }
        score_feedback.retain(|id, _| candidates.iter().any(|node| node.id == *id));

        if candidates.is_empty() {
            debug!(
                user = %user,
                outbound = %outbound_name,
                "SOCKS5 has no available candidate nodes"
            );
            let group_manager = self.group_manager.read().clone();
            for node in group_manager.leaf_nodes_in_group(&outbound_name) {
                self.alive_set.notify_check_tcp(node.id);
            }
            self.stats.record_error(&outbound_name, outbound_kind);
            drop(outbound_guard);
            let rep = if outbound_name == "block" {
                REP_NOT_ALLOWED
            } else {
                REP_GENERAL
            };
            write_failure(&mut stream, rep).await;
            return Ok(());
        }
        // Reserved outbounds always dial by address; named proxies take the
        // domain for remote resolution when we have one.
        let target_domain = if matches!(
            outbound_name.as_str(),
            "direct" | "block" | "must_rules" | "control_plane_routing"
        ) {
            None
        } else {
            domain.clone()
        };

        let cold_urltest = selection_mode == SelectionPlanMode::ColdUrlTest;
        let candidate_refs: Vec<&Node> = candidates.iter().collect();
        let dial_deadline = tokio::time::Instant::now() + overall_dial_timeout;
        let raced = self
            .race_candidates(
                &candidate_refs,
                target_addr,
                target_domain.clone(),
                &outbound_name,
                outbound_kind,
                route.mark,
                connect_timeout,
                dial_deadline,
                Arc::clone(&runtime_generation),
                health_ipver,
                &score_feedback,
                cold_urltest,
                #[cfg(feature = "native-api")]
                &selection_chains,
                #[cfg(feature = "native-api")]
                &observation,
            )
            .await;
        let winner = match raced {
            Ok(Some(winner)) => winner,
            Ok(None) => {
                self.stats.record_error(&outbound_name, outbound_kind);
                drop(outbound_guard);
                let rep = if outbound_name == "block" || only_block_nodes(&candidates) {
                    REP_NOT_ALLOWED
                } else {
                    REP_GENERAL
                };
                write_failure(&mut stream, rep).await;
                return Ok(());
            }
            Err(error) => {
                drop(outbound_guard);
                return Err(error);
            }
        };
        let proxy_stream = winner.stream;
        let node = winner.node;
        let score_reporter = winner.reporter;
        drop(score_feedback);

        let bound = stream.local_addr()?;
        stream.write_all(&encode_reply(0, bound)).await?;
        debug!(
            network = "socks5",
            user = %user,
            outbound = %outbound_name,
            dialer = %node.name,
            target = %target_addr,
            sniffed = target_domain.as_deref().unwrap_or(""),
            src = %client_addr,
            "SOCKS5 session established"
        );

        let conn_upload = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let conn_download = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (outbound_upload, outbound_download) =
            self.stats.byte_counters(&outbound_name, outbound_kind);
        let first_response = score_reporter.as_ref().map(|reporter| {
            let reporter = reporter.clone();
            std::sync::Arc::new(move || reporter.first_response())
                as std::sync::Arc<dyn Fn() + Send + Sync>
        });
        let on_transfer = score_reporter.as_ref().map(|reporter| {
            let reporter = reporter.clone();
            std::sync::Arc::new(move |upload, download| {
                if upload != 0 {
                    reporter.tx(upload);
                }
                if download != 0 {
                    reporter.rx(download);
                }
            }) as std::sync::Arc<dyn Fn(u64, u64) + Send + Sync>
        });
        let relay_result = relay_proxy(
            &mut stream,
            proxy_stream,
            client_addr,
            target_addr,
            RelayProgress {
                upload: conn_upload,
                download: conn_download,
                outbound_upload: Some(outbound_upload),
                outbound_download: Some(outbound_download),
                first_response,
                on_transfer,
            },
        )
        .await;
        match &relay_result {
            Ok(_) => {
                if let Some(reporter) = &score_reporter {
                    reporter.finish(crate::group::ScoreOutcome::Success);
                }
            }
            Err(error) => {
                let io_err = error.downcast_ref::<std::io::Error>();
                if io_err.is_some_and(|error| crate::relay::is_ignorable_connection_error(error)) {
                    debug!(
                        "SOCKS5 relay closed for {user}: {} -> {}",
                        client_addr, target_addr
                    );
                } else {
                    debug!(%error, "SOCKS5 relay ended for {}: {}", user, target_addr);
                }
                self.stats.record_error(&outbound_name, outbound_kind);
                if let Some(reporter) = &score_reporter {
                    reporter.finish(tcp_relay_score_outcome(error));
                }
            }
        }
        drop(outbound_guard);
        relay_result.map(|_| ())
    }

    /// Greeting, RFC 1929 subnegotiation, and CONNECT request framing.
    /// `Ok(None)` means the session was refused with a protocol reply (or
    /// the peer closed); the caller then drops the socket without dialing.
    async fn socks5_handshake(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        users: &[Socks5User],
    ) -> anyhow::Result<Option<(String, Socks5Request)>> {
        // Greeting (RFC 1928): username/password is the only method offered.
        if stream.read_u8().await? != 5 {
            return Ok(None);
        }
        let method_count = stream.read_u8().await?;
        if method_count == 0 {
            return Ok(None);
        }
        let mut methods = vec![0u8; method_count as usize];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&2) {
            let _ = stream.write_all(&[5, 0xFF]).await;
            return Ok(None);
        }
        stream.write_all(&[5, 2]).await?;

        // Subnegotiation (RFC 1929): 0x01 ULEN UNAME PLEN PASSWD.
        if stream.read_u8().await? != 1 {
            return Ok(None);
        }
        let mut username = vec![0u8; stream.read_u8().await? as usize];
        stream.read_exact(&mut username).await?;
        let mut password = vec![0u8; stream.read_u8().await? as usize];
        stream.read_exact(&mut password).await?;
        let Some(user) = users.iter().find(|user| {
            user.username.as_bytes() == username && user.password.as_bytes() == password
        }) else {
            let _ = stream.write_all(&[1, 1]).await;
            debug!(%client_addr, "SOCKS5 authentication failed");
            return Ok(None);
        };
        let user = user.username.clone();
        stream.write_all(&[1, 0]).await?;

        // Request: VER CMD RSV ATYP ADDR PORT.
        if stream.read_u8().await? != 5 {
            return Ok(None);
        }
        let command = stream.read_u8().await?;
        stream.read_u8().await?; // RSV
        let atyp = stream.read_u8().await?;
        let request = match atyp {
            1 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                let port = stream.read_u16().await?;
                Socks5Request::Address(SocketAddr::from((octets, port)))
            }
            3 => {
                let length = stream.read_u8().await?;
                let mut raw = vec![0u8; length as usize];
                stream.read_exact(&mut raw).await?;
                let port = stream.read_u16().await?;
                let Ok(domain) = String::from_utf8(raw) else {
                    write_failure(stream, REP_ADDRESS_UNSUPPORTED).await;
                    return Ok(None);
                };
                Socks5Request::Domain { domain, port }
            }
            4 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets).await?;
                let port = stream.read_u16().await?;
                Socks5Request::Address(SocketAddr::from((octets, port)))
            }
            _ => {
                write_failure(stream, REP_ADDRESS_UNSUPPORTED).await;
                return Ok(None);
            }
        };
        // CONNECT only: BIND and UDP ASSOCIATE are refused, and the request
        // is fully consumed above so the reply is all the client needs.
        if command != 1 {
            write_failure(stream, REP_COMMAND_UNSUPPORTED).await;
            return Ok(None);
        }
        Ok(Some((user, request)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_reply_echoes_the_bound_local_address() {
        let v4 = encode_reply(0, "192.0.2.7:1024".parse().unwrap());
        assert_eq!(
            v4,
            vec![
                5,
                0,
                0,
                1,
                192,
                0,
                2,
                7,
                (1024 >> 8) as u8,
                (1024 & 0xFF) as u8
            ]
        );
        let v6 = encode_reply(0, "[2001:db8::1]:80".parse().unwrap());
        assert_eq!(v6[0..4], [5, 0, 0, 4]);
        assert_eq!(v6.len(), 4 + 16 + 2);
        assert_eq!(
            &v6[4..4 + 16],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].as_slice()
        );
    }
}

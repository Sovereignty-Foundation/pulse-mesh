// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Multicast, opt-in: a frame a sender sends once to a group address
//! reaches every receiver that has joined the group, on any host the
//! network routes the group to.
//!
//! A receiver joins with [`crate::Receiver::bind_multicast`], which binds the
//! group's address and port with `SO_REUSEADDR`, so that several receivers
//! on one host share it and each gets every frame, and joins the group on the interface
//! the [`MulticastConfig`] names. A sender needs no join: it sends to the
//! group address, after [`crate::Sender::set_multicast`] has set how far
//! its frames travel (the TTL, or the hop limit for IPv6), whether they loop
//! back to receivers on its own host, and which interface they leave by.
//!
//! A network may deliver a multicast datagram more than once (a wireless
//! access point repeats a station's own frames back to it, beside the local
//! loopback copy), so a receiver that must not see a frame twice drops
//! repeats by sequence number.
//!
//! The ACK and NACK feedback is one-to-one: with several receivers the
//! sender's cursor follows the furthest one and its retransmissions answer
//! any one's request. One to many, run without backpressure, and repair
//! loss with FEC ([`crate::Sender::enable_fec`]), which rebuilds a lost frame
//! per window at each receiver without a round trip.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// Default TTL (hop limit for IPv6): 1, the local network.
pub const DEFAULT_MULTICAST_TTL: u32 = 1;

/// How a sender's multicast frames travel and where a receiver joins.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MulticastConfig {
    /// Hops a frame may cross: the IPv4 TTL or the IPv6 hop limit. Default
    /// [`DEFAULT_MULTICAST_TTL`].
    pub ttl: u32,
    /// Whether a sender's frames reach receivers on its own host. Default
    /// true.
    pub loopback: bool,
    /// The IPv4 interface, by address, to send from and join on; `None`
    /// lets the system choose by its routes.
    pub interface_v4: Option<Ipv4Addr>,
    /// The IPv6 interface, by index, to send from and join on; `None` (0)
    /// lets the system choose. A group scoped to one interface or one link
    /// (`ff01::/16`, `ff02::/16`) needs it on Linux, which binds such a
    /// group only under an interface's scope.
    pub interface_v6: Option<u32>,
}

impl Default for MulticastConfig {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_MULTICAST_TTL,
            loopback: true,
            interface_v4: None,
            interface_v6: None,
        }
    }
}

/// A UDP socket bound to `group`'s port with `SO_REUSEADDR` and joined to
/// the group on `cfg`'s interface.
pub(crate) fn join(group: SocketAddr, cfg: &MulticastConfig) -> std::io::Result<UdpSocket> {
    if !group.ip().is_multicast() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a multicast address", group.ip()),
        ));
    }
    let domain = socket2::Domain::for_address(group);
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    // Every receiver on the host binds the group's address and port. The
    // BSDs and macOS share a port among SO_REUSEADDR sockets only when they
    // bind a multicast address, not the wildcard; Linux shares it either
    // way, and bound to the group takes only the group's datagrams. Each
    // receiver gets every datagram.
    socket.set_reuse_address(true)?;
    socket.bind(&bind_address(group, cfg).into())?;
    match group.ip() {
        IpAddr::V4(g) => {
            socket.join_multicast_v4(&g, &cfg.interface_v4.unwrap_or(Ipv4Addr::UNSPECIFIED))?;
        }
        IpAddr::V6(g) => socket.join_multicast_v6(&g, cfg.interface_v6.unwrap_or(0))?,
    }
    Ok(socket.into())
}

/// The address a member binds: the group's own. An IPv6 group scoped to one
/// interface or one link (`ff01::/16`, `ff02::/16`) names that interface as
/// its scope, `cfg.interface_v6`, unless the group already carries one:
/// Linux refuses to bind such an address without a scope (`EINVAL`), where
/// macOS takes the scope from the join.
fn bind_address(group: SocketAddr, cfg: &MulticastConfig) -> SocketAddr {
    match group {
        SocketAddr::V6(mut addr) if addr.scope_id() == 0 => {
            if matches!(addr.ip().segments()[0] & 0x000f, 1 | 2) {
                if let Some(index) = cfg.interface_v6 {
                    addr.set_scope_id(index);
                }
            }
            SocketAddr::V6(addr)
        }
        other => other,
    }
}

/// Set `cfg`'s TTL, loopback and interface on a sender's socket, for its
/// address family.
pub(crate) fn configure_sender(socket: &UdpSocket, cfg: &MulticastConfig) -> std::io::Result<()> {
    let sock = socket2::SockRef::from(socket);
    match socket.local_addr()? {
        SocketAddr::V4(_) => {
            sock.set_multicast_ttl_v4(cfg.ttl)?;
            sock.set_multicast_loop_v4(cfg.loopback)?;
            if let Some(interface) = cfg.interface_v4 {
                sock.set_multicast_if_v4(&interface)?;
            }
        }
        SocketAddr::V6(_) => {
            sock.set_multicast_hops_v6(cfg.ttl)?;
            sock.set_multicast_loop_v6(cfg.loopback)?;
            if let Some(index) = cfg.interface_v6 {
                sock.set_multicast_if_v6(index)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    fn on(interface: Option<u32>) -> MulticastConfig {
        MulticastConfig {
            interface_v6: interface,
            ..MulticastConfig::default()
        }
    }

    #[test]
    fn a_link_scoped_group_binds_under_the_configured_interface() {
        for group in ["ff02::7077:1", "ff01::7077:1"] {
            let ip: Ipv6Addr = group.parse().unwrap();
            let addr = bind_address(
                SocketAddr::V6(SocketAddrV6::new(ip, 9000, 0, 0)),
                &on(Some(3)),
            );
            assert_eq!(
                addr,
                SocketAddr::V6(SocketAddrV6::new(ip, 9000, 0, 3)),
                "{group}"
            );
        }
    }

    #[test]
    fn other_groups_and_given_scopes_bind_as_they_are() {
        let site: Ipv6Addr = "ff05::7077:1".parse().unwrap();
        let link: Ipv6Addr = "ff02::7077:1".parse().unwrap();
        let cases = [
            SocketAddr::V6(SocketAddrV6::new(site, 9000, 0, 0)),
            SocketAddr::V6(SocketAddrV6::new(link, 9000, 0, 7)),
            SocketAddr::new(Ipv4Addr::new(239, 255, 77, 1).into(), 9000),
        ];
        for group in cases {
            assert_eq!(bind_address(group, &on(Some(3))), group);
        }
        let unscoped = SocketAddr::V6(SocketAddrV6::new(link, 9000, 0, 0));
        assert_eq!(bind_address(unscoped, &on(None)), unscoped);
    }
}

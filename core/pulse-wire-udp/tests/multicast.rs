// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

//! Multicast end to end on one host: two receivers join a group, a sender
//! with loopback on sends to the group once per frame, and each receiver
//! gets every frame.
//!
//! Each family tries paths in turn. IPv4: the loopback interface, where
//! the host keeps the frames to itself, then the interface the system
//! routes by. IPv6, whose test group is link-local and so needs an
//! interface named: the loopback interface, then each other interface the
//! host has (Linux's loopback carries no IPv6 multicast unless an
//! administrator turns it on, so there a real interface carries it, with
//! the sender's own copy looped back).
//! The first path that delivers is checked frame by frame and named in a
//! `multicast … delivered` line. A host where no path delivers (no route,
//! no IPv6, or on macOS a process without Local Network access, whose sends
//! fail with "No route to host") prints a `SKIP:` line with each path's
//! reason and checks nothing. A skip is not a pass, so the two delivery
//! tests are ignored by a plain `cargo test` and run by the gate's
//! `multicast` check, which fails on any `SKIP:` line.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::{MulticastConfig, Receiver, Sender};

const FRAMES: u64 = 200;

fn pulse(step: u64) -> Pulse {
    let mut p = Pulse::zeroed();
    p.instruction = Instruction::Data as u16;
    p.chain_step = step;
    p.monotonic_nanos = 1;
    p
}

/// A port free on this host now, for a group.
fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Every interface the host has, as its index and name, the loopback
/// interface first.
fn interfaces() -> Vec<(u32, String)> {
    let mut all = Vec::new();
    // SAFETY: `if_nameindex` returns an array ending in an entry whose index
    // is zero, or null; each name is a NUL-terminated string. Both stay
    // valid until `if_freenameindex`, called once after they are copied.
    unsafe {
        let head = libc::if_nameindex();
        if head.is_null() {
            return all;
        }
        let mut entry = head;
        while (*entry).if_index != 0 {
            let name = std::ffi::CStr::from_ptr((*entry).if_name)
                .to_string_lossy()
                .into_owned();
            all.push(((*entry).if_index, name));
            entry = entry.add(1);
        }
        libc::if_freenameindex(head);
    }
    all.sort_by_key(|(_, name)| !name.starts_with("lo"));
    all
}

/// What one path delivered: the frames each member received, repeats
/// included. A network may deliver a datagram twice (a wireless access
/// point repeats a station's own multicast frames back to it, beside the
/// local loopback copy), so repeats are allowed; a member must hold every
/// frame sent, and nothing else.
struct Delivered {
    received: [usize; 2],
}

/// Join two members to `group` on `cfg`'s interface, send `FRAMES` frames
/// from a sender bound to `bind`, and check each member gets every one.
/// `Err` with the reason when the path does not deliver at all: a join or
/// the first send refused, or no frame reaching the first member. Once
/// frames arrive, a missing or foreign frame is a failure, not a skip.
fn deliver(group: SocketAddr, cfg: &MulticastConfig, bind: &str) -> Result<Delivered, String> {
    let join = || -> Result<Receiver, String> {
        let r = Receiver::bind_multicast(group, cfg).map_err(|e| format!("cannot join: {e}"))?;
        r.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        Ok(r)
    };
    let mut members = [join()?, join()?];
    let mut sender = Sender::bind(bind).map_err(|e| format!("cannot bind {bind}: {e}"))?;
    sender
        .set_multicast(cfg)
        .map_err(|e| format!("multicast options refused: {e}"))?;
    for step in 0..FRAMES {
        match sender.send_to(step, &pulse(step), b"to the group", group) {
            Ok(_) => {}
            Err(e) if step == 0 => return Err(format!("cannot send: {e}")),
            Err(e) => panic!("{group}: send {step} of {FRAMES} failed after the first went: {e}"),
        }
    }
    let mut received = [0usize; 2];
    for (m, receiver) in members.iter_mut().enumerate() {
        let mut steps = BTreeSet::new();
        while (steps.len() as u64) < FRAMES {
            match receiver.recv() {
                Ok((p, envelope, _)) => {
                    assert_eq!(envelope, b"to the group");
                    steps.insert(p.chain_step);
                    received[m] += 1;
                }
                Err(e) if steps.is_empty() && m == 0 => {
                    return Err(format!("no frame arrived: {e}"));
                }
                Err(e) => panic!(
                    "{group}: member {m} has {} of {FRAMES} frames: {e}",
                    steps.len()
                ),
            }
        }
        assert!(
            steps.iter().copied().eq(0..FRAMES),
            "{group}: member {m} got a frame never sent"
        );
    }
    Ok(Delivered { received })
}

/// Try each path in turn for a group at `ip`; print which one delivered,
/// or a `SKIP:` line with every path's reason when none did.
fn check(family: &str, ip: IpAddr, bind: &str, paths: Vec<(String, MulticastConfig)>) {
    let mut reasons = Vec::new();
    for (path, cfg) in paths {
        let group = SocketAddr::new(ip, free_port());
        match deliver(group, &cfg, bind) {
            Ok(d) => {
                eprintln!(
                    "multicast {family} delivered via {path}: {group}, \
                     every one of {FRAMES} frames at both members \
                     ({} and {} datagrams received)",
                    d.received[0], d.received[1]
                );
                return;
            }
            Err(reason) => reasons.push(format!("{path}: {reason}")),
        }
    }
    eprintln!(
        "SKIP: multicast {family}: no path delivered, nothing checked ({})",
        reasons.join("; ")
    );
}

#[test]
#[ignore = "needs a host that delivers multicast; the gate's multicast check runs it"]
fn every_member_of_an_ipv4_group_gets_every_frame() {
    let ip = IpAddr::V4(Ipv4Addr::new(
        239,
        255,
        77,
        (std::process::id() % 200) as u8 + 1,
    ));
    let mut loopback = MulticastConfig::default();
    loopback.interface_v4 = Some(Ipv4Addr::LOCALHOST);
    let paths = vec![
        ("the loopback interface".to_owned(), loopback),
        ("the system's route".to_owned(), MulticastConfig::default()),
    ];
    check("IPv4", ip, "0.0.0.0:0", paths);
}

#[test]
#[ignore = "needs a host that delivers multicast; the gate's multicast check runs it"]
fn every_member_of_an_ipv6_group_gets_every_frame() {
    // A link-local group: each path names the interface it leaves by.
    let ip = IpAddr::V6(Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        0,
        0x7077,
        std::process::id() as u16,
    ));
    let paths = interfaces()
        .into_iter()
        .map(|(index, name)| {
            let mut cfg = MulticastConfig::default();
            cfg.interface_v6 = Some(index);
            (format!("interface {name} (index {index})"), cfg)
        })
        .collect();
    check("IPv6", ip, "[::]:0", paths);
}

#[test]
fn a_unicast_address_is_not_a_group() {
    let unicast: SocketAddr = "127.0.0.1:9".parse().unwrap();
    match Receiver::bind_multicast(unicast, &MulticastConfig::default()) {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
        Ok(_) => panic!("joined a unicast address"),
    }
}

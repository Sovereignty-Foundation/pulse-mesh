// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: opening sealed datagrams, `sealed::Sealing::open`, what a
// sealing receiver does with every datagram it reads before the plaintext
// path's decode: the dispatch on the sealed header, the session lookup by
// index, the replay window, the ChaCha20-Poly1305 open, the plaintext rule,
// and the handshake messages a responder answers.
//
// The inputs run against one session, made once per process as two nodes
// make it: Noise IK through snow, the initiation, the response and the
// keepalive passed in memory between two detached sealings under fixed
// static keys, with rekeying put off past any run. Its counter and replay
// window carry over from input to input, which the invariants allow: an
// input seals fewer datagrams than the window spans and can name only what
// it sealed itself. Each input has the initiator seal datagrams of its
// choosing for the responder, and delivers to the responder, from a
// loopback source or
// another: those datagrams as sealed, again, or changed (a bit flipped,
// cut short, extended, bytes overwritten, the header or the tag of another
// spliced on); a genuine header over any body; handshake messages of the
// right length and any content; the fixture's own initiation again; and
// raw bytes. Every datagram is first cut to the receiver's one-MTU buffer,
// as the kernel cuts it.
//
// Invariants:
// - nothing panics;
// - a datagram is opened exactly when it is, byte for byte, one the
//   initiator sealed that has not been opened before; what is handed on is
//   then exactly what was sealed, at the front of the buffer, or nothing,
//   for one sealed with nothing inside (a keepalive);
// - every other datagram is handed on nowhere and counted as exactly one
//   refusal, and the opened count moves only for the first;
// - no session is made but the fixture's, and the responder answers
//   nothing the input wrote: plaintext is never admitted (the flag is off),
//   and no handshake message the input wrote completes.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use pulse_mesh_fuzz::take;
use pulse_wire_udp::sealed::{
    Opened, INITIATION_BYTES, KIND_INITIATION, KIND_RESPONSE, RESPONSE_BYTES, SEALED_HEADER_BYTES,
    TAG_BYTES,
};
use pulse_wire_udp::{
    wire, Allowlist, NodeKey, SealCounts, Sealing, SealingConfig, MTU_BYTES, SEALED_OVERHEAD,
};

/// Most steps in one input; fewer than the replay window, so a datagram
/// the initiator sealed is never too old.
const MAX_STEPS: usize = 192;
/// Longest plaintext sealed: past the budget, so some sealed datagrams are
/// cut by the receive buffer.
const MAX_INNER: usize = MTU_BYTES;

const A_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4100);
const B_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4200);
/// The sources a datagram comes from: loopback, and an address that is not.
const SOURCES: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
];

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

/// One datagram the initiator sealed, with what it holds.
struct Sent {
    sealed: Vec<u8>,
    inner: Vec<u8>,
    opened: bool,
}

/// The initiator, the responder with the session confirmed, and the
/// initiation that made it.
fn fixture() -> (Sealing, Sealing, Vec<u8>) {
    let ka = NodeKey::from_secret_bytes(&[0x11; 32]).unwrap();
    let kb = NodeKey::from_secret_bytes(&[0x22; 32]).unwrap();
    let (pa, pb) = (ka.public_key(), kb.public_key());
    let config = SealingConfig::new().with_rekey_after(Duration::from_secs(86_400));
    let a = Sealing::detached(ka, [pb].into_iter().collect::<Allowlist>(), config.clone()).unwrap();
    let b = Sealing::detached(kb, [pa].into_iter().collect::<Allowlist>(), config).unwrap();
    a.initiate(&pb, B_ADDR).unwrap();
    let (initiation, _) = a.take_outgoing().pop().unwrap();
    let mut buf = initiation.clone();
    assert_eq!(b.open(&mut buf, initiation.len(), A_ADDR), Opened::Consumed);
    let (mut response, _) = b.take_outgoing().pop().unwrap();
    let len = response.len();
    assert_eq!(a.open(&mut response, len, B_ADDR), Opened::Consumed);
    let (mut keepalive, _) = a.take_outgoing().pop().unwrap();
    let len = keepalive.len();
    assert_eq!(b.open(&mut keepalive, len, A_ADDR), Opened::Consumed);
    assert!(a.has_session(&pb) && b.has_session(&pa));
    (a, b, initiation)
}

fn refusals(c: &SealCounts) -> u64 {
    c.unauthentic
        + c.replayed
        + c.too_old
        + c.unknown_session
        + c.malformed
        + c.plaintext_refused
        + c.handshakes_refused
        + c.handshakes_failed
}

fn fuzz(data: &[u8]) -> Result<()> {
    static FIXTURE: OnceLock<(Sealing, Sealing, Vec<u8>)> = OnceLock::new();
    let (a, b, initiation) = FIXTURE.get_or_init(fixture);
    // What either sent for an earlier input (a rekey the initiator would
    // start, were it due) is not this input's.
    let _ = (a.take_outgoing(), b.take_outgoing());
    let mut u = Unstructured::new(data);
    let established = b.counts().sessions_established;
    let mut sent: Vec<Sent> = Vec::new();

    for _ in 0..MAX_STEPS {
        if u.is_empty() {
            break;
        }
        let pick = |u: &mut Unstructured<'_>, sent: &[Sent]| -> Result<Option<usize>> {
            if sent.is_empty() {
                Ok(None)
            } else {
                Ok(Some(u.choose_index(sent.len())?))
            }
        };
        let datagram: Vec<u8> = match u.int_in_range(0..=8u8)? {
            0 | 1 => {
                // The initiator seals: often a frame, sometimes anything.
                let inner = if u.arbitrary()? {
                    let envelope = take(&mut u, 64)?;
                    wire::encode(
                        u.arbitrary()?,
                        u.arbitrary()?,
                        &pulse_canon::Pulse::zeroed(),
                        envelope,
                    )
                    .unwrap()
                } else {
                    take(&mut u, MAX_INNER)?.to_vec()
                };
                let mut sealed = Vec::new();
                a.seal_to(B_ADDR, &inner, &mut sealed).unwrap();
                assert_eq!(sealed.len(), inner.len() + SEALED_OVERHEAD);
                sent.push(Sent {
                    sealed,
                    inner,
                    opened: false,
                });
                continue;
            }
            2 => match pick(&mut u, &sent)? {
                Some(k) => sent[k].sealed.clone(),
                None => continue,
            },
            3 => {
                // Changed.
                let Some(k) = pick(&mut u, &sent)? else {
                    continue;
                };
                let mut d = sent[k].sealed.clone();
                for _ in 0..u.int_in_range(1..=3u8)? {
                    match u.int_in_range(0..=3u8)? {
                        0 => {
                            let i = u.choose_index(d.len())?;
                            d[i] ^= 1 << u.int_in_range(0..=7u8)?;
                        }
                        1 => d.truncate(u.int_in_range(0..=d.len())?),
                        2 => d.extend_from_slice(take(&mut u, 32)?),
                        _ => {
                            if !d.is_empty() {
                                let at = u.choose_index(d.len())?;
                                let with = take(&mut u, 8)?;
                                let end = (at + with.len()).min(d.len());
                                d[at..end].copy_from_slice(&with[..end - at]);
                            }
                        }
                    }
                }
                d
            }
            4 => {
                // One datagram's header, or tag, on another's body.
                let (Some(i), Some(j)) = (pick(&mut u, &sent)?, pick(&mut u, &sent)?) else {
                    continue;
                };
                let (x, y) = (&sent[i].sealed, &sent[j].sealed);
                if u.arbitrary()? {
                    [&x[..SEALED_HEADER_BYTES], &y[SEALED_HEADER_BYTES..]].concat()
                } else {
                    [&y[..y.len() - TAG_BYTES], &x[x.len() - TAG_BYTES..]].concat()
                }
            }
            5 => {
                // A genuine header, its counter changed or not, over any
                // body: the input reaches the AEAD.
                let Some(k) = pick(&mut u, &sent)? else {
                    continue;
                };
                let mut d = sent[k].sealed[..SEALED_HEADER_BYTES].to_vec();
                if u.arbitrary()? {
                    d[12..20].copy_from_slice(&u.arbitrary::<u64>()?.to_le_bytes());
                }
                d.extend_from_slice(take(&mut u, 256)?);
                d
            }
            6 => {
                // A handshake message of the right length, any content.
                let initiation_kind = u.arbitrary()?;
                let (kind, len) = if initiation_kind {
                    (KIND_INITIATION, INITIATION_BYTES)
                } else {
                    (KIND_RESPONSE, RESPONSE_BYTES)
                };
                let mut d = initiation[..8].to_vec();
                d[5] = kind;
                let rest = take(&mut u, len - 8)?;
                d.extend_from_slice(rest);
                d.resize(len, 0);
                d
            }
            7 => initiation.clone(),
            _ => take(&mut u, MTU_BYTES + 8)?.to_vec(),
        };
        let src = SocketAddr::new(SOURCES[u.choose_index(SOURCES.len())?], u.arbitrary()?);

        // What the receive buffer holds.
        let cut = &datagram[..datagram.len().min(MTU_BYTES)];
        let mut buf = vec![0u8; MTU_BYTES];
        buf[..cut.len()].copy_from_slice(cut);
        let before = b.counts();
        let got = b.open(&mut buf, cut.len(), src);
        let after = b.counts();

        match sent.iter().position(|s| !s.opened && s.sealed == cut) {
            Some(k) => {
                sent[k].opened = true;
                assert_eq!(after.opened, before.opened + 1);
                assert_eq!(refusals(&after), refusals(&before));
                if sent[k].inner.is_empty() {
                    assert_eq!(got, Opened::Consumed, "a keepalive is handed on as nothing");
                } else {
                    assert_eq!(got, Opened::Inner(sent[k].inner.len()));
                    assert_eq!(&buf[..sent[k].inner.len()], sent[k].inner.as_slice());
                }
            }
            None => {
                assert_eq!(
                    got,
                    Opened::Consumed,
                    "a datagram not sealed by the initiator was taken"
                );
                assert_eq!(after.opened, before.opened);
                assert_eq!(
                    refusals(&after),
                    refusals(&before) + 1,
                    "{before:?} {after:?}"
                );
            }
        }
    }
    assert_eq!(b.counts().sessions_established, established);
    assert!(
        b.take_outgoing().is_empty(),
        "the responder answered the input"
    );
    Ok(())
}

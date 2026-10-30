# Tune the UDP transport

<p class="pm-kind"><b>How-to guide</b> · for anyone running `pulse-wire-udp` over a link that loses packets, a receiver that falls behind, or a path where a round trip is too slow</p>

The transport's three mechanisms are independent and default to off. Switch on the one whose symptom you have, then read the counters.

## The receiver falls behind

Enable backpressure on both ends. The receiver acknowledges its cursor, one past the highest sequence it has seen, every millisecond, and the sender stalls when more than sixteen frames are in flight beyond it.

```rust
use pulse_wire_udp::{BackpressureConfig, Receiver, Sender};

let mut rx = Receiver::bind("127.0.0.1:9000")?;
let mut tx = Sender::bind("127.0.0.1:0")?;
tx.connect(rx.local_addr()?)?;

// The sender's feedback socket and the receiver's ACK target are one endpoint.
let any = "127.0.0.1:0".parse()?;
let mut cfg = BackpressureConfig::new(any, any);
tx.enable_backpressure(cfg.clone())?;
cfg.ack_target_addr = tx.ack_local_addr().expect("backpressure is on");
rx.enable_backpressure(cfg)?;
```

The first address in `new` is where that side binds its feedback socket and the second is where it sends feedback; the sender only receives, so it reports the address it bound with `ack_local_addr` and the receiver targets that. `target_queue_depth` (16) and `ack_period` (1 ms) are fields on the config; raise the depth for a link with a long round trip, and never set it to zero, which `enable_backpressure` refuses because it would admit no frame. A batch (`send_batch`) is held to the same rule frame by frame and stops at the first frame that stalls, with the frames before it sent. A batch receive (`recv_batch`) acknowledges and tracks gaps per datagram exactly as the single receive does, so a sender under backpressure is not stalled by a receiver that batches. A stall lasts at most `stall_timeout`, five seconds by default (`with_stall_timeout`; `None` removes the deadline), after which the send fails with `SenderError::Stalled` and the frame is not sent, so a dead receiver cannot wedge a sender. Watch `tx.observed_recv_cursor()` move; if it never does, the feedback address is wrong.

## Frames are lost and the round trip is short

Add retransmission on top of backpressure with `with_nack(capacity)` on both configs. The sender keeps the last `capacity` encoded frames (1,024 by default) and the receiver asks for the ones it misses: each missing sequence is staged once, requested at most sixteen per period, requested again after four periods if it is still missing, and given up after three requests.

```rust
let cfg = BackpressureConfig::new(bind, target).with_nack(1024);
```

A retransmitted frame can arrive after its late original, so a caller that must see each sequence once filters on `RecvMeta::seq`. Read `tx.retransmit_count()`, `tx.cache_miss_count()` (a miss means the receiver asked for a frame older than the cache; raise the capacity), `rx.nacks_sent()`, `rx.nack_drop_count()` (sequences given up on without a request: a gap wider than the cache, or the frames before a late joiner's first) and `rx.gap_resyncs()` (a resync means a gap wider than the cache; the stream skipped ahead rather than stall).

## Frames are lost and the round trip is long

Enable parity. Every window of K frames gets one parity frame, and the receiver rebuilds one loss per window without asking.

```rust
tx.enable_fec(16);         // window of 16 frames
rx.enable_fec(16, 64);     // the same window, up to 64 windows in flight
```

A smaller window recovers more often and costs more bandwidth. `rx.fec_recovered_count()` says how often it paid off; two losses in one window fall through to retransmission if that is on. A frame rebuilt from parity can be followed by its late original, so the same filter on `RecvMeta::seq` applies.

## The feedback socket must not listen to strangers

```rust
let cfg = BackpressureConfig::new(bind, target).with_feedback_peer("10.0.0.7".parse()?);
```

Feedback from any other address is dropped and counted in `tx.feedback_rejected_count()`. A count that climbs while the cursor stalls means the filter names the wrong peer: a multi-homed receiver may answer from another address than the one you send to.

## Do not tune

The envelope size is not a knob: a datagram carries at most 1,315 envelope bytes and the transport does not fragment. An envelope larger than that belongs in the envelope store with a Pulse referencing it, or on a transport with a larger unit. The [transport chapter](../reference/spec/06-udp-transport.md) has every constant; [Transport design](../explanation/transport-design.md) says why each mechanism is shaped as it is.

# Across a network: encode, verify, send over UDP

<p class="pm-kind"><b>Example</b> · for anyone moving Pulses between two machines, or two processes that cannot share memory; about fifteen minutes with nothing but the standard</p>

<figure class="pm-art"><svg class="uc-diagram" viewBox="0 0 380 240" role="img" aria-label="One Pulse and its envelope per datagram"><circle cx="50" cy="150" r="18" class="uc-node-strong"/><text x="50" y="190" class="uc-label">sender</text><circle cx="330" cy="150" r="18" class="uc-ring"/><circle cx="330" cy="150" r="9" class="uc-ring-dash"/><text x="330" y="190" class="uc-label">receiver</text><line x1="68" y1="150" x2="312" y2="150" class="uc-edge-dash"/><rect x="110" y="48" width="160" height="26" rx="2" class="uc-frame"/><text x="122.0" y="90" class="uc-label">magic</text><line x1="134" y1="48" x2="134" y2="74" class="uc-frame-seg"/><text x="146.0" y="90" class="uc-label">seq</text><line x1="158" y1="48" x2="158" y2="74" class="uc-frame-seg"/><text x="184.0" y="90" class="uc-label">pulse</text><line x1="210" y1="48" x2="210" y2="74" class="uc-frame-seg"/><text x="230.0" y="90" class="uc-label">envelope</text><line x1="250" y1="48" x2="250" y2="74" class="uc-frame-seg"/><text x="260.0" y="90" class="uc-label">crc</text><rect x="158" y="48" width="52" height="26" class="uc-frame-accent"/><text x="190" y="118" class="uc-label">one datagram, checked on arrival</text><circle class="uc-pulse" r="3"><animateMotion dur="1.8s" begin="0s" repeatCount="indefinite" path="M68,150 L312,150"/></circle><circle class="uc-pulse" r="3"><animateMotion dur="1.8s" begin="0.6s" repeatCount="indefinite" path="M68,150 L312,150"/></circle><circle class="uc-pulse" r="3"><animateMotion dur="1.8s" begin="1.2s" repeatCount="indefinite" path="M68,150 L312,150"/></circle></svg><figcaption>One Pulse and its envelope per datagram</figcaption></figure>

**You will have:** one envelope encoded, decoded and verified by hand, with the check failing on one changed byte; three Pulses sent over UDP from one terminal and received in another, on one machine or across two; and a program that does the same exchange a thousand times.

**You need:** the standard's repository set up as [Start here](../start/onboard-your-agent.md) describes, with `pulse` installed (`cargo install --path tools/pulse-cli --locked`). Two terminals. One machine is fine: the loopback interface is a network as far as the transport is concerned.

## Hand this to your agent

```text
Run the example "Across a network" from book/src/examples/across-a-network.md in the pulse-mesh repository:
1. Install the command line if it is missing: cargo install --path tools/pulse-cli --locked. Run pulse version and show me the codec-test-vector line; its identifier must be 57f2c2eec9bae1b5e69c97f88e9bfd8d.
2. Write spec.json with {"envelope_type": 1, "payload_utf8": "hello, mesh"} and run pulse encode --json spec.json. Confirm decoded_equal is true and keep canonical_hex.
3. Run pulse decode on that hex and confirm verified is true. Then change the last hex byte from 68 to 69 and decode again: verified must be false and the exit status 1.
4. Start pulse recv 127.0.0.1:9000 --count 3 --timeout-ms 10000 in the background, then run pulse send 127.0.0.1:9000 --count 3 --payload 32. Show me the receiver's "received 3/3" line and its three seq lines.
5. Run cargo run --release -p example-02-loopback-udp-rust and confirm it prints a line starting with OK.
6. If I have named a second machine, repeat step 4 with the receiver bound there and the sender pointed at its address, and tell me what the receiver printed.
Explain in plain words what each step showed, including why the tampered envelope failed. Stop and tell me if anything fails, and say which step.
```

## Or do it by hand

### 1. Check the codec

```bash
pulse version
```

```text
pulse (pulse-cli) 1.0.0-beta
rust-toolchain    1.95.0
codec-test-vector 58 bytes, BLAKE3-16 57f2c2eec9bae1b5e69c97f88e9bfd8d
```

The last line is the one that matters: `pulse` has just encoded the reference test vector and printed the identifier it got. The specification's fixtures record `57f2c2eec9bae1b5e69c97f88e9bfd8d`, so a line that shows it says the codec you built agrees with them.

### 2. Encode an envelope

```bash
cat > spec.json <<'EOF'
{ "envelope_type": 1, "payload_utf8": "hello, mesh" }
EOF
pulse encode --json spec.json
```

```text
canonical_size  61 bytes
content_hash    71aad243e722c17b9f1cf2723ec6148a
decoded_equal   true
canonical_hex   71aad243e722c17b9f1cf2723ec6148a0000000000000000000000000000000000000000000000000100000000000b00000068656c6c6f2c206d657368
```

Four lines, four facts. The encoding is 61 bytes: the 50-byte fixed part every envelope has, plus your 11 bytes of payload. `content_hash` is the identifier, the first 16 bytes of a BLAKE3 hash over a fixed domain tag and the envelope's content; the hex begins with it. `decoded_equal` says decoding the bytes gave back an envelope equal to the one encoded. `canonical_hex` is the whole envelope, and every conforming implementation, in any language, produces these bytes from this spec.

### 3. Decode, then change one byte

```bash
pulse decode 71aad243e722c17b9f1cf2723ec6148a0000000000000000000000000000000000000000000000000100000000000b00000068656c6c6f2c206d657368
```

```text
envelope_type    0x0001
content_hash     71aad243e722c17b9f1cf2723ec6148a
verified         true
monotonic_nanos  0
flags            0x0000
payload          Raw, 11 byte(s)
```

`verified true` means the decoder recomputed the identifier from the decoded content and it matched the one the bytes carry. The last byte of the hex is the payload's final `h` (`68`). Change it to `i` (`69`) and decode again:

```bash
pulse decode 71aad243e722c17b9f1cf2723ec6148a0000000000000000000000000000000000000000000000000100000000000b00000068656c6c6f2c206d657369
```

```text
envelope_type    0x0001
content_hash     71aad243e722c17b9f1cf2723ec6148a
verified         false
monotonic_nanos  0
flags            0x0000
payload          Raw, 11 byte(s)
```

The bytes still parse, because the layout is intact. But the identifier they carry was computed from `hello, mesh` and the content now says `hello, mesi`, so `verified` is false and `pulse decode` exits with status 1, so a script can refuse the envelope without reading the output. That is the whole of content addressing: a name the bytes cannot keep once they change.

### 4. Receive and send over UDP

In the first terminal:

```bash
pulse recv 127.0.0.1:9000 --count 3 --timeout-ms 10000
```

It binds the address and waits, silently, for three datagrams or ten seconds. In the second:

```bash
pulse send 127.0.0.1:9000 --count 3 --payload 32
```

```text
sent 3 pulse(s) (32 byte payload each) to 127.0.0.1:9000 in … µs
```

The time is your run's own and changes with every run and machine. The receiver prints:

```text
received 3/3 pulse(s) on 127.0.0.1:9000 (timeout 10000 ms):
  seq=     0  send_ns=     …  inst=DATA        envelope=32 B
  seq=     1  send_ns=     …  inst=DATA        envelope=32 B
  seq=     2  send_ns=     …  inst=DATA        envelope=32 B
```

Each line is one datagram: its sequence number, the sender's clock reading when it was sent, the Pulse's instruction and the envelope's size. The sender framed each Pulse with a 32-byte envelope into one datagram, with a magic, a version, the sequence, the clock and a CRC around them, and the receiver checked each on arrival.

**Across two machines:** run `pulse recv 0.0.0.0:9000 --count 3 --timeout-ms 10000` on the receiving machine, and `pulse send <its address>:9000 --count 3 --payload 32` on the sending one. UDP port 9000 must be open between them; nothing else changes.

### 5. The same exchange in a program

`examples/02-loopback-udp-rust` is the exchange above in one process, a receiver thread and a sender, a thousand times:

```rust
{{#include ../../../examples/02-loopback-udp-rust/src/main.rs:32:73}}
```

```bash
cargo run --release -p example-02-loopback-udp-rust
```

```text
OK — 1000 pulses sent and received on 127.0.0.1:… (8 B payload each).
```

The port is the kernel's choice and differs each run. `send` takes the sender's clock reading, the Pulse and the envelope bytes, frames them, and returns the sequence number it used; it refuses an envelope larger than the transport's maximum, because the transport never fragments a datagram unless asked to. `recv_into` waits for a datagram, checks its magic, version and CRC, and hands back the Pulse, the envelope's length and the sender's sequence and clock.

## Check it worked

| Check | Command | Pass |
|---|---|---|
| The codec agrees with the specification | `pulse version` | The `codec-test-vector` line ends `57f2c2eec9bae1b5e69c97f88e9bfd8d` |
| Encoding is canonical | `pulse encode --json spec.json` | `content_hash 71aad243e722c17b9f1cf2723ec6148a`, `decoded_equal true` |
| Tampering is caught | `pulse decode` of the hex with `…68` changed to `…69` | `verified false`, exit status 1 |
| Datagrams arrive and verify | `pulse recv … --count 3` and `pulse send … --count 3` | `received 3/3`, three `seq=` lines |
| The program agrees | `cargo run --release -p example-02-loopback-udp-rust` | A line starting `OK — 1000 pulses` |

If `pulse recv` prints `received 0/3`, the sender ran before the receiver was bound, or a firewall dropped the datagrams; start the receiver first and, across machines, open UDP port 9000. If `pulse version` shows a different identifier, the codec you built does not agree with the specification's fixtures, and that is a defect to report.

## What happened

- **One canonical encoding.** The envelope has exactly one byte layout, and its identifier is a hash of that layout. The same spec gives the same bytes and the same name in every language, which is what the conformance vectors pin and what `pulse version` checks.
- **Verification is recomputation.** A decoder does not trust the identifier it is handed; it recomputes it from the content and compares. A changed byte parses and fails.
- **UDP carries the same bytes a ring would.** One Pulse and its envelope per datagram, framed with a magic, a version, a sequence, the sender's clock and a CRC. The receiver checks the frame and the envelope; a datagram that fails either is dropped and counted.
- **Over loopback nothing is lost.** Over a real link the transport has mechanisms for that, each off by default and switched on with two lines on each side: backpressure, so a sender does not outrun its receiver; retransmission, so a receiver can ask for a frame it missed; and parity, so a receiver can rebuild a lost frame without asking. [Tune the UDP transport](../guides/tune-udp.md) switches them on.

What the transport does not do by default: no encryption and no authentication of the sender; the CRC detects accidental corruption, not a forged datagram. Sealing is an option of the transport, and [Trust boundaries](/docs/daemon/explanation/trust-boundaries.html) says what each layer protects.

## Make it yours

- **Larger payloads:** `--payload 1000` on `pulse send`; the transport refuses an envelope larger than a datagram carries unless fragmentation is on.
- **A nested envelope:** `pulse encode` with `"envelope_type": 2` and a payload that is itself an envelope's hex, as the specification's nested test vector does.
- **Your own program:** the loopback example is thirty lines; swap `127.0.0.1` for a peer's address and you have a sender on one machine and a receiver on another.

## Next

- [Two programs talk through the daemon](/docs/daemon/examples/two-programs.html): the same naming, with a daemon routing between processes.
- [Tune the UDP transport](../guides/tune-udp.md): backpressure, retransmission and parity.
- [The UDP transport](../reference/spec/06-udp-transport.md), the specification chapter, and [Transport design](../explanation/transport-design.md), the reasoning.
- [Run the smoke bench and read the result](../guides/run-the-benches.md): the same exchange at two hundred thousand Pulses, timed, on your machine.

## Spoken walkthrough

*A script for the video and audio version of this page, about ninety seconds.*

Start with one envelope. We write a spec, eleven bytes of payload, and encode it. Sixty-one bytes come out, and the first sixteen are the envelope's name: a hash of its content. Decode those bytes and the decoder recomputes the name and compares. Verified, true.

Now change the last byte, an h to an i. The bytes still parse. But the name no longer matches the content, so verified is false and the command exits with an error. That is content addressing: a name the bytes cannot keep once they change.

Then the network. A receiver waits on a UDP port; a sender fires three Pulses at it. Each one is a Pulse and its envelope in one datagram, with a sequence number, the sender's clock and a checksum around it. The receiver prints three lines, one per datagram, each checked on arrival. Put the receiver on another machine and change one address; nothing else changes.

Last, a program does the same exchange a thousand times in one process and prints OK. Thirty lines, and it is the whole transport. The daemon, in the next example, is built on exactly this.

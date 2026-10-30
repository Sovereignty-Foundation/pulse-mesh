# Run the smoke bench and read the result

<p class="pm-kind"><b>How-to guide</b> · for anyone who wants a measurement from this machine and needs to know what it is a measurement of</p>

## What you need

- A checkout of this repository and the Rust toolchain it pins in `rust-toolchain.toml`.
- Nothing running. The bench needs no daemon and no shared memory.

## Run the bench

```bash
cargo run --release -p pulse-cli -- bench --count 200000 --json
```

It sends 200,000 Pulses, each with a 64-byte envelope, from one socket to another over the loopback interface through the reference UDP transport, and prints one JSON object with the fields below. Without `--count` it sends 10,000.

Always run it in the release profile. A debug build measures the compiler, not the transport. Run it more than once, because the tail moves with whatever else the host is doing.

`pms bench smoke` runs the same bench and prints the same fields; its flags are in [The pms command line](/docs/daemon/reference/cli-reference.html).

## Check the count before anything else

Compare `pulses_received` with `pulses_sent`. In a valid run they are equal.

The bench sends as fast as one thread can, with the transport's backpressure off. When the receiving socket's buffer fills, the kernel drops datagrams, and the receiver stops only after five seconds pass without one. A run where `pulses_received` is less than `pulses_sent` is not a result. Its percentiles describe only the Pulses that arrived. The command still exits 0. Discard the run and repeat it. A shortfall that repeats means the receiver cannot keep pace with an unpaced sender at that count on this host.

## Read the fields

| Field | Meaning |
|---|---|
| `pulses_sent` | Pulses the sender sent. |
| `pulses_received` | Pulses the receiver decoded. |
| `payload_bytes` | The envelope size of every Pulse, 64. |
| `send_elapsed_ns` | Wall time the sender spent sending, in nanoseconds. |
| `recv_elapsed_ns` | Nanoseconds from the receiver's first read to its last decode. The timeout that ends a short run is not counted. |
| `throughput_pulses_per_sec` | `pulses_received` per second of `recv_elapsed_ns`. |
| `p50_ns`, `p99_ns`, `p999_ns` | One-way latency at the median, the 99th and the 99.9th percentile, in nanoseconds: the receiver's clock at decode minus the sender's clock carried in the frame. Both are the host's monotonic clock, so the two readings compare on one host and on no other. |

## What the latency includes

The sender is not paced. When it sends faster than the receiver decodes, Pulses wait in the receiving socket's buffer, and that wait is part of their latency. While the sender stays ahead, the queue grows with every Pulse, up to what the receiving socket's buffer holds, so the latencies depend on the count and on how far the sender gets ahead. A run that would queue more than the buffer holds drops Pulses and is not a result. The percentiles describe a burst through two sockets, not one Pulse crossing an idle path. Compare two runs by throughput, and only at the same count. Beyond the wait, the one-way latency through two sockets is mostly the loopback path's price: encoding and decoding a Pulse is a small part of it.

## What is not here

The smoke bench measures Pulse Mesh alone, over UDP loopback. It says nothing about the shared-memory ring, the HFT ring's wait strategies and NUMA placement, or a path between two hosts.

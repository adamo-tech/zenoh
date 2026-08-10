# Zenoh client/server benchmark (`z_bench_client` / `z_bench_server`)

Date: 2026-08-10
Status: approved

## Goal

Measure the maximum performance of a zenoh session over any link (webtransport,
tcp, quic, ...) with a client/server pair that supports both **open-loop**
(fixed offered rate) and **closed-loop** (fixed in-flight window) load, with
configurable app-level **batch size** and **message size**, reporting
throughput and RTT latency percentiles.

## Where it lives

Two new binaries in `examples/examples/`, following the repo convention that
examples double as manual test tools:

- `z_bench_server`
- `z_bench_client`

Both reuse the examples' `CommonArgs`, so `--connect`, `--listen`, and
`--config` work with every locator. One new dependency for the
`zenoh-examples` crate: `hdrhistogram` (latency percentiles).

## Wire format

Every client payload starts with a 16-byte header, padded with filler bytes to
`--size`:

- bytes 0..8 — `u64` little-endian sequence number
- bytes 8..16 — `u64` little-endian send timestamp (client-local, nanoseconds
  from a client-chosen epoch)

Acks/replies are 16 bytes: the same seq + timestamp echoed back. RTT is
computed entirely on the client from the echoed timestamp, so there is no
clock-synchronization requirement. One-way latency is not measured; the
summary notes RTT/2 as an approximation only.

## Server

`z_bench_server --pattern pubsub|query [CommonArgs]`

- **pubsub**: declares a subscriber on `bench/data` and a publisher on
  `bench/ack`. For each sample received it immediately publishes the 16-byte
  ack. Also counts received messages/bytes and prints a per-run total on
  Ctrl-C.
- **query**: declares a queryable on `bench/query`. Each query carries the
  full-size payload as its body; the reply is the 16-byte ack.

The server runs until interrupted and can serve many consecutive client runs.

## Client

`z_bench_client --pattern pubsub|query --mode open|closed [knobs] [CommonArgs]`

Knobs:

| Flag | Meaning | Default |
|---|---|---|
| `--pattern` | `pubsub` (put + ack subscriber) or `query` (get/reply) | `pubsub` |
| `--mode` | `open` or `closed` | `closed` |
| `--rate R` | open loop: offered rate, messages/sec | required in open mode |
| `--window W` | closed loop: max messages in flight | 16 |
| `--batch B` | app-level burst: messages sent back-to-back per wakeup | 1 |
| `--size N` | payload size in bytes (min 16) | 64 |
| `--duration S` | measured run length, seconds | 10 |
| `--warmup S` | warmup before measurement, discarded from stats | 1 |
| `--csv FILE` | append one CSV row per run | off |

Semantics:

- **Open loop**: a tokio interval fires `R / B` times per second; each tick
  sends a burst of `B` messages. Latency for each message is measured from
  its **scheduled** send time, not the actual send time, so coordinated
  omission is captured. If the sender cannot keep up, the run still completes
  and the summary reports offered vs. achieved rate.
- **Closed loop**: the client keeps at most `W` messages in flight. Each ack
  frees a slot; the client refills in bursts of up to `B` whenever at least
  `B` slots are free (a final partial burst is allowed at run end).
  `--window 1 --batch 1` reproduces classic ping-pong.
- Publisher uses `CongestionControl::Block`. In open-loop mode, blocking
  time shows up as scheduled-time latency and reduced achieved rate — that is
  the intended signal.
- Warmup samples are excluded from the histogram and counters.

## Output

End-of-run human summary:

- knobs echoed (pattern, mode, rate/window, batch, size, duration, locator)
- offered rate (open loop) and achieved send rate, msg/s and MB/s
- acked count, ack rate, loss = sent − acked
- RTT p50 / p90 / p99 / p99.9 / max from an `hdrhistogram`

`--csv FILE` appends a single row per run containing all knobs and all
metrics (header written if the file is new), for scripted sweeps over rates,
sizes, and windows.

## Error handling

- Client exits non-zero if the session cannot be opened or the first message
  is never acked within 5 s (server missing).
- After the send phase, the client waits a grace period (2 s) for stragglers;
  if fewer than 95% of sent messages were acked, it exits non-zero and says
  so in the summary (CSV row is still written, with the loss recorded).
- Payloads smaller than the 16-byte header are rejected at argument parsing.

## Testing

- Smoke runs over `tcp/127.0.0.1:7447` and `webtransport/127.0.0.1:7447` in
  all four (pattern × mode) combinations, verifying sane summaries and a CSV
  row.
- `cargo clippy --all-targets -- --deny warnings` on the examples crate.
- Run instructions (including a small rate-sweep shell loop) added to the
  examples README.

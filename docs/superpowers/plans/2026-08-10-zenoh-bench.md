# Zenoh Client/Server Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `z_bench_server` and `z_bench_client` example binaries that measure zenoh throughput and RTT latency over any link, with open-loop (fixed rate) and closed-loop (fixed window) load, configurable batch and message size, human summary + CSV output.

**Architecture:** Shared logic (wire header, latency stats, CSV) lives in a unit-testable `bench` module inside the `zenoh-examples` lib crate. The two binaries are thin async drivers over the zenoh API: the server acks every sample/query with a 16-byte echo; the client computes RTT from echoed client-local timestamps (no clock sync needed).

**Tech Stack:** Rust, tokio, clap (derive), zenoh session API, `hdrhistogram` crate.

**Spec:** `docs/superpowers/specs/2026-08-10-zenoh-bench-design.md` — read it before starting.

## Global Constraints

- Repo convention: every commit message ends with `Signed-off-by: Ryan Sana <sarsanaee@gmail.com>`.
- Every new `.rs` file starts with the standard ZettaScale EPL-2.0/Apache-2.0 copyright header (copy verbatim from `examples/examples/z_pub_thr.rs` lines 1–13).
- `cargo clippy -p zenoh-examples --all-targets -- --deny warnings` must stay clean.
- The client flag for open/closed is `--load` (NOT `--mode` — `CommonArgs` already owns `-m/--mode` for the session mode).
- Key expressions: `bench/data`, `bench/ack`, `bench/query`. Wire header: 16 bytes = u64 LE seq + u64 LE timestamp-nanos.
- Run all commands from the worktree root: `/Users/sarsanaee/dojang/zenoh/.claude/worktrees/zenoh-bench`.

---

### Task 1: `bench` module — wire header + stats + CSV

**Files:**
- Create: `examples/src/bench.rs`
- Modify: `examples/src/lib.rs` (add `pub mod bench;` after the existing `use` block)
- Modify: `examples/Cargo.toml` (add `hdrhistogram = "7.5"` to `[dependencies]`)

**Interfaces:**
- Produces (used by Tasks 2 and 3):
  - `bench::encode_header(buf: &mut [u8], seq: u64, ts_nanos: u64)` — panics if `buf.len() < 16`
  - `bench::decode_header(buf: &[u8]) -> Option<(u64, u64)>` — `None` if `buf.len() < 16`
  - `bench::make_payload(size: usize, seq: u64, ts_nanos: u64) -> Vec<u8>` — size ≥ 16, filler bytes are `(i % 10) as u8`
  - `struct bench::Stats` with `fn new() -> Self`, `fn record(&mut self, rtt_nanos: u64)`, `fn count(&self) -> u64`, `fn summary(&self) -> String` (multi-line human text with p50/p90/p99/p99.9/max in µs), `fn csv_metrics(&self) -> String` (comma-joined `count,p50_us,p90_us,p99_us,p999_us,max_us`)
  - `bench::append_csv(path: &Path, header: &str, row: &str) -> std::io::Result<()>` — creates file with `header` line if missing, then appends `row`

- [ ] **Step 1: Add the dependency and module hook**

In `examples/Cargo.toml` `[dependencies]` (alphabetical spot, after `futures`):

```toml
hdrhistogram = "7.5"
```

In `examples/src/lib.rs`, after the `use` lines:

```rust
pub mod bench;
```

- [ ] **Step 2: Write the failing tests**

Create `examples/src/bench.rs` with the copyright header, then module code stubs and tests. Write tests first (they won't compile — that's the failing state):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let mut buf = [0u8; 16];
        encode_header(&mut buf, 42, 123_456_789);
        assert_eq!(decode_header(&buf), Some((42, 123_456_789)));
    }

    #[test]
    fn decode_too_short_is_none() {
        assert_eq!(decode_header(&[0u8; 15]), None);
    }

    #[test]
    fn payload_has_header_and_size() {
        let p = make_payload(64, 7, 99);
        assert_eq!(p.len(), 64);
        assert_eq!(decode_header(&p), Some((7, 99)));
    }

    #[test]
    fn stats_percentiles_sane() {
        let mut s = Stats::new();
        for i in 1..=1000u64 {
            s.record(i * 1_000); // 1..1000 µs
        }
        assert_eq!(s.count(), 1000);
        let csv = s.csv_metrics();
        let fields: Vec<&str> = csv.split(',').collect();
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0], "1000");
        let p50: f64 = fields[1].parse().unwrap();
        assert!((400.0..=600.0).contains(&p50), "p50 was {p50}");
    }

    #[test]
    fn csv_appends_with_header_once() {
        let dir = std::env::temp_dir().join(format!("zbench-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.csv");
        let _ = std::fs::remove_file(&path);
        append_csv(&path, "a,b", "1,2").unwrap();
        append_csv(&path, "a,b", "3,4").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "a,b\n1,2\n3,4\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
```

- [ ] **Step 3: Run tests, verify they fail**

Run: `cargo test -p zenoh-examples --lib`
Expected: compile error (functions not defined).

- [ ] **Step 4: Implement the module**

Above the tests in `examples/src/bench.rs`:

```rust
//! Shared helpers for the z_bench_client / z_bench_server examples.

use std::{
    fs::OpenOptions,
    io::Write,
    path::Path,
};

use hdrhistogram::Histogram;

/// Wire header: u64 LE sequence number + u64 LE client timestamp (nanos).
pub const HEADER_LEN: usize = 16;

pub fn encode_header(buf: &mut [u8], seq: u64, ts_nanos: u64) {
    buf[0..8].copy_from_slice(&seq.to_le_bytes());
    buf[8..16].copy_from_slice(&ts_nanos.to_le_bytes());
}

pub fn decode_header(buf: &[u8]) -> Option<(u64, u64)> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let seq = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let ts = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    Some((seq, ts))
}

pub fn make_payload(size: usize, seq: u64, ts_nanos: u64) -> Vec<u8> {
    assert!(size >= HEADER_LEN, "payload size must be >= {HEADER_LEN}");
    let mut buf: Vec<u8> = (0..size).map(|i| (i % 10) as u8).collect();
    encode_header(&mut buf, seq, ts_nanos);
    buf
}

/// RTT statistics over an HDR histogram (nanosecond samples, 3 significant digits).
pub struct Stats {
    hist: Histogram<u64>,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    pub fn new() -> Self {
        Self {
            hist: Histogram::new(3).expect("failed to create histogram"),
        }
    }

    pub fn record(&mut self, rtt_nanos: u64) {
        self.hist.saturating_record(rtt_nanos);
    }

    pub fn count(&self) -> u64 {
        self.hist.len()
    }

    fn us(&self, quantile: f64) -> f64 {
        self.hist.value_at_quantile(quantile) as f64 / 1_000.0
    }

    pub fn summary(&self) -> String {
        format!(
            "RTT latency (us): p50={:.1} p90={:.1} p99={:.1} p99.9={:.1} max={:.1} (n={})",
            self.us(0.50),
            self.us(0.90),
            self.us(0.99),
            self.us(0.999),
            self.hist.max() as f64 / 1_000.0,
            self.count(),
        )
    }

    pub fn csv_metrics(&self) -> String {
        format!(
            "{},{:.1},{:.1},{:.1},{:.1},{:.1}",
            self.count(),
            self.us(0.50),
            self.us(0.90),
            self.us(0.99),
            self.us(0.999),
            self.hist.max() as f64 / 1_000.0,
        )
    }
}

/// Append `row` to a CSV file, writing `header` first if the file doesn't exist yet.
pub fn append_csv(path: &Path, header: &str, row: &str) -> std::io::Result<()> {
    let existed = path.exists();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    if !existed {
        writeln!(file, "{header}")?;
    }
    writeln!(file, "{row}")
}
```

- [ ] **Step 5: Run tests, verify they pass**

Run: `cargo test -p zenoh-examples --lib`
Expected: 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add examples/Cargo.toml examples/src/lib.rs examples/src/bench.rs
git commit -m "feat(examples): bench helper module (wire header, RTT stats, CSV)

Signed-off-by: Ryan Sana <sarsanaee@gmail.com>"
```

---

### Task 2: `z_bench_server`

**Files:**
- Create: `examples/examples/z_bench_server.rs`
- Modify: `examples/Cargo.toml` (add `[[example]]` entry after the `z_sub_thr` entry)

**Interfaces:**
- Consumes: `zenoh_examples::bench::{decode_header, HEADER_LEN, encode_header}` from Task 1; `zenoh_examples::CommonArgs`.
- Produces (protocol relied on by Task 3): pubsub — subscriber on `bench/data`, per-sample 16-byte ack published on `bench/ack`; query — queryable on `bench/query` replying 16 bytes on the query's own key expression.

- [ ] **Step 1: Add the example entry**

In `examples/Cargo.toml`, after the `z_sub_thr` `[[example]]` block:

```toml
[[example]]
name = "z_bench_server"
path = "examples/z_bench_server.rs"
```

- [ ] **Step 2: Write the server**

Create `examples/examples/z_bench_server.rs` (with copyright header):

```rust
use clap::Parser;
use zenoh::{key_expr::keyexpr, qos::CongestionControl};
use zenoh_examples::{
    bench::{decode_header, encode_header, HEADER_LEN},
    CommonArgs,
};

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Pattern {
    Pubsub,
    Query,
}

#[derive(Parser, Clone, Debug)]
struct Args {
    /// Messaging pattern to serve.
    #[arg(long, value_enum, default_value = "pubsub")]
    pattern: Pattern,
    #[command(flatten)]
    common: CommonArgs,
}

#[tokio::main]
async fn main() {
    zenoh::init_log_from_env_or("error");
    let args = Args::parse();

    let session = zenoh::open(args.common).await.unwrap();

    match args.pattern {
        Pattern::Pubsub => {
            let key_data = keyexpr::new("bench/data").unwrap();
            let key_ack = keyexpr::new("bench/ack").unwrap();
            let sub = session.declare_subscriber(key_data).await.unwrap();
            let publisher = session
                .declare_publisher(key_ack)
                .congestion_control(CongestionControl::Block)
                .await
                .unwrap();
            println!("Serving pattern=pubsub on {key_data} (acks on {key_ack}). Press CTRL-C to quit...");
            let mut received: u64 = 0;
            let mut bytes: u64 = 0;
            while let Ok(sample) = sub.recv_async().await {
                let payload = sample.payload().to_bytes();
                if let Some((seq, ts)) = decode_header(&payload) {
                    let mut ack = [0u8; HEADER_LEN];
                    encode_header(&mut ack, seq, ts);
                    publisher.put(&ack[..]).await.unwrap();
                    received += 1;
                    bytes += payload.len() as u64;
                    if received.is_multiple_of(100_000) {
                        println!("received {received} msgs ({bytes} bytes)");
                    }
                }
            }
        }
        Pattern::Query => {
            let key_query = keyexpr::new("bench/query").unwrap();
            let queryable = session.declare_queryable(key_query).await.unwrap();
            println!("Serving pattern=query on {key_query}. Press CTRL-C to quit...");
            while let Ok(query) = queryable.recv_async().await {
                let header = query
                    .payload()
                    .and_then(|p| decode_header(&p.to_bytes()));
                if let Some((seq, ts)) = header {
                    let mut ack = [0u8; HEADER_LEN];
                    encode_header(&mut ack, seq, ts);
                    query
                        .reply(query.key_expr().clone(), &ack[..])
                        .await
                        .unwrap();
                }
            }
        }
    }
}
```

Note: if `is_multiple_of` is unavailable on the pinned toolchain, use `received % 100_000 == 0`. If `query.payload()` has a different name on this branch, check `examples/examples/z_queryable.rs` for the current accessor and match it.

- [ ] **Step 3: Verify it builds**

Run: `cargo build -p zenoh-examples --example z_bench_server`
Expected: builds without warnings.

- [ ] **Step 4: Smoke-run it**

```bash
target/debug/examples/z_bench_server --pattern pubsub -l tcp/127.0.0.1:7447 --no-multicast-scouting &
sleep 2
target/debug/examples/z_pub -e tcp/127.0.0.1:7447 --no-multicast-scouting -k bench/other -p hi &  # unrelated key: server must not crash
sleep 3; kill %1 %2 2>/dev/null
```

Expected: server prints its "Serving pattern=pubsub" line and doesn't panic. (`z_pub` needs a debug build: `cargo build -p zenoh-examples --example z_pub`.)

- [ ] **Step 5: Commit**

```bash
git add examples/Cargo.toml examples/examples/z_bench_server.rs
git commit -m "feat(examples): z_bench_server ack/reply server for benchmarking

Signed-off-by: Ryan Sana <sarsanaee@gmail.com>"
```

---

### Task 3: `z_bench_client` — closed loop, both patterns

**Files:**
- Create: `examples/examples/z_bench_client.rs`
- Modify: `examples/Cargo.toml` (add `[[example]]` entry after `z_bench_server`; add `"sync"` to the tokio features list)

**Interfaces:**
- Consumes: `bench::{make_payload, decode_header, Stats, append_csv, HEADER_LEN}`; server protocol from Task 2.
- Produces: the full client CLI (open-loop arrives in Task 4; this task wires `--load open` to `todo!()`).

- [ ] **Step 1: Add the example entry and tokio feature**

In `examples/Cargo.toml`:

```toml
[[example]]
name = "z_bench_client"
path = "examples/z_bench_client.rs"
```

and change the tokio dependency line to include `"sync"`:

```toml
tokio = { workspace = true, features = ["io-std", "rt-multi-thread", "sync", "time"] }
```

- [ ] **Step 2: Write the client (closed loop)**

Create `examples/examples/z_bench_client.rs` (with copyright header). Key structure:

```rust
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use clap::Parser;
use tokio::sync::{mpsc, Semaphore};
use zenoh::{key_expr::keyexpr, qos::CongestionControl, Session};
use zenoh_examples::{
    bench::{append_csv, decode_header, make_payload, Stats, HEADER_LEN},
    CommonArgs,
};

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Pattern {
    Pubsub,
    Query,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Load {
    Open,
    Closed,
}

#[derive(Parser, Clone, Debug)]
struct Args {
    /// Messaging pattern: pubsub (put + ack) or query (get + reply).
    #[arg(long, value_enum, default_value = "pubsub")]
    pattern: Pattern,
    /// Load generation: open (fixed rate) or closed (fixed window).
    #[arg(long, value_enum, default_value = "closed")]
    load: Load,
    /// Open loop: offered rate in messages per second.
    #[arg(long)]
    rate: Option<f64>,
    /// Closed loop: maximum messages in flight.
    #[arg(long, default_value = "16")]
    window: usize,
    /// Messages sent back-to-back per wakeup.
    #[arg(long, default_value = "1")]
    batch: usize,
    /// Payload size in bytes (min 16).
    #[arg(long, default_value = "64")]
    size: usize,
    /// Measured run length in seconds.
    #[arg(long, default_value = "10")]
    duration: f64,
    /// Warmup length in seconds (excluded from stats).
    #[arg(long, default_value = "1")]
    warmup: f64,
    /// Append a CSV row with knobs + metrics to this file.
    #[arg(long)]
    csv: Option<PathBuf>,
    #[command(flatten)]
    common: CommonArgs,
}
```

Argument validation in `main` before opening the session:

```rust
    if args.size < HEADER_LEN {
        eprintln!("--size must be >= {HEADER_LEN}");
        std::process::exit(2);
    }
    if args.batch == 0 || args.window == 0 {
        eprintln!("--batch and --window must be >= 1");
        std::process::exit(2);
    }
    if args.load == Load::Open && args.rate.is_none() {
        eprintln!("--rate is required with --load open");
        std::process::exit(2);
    }
```

Shared run skeleton (`main`, after validation):

```rust
    let session = zenoh::open(args.common.clone()).await.unwrap();
    let epoch = Instant::now();

    // ack stream: (seq, rtt_nanos) pairs, produced by pattern-specific plumbing
    let (ack_tx, ack_rx) = mpsc::unbounded_channel::<(u64, u64)>();
    let sender = make_sender(&session, &args, epoch, ack_tx).await;
    ...
```

`make_sender` abstracts the two patterns behind one closure-ish interface:

```rust
/// Sends one message with the given seq and embedded timestamp; acks arrive on the channel.
enum Sender {
    Pubsub {
        publisher: zenoh::pubsub::Publisher<'static>,
    },
    Query {
        session: Session,
    },
}

impl Sender {
    async fn send(&self, args: &Args, seq: u64, ts_nanos: u64, ack_tx: &mpsc::UnboundedSender<(u64, u64)>, epoch: Instant) {
        let payload = make_payload(args.size, seq, ts_nanos);
        match self {
            Sender::Pubsub { publisher } => {
                publisher.put(payload).await.unwrap();
                // acks arrive via the bench/ack subscriber task
            }
            Sender::Query { session } => {
                let replies = session
                    .get("bench/query")
                    .payload(payload)
                    .await
                    .unwrap();
                let ack_tx = ack_tx.clone();
                tokio::spawn(async move {
                    while let Ok(reply) = replies.recv_async().await {
                        if let Ok(sample) = reply.result() {
                            if let Some((seq, ts)) = decode_header(&sample.payload().to_bytes()) {
                                let now = epoch.elapsed().as_nanos() as u64;
                                let _ = ack_tx.send((seq, now.saturating_sub(ts)));
                            }
                        }
                    }
                });
            }
        }
    }
}
```

For pubsub, one background task drains the `bench/ack` subscriber:

```rust
    if args.pattern == Pattern::Pubsub {
        let sub = session
            .declare_subscriber(keyexpr::new("bench/ack").unwrap())
            .await
            .unwrap();
        let ack_tx = ack_tx.clone();
        tokio::spawn(async move {
            while let Ok(sample) = sub.recv_async().await {
                if let Some((seq, ts)) = decode_header(&sample.payload().to_bytes()) {
                    let now = epoch.elapsed().as_nanos() as u64;
                    let _ = ack_tx.send((seq, now.saturating_sub(ts)));
                }
            }
        });
    }
```

The pubsub publisher is declared on `bench/data` with `CongestionControl::Block`.

**Connectivity probe** (spec: fail fast if no server): before warmup, send seq `u64::MAX` and wait up to 5 s for its ack on the channel; exit(1) with "no ack from server within 5s — is z_bench_server running?" on timeout. Probe/warmup acks with seq below the measurement boundary are filtered later, and seq `u64::MAX` is filtered explicitly.

**Closed-loop driver:**

```rust
async fn run_closed(...) -> RunResult {
    let sem = Arc::new(Semaphore::new(args.window));
    let sent = Arc::new(AtomicU64::new(0));
    // collector task: drains ack_rx, releases permits, records stats for seq >= first_measured
    // driver loop:
    let mut seq: u64 = 0;
    let warmup_end = epoch + Duration::from_secs_f64(args.warmup);
    let run_end = warmup_end + Duration::from_secs_f64(args.duration);
    let mut first_measured: u64 = u64::MAX;
    loop {
        let now = Instant::now();
        if now >= run_end { break; }
        if first_measured == u64::MAX && now >= warmup_end {
            first_measured = seq; // everything from here on counts
        }
        let burst = args.batch.min(...);
        // acquire `burst` permits (forget them; the collector adds them back per ack)
        let permits = sem.clone().acquire_many_owned(burst as u32).await.unwrap();
        permits.forget();
        for _ in 0..burst {
            let ts = epoch.elapsed().as_nanos() as u64;
            sender.send(&args, seq, ts, &ack_tx, epoch).await;
            seq += 1;
        }
    }
    ...grace: wait up to 2s for in-flight acks, then compute totals...
}
```

The collector task owns `Stats` and counters (`acked_measured`), receives `first_measured` via a `tokio::sync::watch` channel set by the driver, and releases one semaphore permit per ack (`sem.add_permits(1)`).

**Summary + CSV** (shared by both loops):

```rust
struct RunResult {
    sent_measured: u64,
    acked_measured: u64,
    elapsed: Duration,
    stats: Stats,
    offered_rate: Option<f64>,
}
```

Printed summary includes achieved send rate (`sent_measured / elapsed`), MB/s (`rate * size / 1e6`), acked count, loss, `stats.summary()`, and for open loop the offered rate. CSV header:

```text
pattern,load,rate,window,batch,size,duration_s,sent,acked,loss,achieved_msgs,achieved_mbs,acked_count,p50_us,p90_us,p99_us,p999_us,max_us
```

(`rate` empty for closed loop, `window` empty for open loop; metrics tail comes from `stats.csv_metrics()`.)

Exit non-zero (code 1) with a message if `acked_measured < sent_measured * 95 / 100` after the grace period — but still print the summary and write the CSV row first.

`--load open` in this task: `unimplemented!("open loop lands in the next commit")`.

- [ ] **Step 3: Build**

Run: `cargo build -p zenoh-examples --example z_bench_client --example z_bench_server`
Expected: builds cleanly.

- [ ] **Step 4: Smoke test closed loop, both patterns, over tcp**

```bash
target/debug/examples/z_bench_server --pattern pubsub -l tcp/127.0.0.1:7447 --no-multicast-scouting &
SERVER=$!
sleep 2
target/debug/examples/z_bench_client --pattern pubsub --load closed --window 32 --batch 4 --size 256 \
  --duration 5 --warmup 1 --csv /tmp/zbench-smoke.csv -e tcp/127.0.0.1:7447 --no-multicast-scouting
kill $SERVER
target/debug/examples/z_bench_server --pattern query -l tcp/127.0.0.1:7447 --no-multicast-scouting &
SERVER=$!
sleep 2
target/debug/examples/z_bench_client --pattern query --load closed --window 8 --size 64 \
  --duration 5 --warmup 1 --csv /tmp/zbench-smoke.csv -e tcp/127.0.0.1:7447 --no-multicast-scouting
kill $SERVER
cat /tmp/zbench-smoke.csv
```

Expected: both runs print a summary with non-zero throughput and plausible RTTs (sub-millisecond p50 on loopback), exit 0, and the CSV has 1 header + 2 rows. Also verify the failure path: run the client with no server and confirm it exits 1 within ~5 s.

- [ ] **Step 5: Commit**

```bash
git add examples/Cargo.toml examples/examples/z_bench_client.rs
git commit -m "feat(examples): z_bench_client closed-loop benchmark (pubsub + query)

Signed-off-by: Ryan Sana <sarsanaee@gmail.com>"
```

---

### Task 4: `z_bench_client` — open loop

**Files:**
- Modify: `examples/examples/z_bench_client.rs`

**Interfaces:**
- Consumes: everything from Task 3 (`Sender::send`, collector, `RunResult`, summary/CSV).
- Produces: `run_open(...) -> RunResult` replacing the `unimplemented!()`.

- [ ] **Step 1: Implement the open-loop driver**

Core rules from the spec: tick period = `batch / rate` seconds; **latency is measured from the scheduled send time** (the timestamp embedded in the payload is the tick's scheduled time, not `Instant::now()`), so RTT computed from the echo automatically includes any send-side backlog (coordinated omission captured). If sends fall behind, keep going and report offered vs achieved.

```rust
async fn run_open(...) -> RunResult {
    let rate = args.rate.unwrap();
    let period = Duration::from_secs_f64(args.batch as f64 / rate);
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);

    let warmup_end = epoch + Duration::from_secs_f64(args.warmup);
    let run_end = warmup_end + Duration::from_secs_f64(args.duration);
    let start = Instant::now();
    let mut seq: u64 = 0;
    let mut tick_index: u64 = 0;
    let mut first_measured: u64 = u64::MAX;
    loop {
        interval.tick().await;
        let scheduled = start + period * tick_index as u32; // scheduled time of this burst
        tick_index += 1;
        if scheduled >= run_end { break; }
        if first_measured == u64::MAX && scheduled >= warmup_end {
            first_measured = seq;
            let _ = first_measured_tx.send(first_measured);
        }
        let scheduled_nanos = scheduled.duration_since(epoch).as_nanos() as u64;
        for _ in 0..args.batch {
            sender.send(&args, seq, scheduled_nanos, &ack_tx, epoch).await;
            seq += 1;
        }
    }
    // same 2s grace + totals as closed loop; offered_rate = Some(rate)
}
```

(Note `period * u32` overflow: for long runs compute `scheduled = start + Duration::from_secs_f64(tick_index as f64 * period.as_secs_f64())` instead — pick this form in the implementation.)

Achieved rate = `sent_measured / measured_wall_time`; the summary prints `offered X msg/s, achieved Y msg/s` and warns when `Y < 0.99 * X`.

- [ ] **Step 2: Build**

Run: `cargo build -p zenoh-examples --example z_bench_client`
Expected: clean build.

- [ ] **Step 3: Smoke test open loop**

```bash
target/debug/examples/z_bench_server --pattern pubsub -l tcp/127.0.0.1:7447 --no-multicast-scouting &
SERVER=$!
sleep 2
# comfortable rate: achieved ≈ offered
target/debug/examples/z_bench_client --pattern pubsub --load open --rate 10000 --batch 10 --size 128 \
  --duration 5 --warmup 1 --csv /tmp/zbench-smoke.csv -e tcp/127.0.0.1:7447 --no-multicast-scouting
kill $SERVER
```

Expected: exit 0; achieved within ~1% of 10000 msg/s; sane RTTs. Then rerun with an absurd `--rate 50000000` and confirm it completes, reports achieved << offered, and (if acks lag) exits with the loss warning rather than hanging.

- [ ] **Step 4: Commit**

```bash
git add examples/examples/z_bench_client.rs
git commit -m "feat(examples): z_bench_client open-loop rate-driven mode

Signed-off-by: Ryan Sana <sarsanaee@gmail.com>"
```

---

### Task 5: WebTransport smoke, lint, docs

**Files:**
- Modify: `examples/README.md` (add a `z_bench_client` / `z_bench_server` section after the `z_sub_thr` section)

**Interfaces:**
- Consumes: everything shipped in Tasks 1–4.

- [ ] **Step 1: Release build with webtransport**

Run: `cargo build --release -p zenoh-examples -F transport_webtransport --example z_bench_client --example z_bench_server`
Expected: clean.

- [ ] **Step 2: Smoke over webtransport**

Check `docs` or the recent `docs(link): webtransport end-to-end demo instructions` commit (`git show 152613734 --stat`) for the exact webtransport locator syntax (certificates etc.) and reuse it. Then:

```bash
target/release/examples/z_bench_server --pattern pubsub -l <webtransport locator> --no-multicast-scouting &
sleep 2
target/release/examples/z_bench_client --pattern pubsub --load closed --window 64 --batch 8 --size 1024 \
  --duration 10 --csv /tmp/zbench-wt.csv -e <webtransport locator> --no-multicast-scouting
```

Expected: exit 0, summary printed. Record the numbers in the final report.

- [ ] **Step 3: Clippy + fmt + full example-crate test**

```bash
cargo fmt --all
cargo clippy -p zenoh-examples --all-targets -- --deny warnings
cargo test -p zenoh-examples --lib
```

Expected: all clean/pass.

- [ ] **Step 4: Document usage**

Add to `examples/README.md`, following the style of the existing `z_pub_thr` entry: what each binary does, the four (pattern × load) combinations, one copy-paste server+client pair for tcp and one for webtransport, and this sweep example:

```bash
for rate in 1000 10000 100000 1000000; do
  target/release/examples/z_bench_client --load open --rate $rate --batch 16 --size 256 \
    --duration 10 --csv sweep.csv -e tcp/127.0.0.1:7447 --no-multicast-scouting
done
```

- [ ] **Step 5: Commit**

```bash
git add examples/README.md
git commit -m "docs(examples): z_bench usage and sweep instructions

Signed-off-by: Ryan Sana <sarsanaee@gmail.com>"
```

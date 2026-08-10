//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Parser;
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
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

impl Pattern {
    fn as_str(self) -> &'static str {
        match self {
            Pattern::Pubsub => "pubsub",
            Pattern::Query => "query",
        }
    }
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Load {
    Open,
    Closed,
}

impl Load {
    fn as_str(self) -> &'static str {
        match self {
            Load::Open => "open",
            Load::Closed => "closed",
        }
    }
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
    async fn send(
        &self,
        args: &Args,
        seq: u64,
        ts_nanos: u64,
        ack_tx: &mpsc::UnboundedSender<(u64, u64)>,
        epoch: Instant,
    ) {
        let payload = make_payload(args.size, seq, ts_nanos);
        match self {
            Sender::Pubsub { publisher } => {
                publisher.put(payload).await.unwrap_or_else(|e| {
                    eprintln!(">> Error sending data: {e}");
                });
                // acks arrive via the bench/ack subscriber task
            }
            Sender::Query { session } => {
                let replies = session
                    .get("bench/query")
                    .payload(payload)
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!(">> Error sending query: {e}");
                        std::process::exit(1);
                    });
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

/// Builds the pattern-specific `Sender`, wiring up the bench/ack subscriber for pubsub.
async fn make_sender(
    session: &Session,
    args: &Args,
    epoch: Instant,
    ack_tx: &mpsc::UnboundedSender<(u64, u64)>,
) -> Sender {
    match args.pattern {
        Pattern::Pubsub => {
            let key_data = keyexpr::new("bench/data").unwrap();
            let key_ack = keyexpr::new("bench/ack").unwrap();
            let publisher = session
                .declare_publisher(key_data)
                .congestion_control(CongestionControl::Block)
                .await
                .unwrap();
            let sub = session.declare_subscriber(key_ack).await.unwrap();
            let ack_tx = ack_tx.clone();
            tokio::spawn(async move {
                while let Ok(sample) = sub.recv_async().await {
                    if let Some((seq, ts)) = decode_header(&sample.payload().to_bytes()) {
                        let now = epoch.elapsed().as_nanos() as u64;
                        let _ = ack_tx.send((seq, now.saturating_sub(ts)));
                    }
                }
            });
            Sender::Pubsub { publisher }
        }
        Pattern::Query => Sender::Query {
            session: session.clone(),
        },
    }
}

struct RunResult {
    sent_measured: u64,
    acked_measured: u64,
    elapsed: Duration,
    stats: Stats,
    offered_rate: Option<f64>,
}

/// Drains acks, releases semaphore permits, and accumulates stats for measured messages.
/// Runs until told to stop, then keeps draining for a 2s grace period before reporting.
async fn collector(
    mut ack_rx: mpsc::UnboundedReceiver<(u64, u64)>,
    sem: Arc<Semaphore>,
    first_measured_rx: watch::Receiver<u64>,
    mut stop_rx: oneshot::Receiver<()>,
    result_tx: oneshot::Sender<(Stats, u64)>,
) {
    let mut stats = Stats::new();
    let mut acked_measured: u64 = 0;

    let record = |seq: u64, rtt: u64, stats: &mut Stats, acked_measured: &mut u64| {
        let fm = *first_measured_rx.borrow();
        if seq != u64::MAX && fm != u64::MAX && seq >= fm {
            stats.record(rtt);
            *acked_measured += 1;
        }
    };

    loop {
        tokio::select! {
            maybe = ack_rx.recv() => {
                match maybe {
                    Some((seq, rtt)) => {
                        // Probe acks (seq == u64::MAX) never took a permit from
                        // this semaphore, which is created fresh per run after
                        // the probe completes. A duplicate probe ack arriving
                        // late (from the retried probe) must not credit a
                        // permit here — that would inflate the closed-loop
                        // in-flight window.
                        if seq != u64::MAX {
                            sem.add_permits(1);
                        }
                        record(seq, rtt, &mut stats, &mut acked_measured);
                    }
                    None => break,
                }
            }
            _ = &mut stop_rx => break,
        }
    }

    let grace = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(grace);
    loop {
        tokio::select! {
            maybe = ack_rx.recv() => {
                match maybe {
                    Some((seq, rtt)) => record(seq, rtt, &mut stats, &mut acked_measured),
                    None => break,
                }
            }
            _ = &mut grace => break,
        }
    }

    let _ = result_tx.send((stats, acked_measured));
}

async fn run_closed(
    sender: Sender,
    args: &Args,
    ack_rx: mpsc::UnboundedReceiver<(u64, u64)>,
    ack_tx: mpsc::UnboundedSender<(u64, u64)>,
    epoch: Instant,
    measure_start: Instant,
) -> RunResult {
    let sem = Arc::new(Semaphore::new(args.window));
    let (first_measured_tx, first_measured_rx) = watch::channel(u64::MAX);
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let (result_tx, result_rx) = oneshot::channel::<(Stats, u64)>();

    tokio::spawn(collector(
        ack_rx,
        sem.clone(),
        first_measured_rx,
        stop_rx,
        result_tx,
    ));

    let burst = args.batch.min(args.window).max(1);
    let mut seq: u64 = 0;
    let warmup_end = measure_start + Duration::from_secs_f64(args.warmup);
    let run_end = warmup_end + Duration::from_secs_f64(args.duration);
    let mut first_measured: u64 = u64::MAX;
    let mut sent_measured: u64 = 0;

    loop {
        let now = Instant::now();
        if now >= run_end {
            break;
        }
        if first_measured == u64::MAX && now >= warmup_end {
            first_measured = seq;
            let _ = first_measured_tx.send(first_measured);
        }
        // Bound the acquire on the run deadline: a lost ack permanently
        // consumes a permit (the collector never sees it to release it
        // back), so without a deadline a dead server/link can hang here
        // forever once `window` acks have been lost.
        let acquired =
            tokio::time::timeout_at(run_end.into(), sem.clone().acquire_many_owned(burst as u32))
                .await;
        let permits = match acquired {
            Ok(Ok(permits)) => permits,
            _ => break,
        };
        permits.forget();
        for _ in 0..burst {
            let ts = epoch.elapsed().as_nanos() as u64;
            sender.send(args, seq, ts, &ack_tx, epoch).await;
            if first_measured != u64::MAX {
                sent_measured += 1;
            }
            seq += 1;
        }
    }

    let elapsed = if first_measured == u64::MAX {
        Duration::from_secs(0)
    } else {
        Instant::now().saturating_duration_since(warmup_end)
    };

    // Signal the collector to enter its grace period, then wait for the final tally.
    let _ = stop_tx.send(());
    let (stats, acked_measured) = result_rx.await.unwrap_or_else(|_| (Stats::new(), 0));

    RunResult {
        sent_measured,
        acked_measured,
        elapsed,
        stats,
        offered_rate: None,
    }
}

/// Open-loop driver: fires `args.batch` messages every `batch / rate` seconds,
/// regardless of how long acks take. Latency is measured from the tick's
/// *scheduled* send time (not `Instant::now()` at send time), so any
/// send-side backlog caused by falling behind the offered rate is captured
/// in the RTT rather than hidden (avoids coordinated omission).
async fn run_open(
    sender: Sender,
    args: &Args,
    ack_rx: mpsc::UnboundedReceiver<(u64, u64)>,
    ack_tx: mpsc::UnboundedSender<(u64, u64)>,
    epoch: Instant,
    measure_start: Instant,
) -> RunResult {
    let rate = args.rate.unwrap();
    let period = Duration::from_secs_f64(args.batch as f64 / rate);
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);

    // Open loop has no send-side backpressure, so the collector's semaphore
    // is unused (permits accumulate but nothing ever acquires them).
    let sem = Arc::new(Semaphore::new(0));
    let (first_measured_tx, first_measured_rx) = watch::channel(u64::MAX);
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let (result_tx, result_rx) = oneshot::channel::<(Stats, u64)>();

    tokio::spawn(collector(
        ack_rx,
        sem,
        first_measured_rx,
        stop_rx,
        result_tx,
    ));

    let warmup_end = measure_start + Duration::from_secs_f64(args.warmup);
    let run_end = warmup_end + Duration::from_secs_f64(args.duration);
    let mut seq: u64 = 0;
    let mut tick_index: u64 = 0;
    let mut first_measured: u64 = u64::MAX;
    let mut sent_measured: u64 = 0;

    loop {
        interval.tick().await;
        // f64 form to avoid overflowing `Duration * u32` on long runs.
        let scheduled =
            measure_start + Duration::from_secs_f64(tick_index as f64 * period.as_secs_f64());
        tick_index += 1;
        if scheduled >= run_end {
            break;
        }
        if first_measured == u64::MAX && scheduled >= warmup_end {
            first_measured = seq;
            let _ = first_measured_tx.send(first_measured);
        }
        let scheduled_nanos = scheduled.saturating_duration_since(epoch).as_nanos() as u64;
        for _ in 0..args.batch {
            sender
                .send(args, seq, scheduled_nanos, &ack_tx, epoch)
                .await;
            if first_measured != u64::MAX {
                sent_measured += 1;
            }
            seq += 1;
        }
    }

    let elapsed = if first_measured == u64::MAX {
        Duration::from_secs(0)
    } else {
        Instant::now().saturating_duration_since(warmup_end)
    };

    // Signal the collector to enter its grace period, then wait for the final tally.
    let _ = stop_tx.send(());
    let (stats, acked_measured) = result_rx.await.unwrap_or_else(|_| (Stats::new(), 0));

    RunResult {
        sent_measured,
        acked_measured,
        elapsed,
        stats,
        offered_rate: Some(rate),
    }
}

fn report(args: &Args, result: &RunResult) {
    let elapsed_s = result.elapsed.as_secs_f64();
    let achieved_rate = if elapsed_s > 0.0 {
        result.sent_measured as f64 / elapsed_s
    } else {
        0.0
    };
    let achieved_mbs = achieved_rate * args.size as f64 / 1e6;
    let loss = result.sent_measured.saturating_sub(result.acked_measured);

    println!(
        "pattern={} load={} sent={} acked={} loss={} rate={achieved_rate:.1} msg/s ({achieved_mbs:.3} MB/s)",
        args.pattern.as_str(),
        args.load.as_str(),
        result.sent_measured,
        result.acked_measured,
        loss,
    );
    if let Some(rate) = result.offered_rate {
        println!("offered {rate:.1} msg/s, achieved {achieved_rate:.1} msg/s");
        if achieved_rate < 0.99 * rate {
            eprintln!(
                "warning: achieved rate {achieved_rate:.1} msg/s is below 99% of offered {rate:.1} msg/s"
            );
        }
    }
    println!("{}", result.stats.summary());
    println!(
        "batch={} size={} duration={}s warmup={}s",
        args.batch, args.size, args.duration, args.warmup
    );

    if let Some(path) = &args.csv {
        let header = "pattern,load,rate,window,batch,size,duration_s,sent,acked,loss,achieved_msgs,achieved_mbs,acked_count,p50_us,p90_us,p99_us,p999_us,max_us";
        let rate_field = if args.load == Load::Open {
            args.rate.map(|r| r.to_string()).unwrap_or_default()
        } else {
            String::new()
        };
        let window_field = if args.load == Load::Open {
            String::new()
        } else {
            args.window.to_string()
        };
        let row = format!(
            "{},{},{},{},{},{},{},{},{},{},{:.1},{:.3},{}",
            args.pattern.as_str(),
            args.load.as_str(),
            rate_field,
            window_field,
            args.batch,
            args.size,
            args.duration,
            result.sent_measured,
            result.acked_measured,
            loss,
            achieved_rate,
            achieved_mbs,
            result.stats.csv_metrics(),
        );
        if let Err(e) = append_csv(path, header, &row) {
            eprintln!("failed to write csv to {}: {e}", path.display());
        }
    }
}

#[tokio::main]
async fn main() {
    zenoh::init_log_from_env_or("error");
    let args = Args::parse();

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

    let session = zenoh::open(args.common.clone()).await.unwrap();
    let epoch = Instant::now();

    // ack stream: (seq, rtt_nanos) pairs, produced by pattern-specific plumbing
    let (ack_tx, mut ack_rx) = mpsc::unbounded_channel::<(u64, u64)>();
    let sender = make_sender(&session, &args, epoch, &ack_tx).await;

    // Connectivity probe: fail fast if no server is listening. Resend every
    // ~500ms (reusing seq == u64::MAX) within the overall 5s deadline, to
    // ride out a startup propagation race where the server's subscriber /
    // queryable hasn't finished matching yet when the first probe goes out.
    // Duplicate probe acks are harmless: the collector (started only after
    // the probe completes) ignores seq == u64::MAX for both stats and
    // semaphore permits, so a late duplicate that outlives this loop and
    // lands in the collector's channel is a no-op there.
    let probe_deadline = Instant::now() + Duration::from_secs(5);
    let mut probe_acked = false;
    while Instant::now() < probe_deadline {
        let probe_ts = epoch.elapsed().as_nanos() as u64;
        sender.send(&args, u64::MAX, probe_ts, &ack_tx, epoch).await;
        let remaining = probe_deadline.saturating_duration_since(Instant::now());
        let wait = remaining.min(Duration::from_millis(500));
        if wait.is_zero() {
            break;
        }
        let got = tokio::time::timeout(wait, async {
            loop {
                match ack_rx.recv().await {
                    Some((seq, _)) if seq == u64::MAX => return true,
                    Some(_) => continue,
                    None => return false,
                }
            }
        })
        .await;
        match got {
            Ok(true) => {
                probe_acked = true;
                break;
            }
            Ok(false) => break, // ack channel closed, no point retrying
            Err(_) => continue, // timed out this round, resend
        }
    }
    if !probe_acked {
        eprintln!("no ack from server within 5s — is z_bench_server running?");
        std::process::exit(1);
    }

    // `epoch` stays the RTT timestamp origin, but the warmup/run schedule
    // starts only now: a slow probe (session matching, connection setup —
    // up to 5s) must not eat into the warmup window.
    let measure_start = Instant::now();

    let result = match args.load {
        Load::Closed => run_closed(sender, &args, ack_rx, ack_tx, epoch, measure_start).await,
        Load::Open => run_open(sender, &args, ack_rx, ack_tx, epoch, measure_start).await,
    };

    report(&args, &result);

    if result.sent_measured == 0 {
        eprintln!("no messages were sent during the measured window — run invalid");
        std::process::exit(1);
    }

    if result.acked_measured < result.sent_measured * 95 / 100 {
        eprintln!(
            "loss too high: acked {} / sent {} (< 95%)",
            result.acked_measured, result.sent_measured
        );
        std::process::exit(1);
    }
}

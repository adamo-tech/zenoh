# Zenoh Rust examples

## Start instructions

   When Zenoh is built in release mode:

   ```bash
   ./target/release/example/<example_name>
   ```

   Each example accepts the `-h` or `--help` option that provides a description of its arguments and their default values.

   If you run the tests against the Zenoh router running in a Docker container, you need to add the
   `-e tcp/localhost:7447` option to your examples. That's because Docker doesn't support UDP multicast
   transport, and therefore the Zenoh scouting and discovery mechanism cannot work with it.

## Examples description

### z_scout

   Scouts for Zenoh peers and routers available on the network.

   Typical usage:

   ```bash
   z_scout
   ```

### z_info

   Gets information about the Zenoh session.

   Typical usage:

   ```bash
   z_info
   ```

### z_put

   Puts a path/value into Zenoh.
   The path/value will be received by all matching subscribers, for instance the [z_sub](#z_sub)
   and [z_storage](#z_storage) examples.

   Typical usage:

   ```bash
   z_put
   ```

   or

   ```bash
   z_put -k demo/example/test -v 'Hello World'
   ```

### z_pub

   Declares a key expression and a publisher. Then writes values periodically on the declared key expression.
   The published value will be received by all matching subscribers, for instance the [z_sub](#z_sub) and [z_storage](#z_storage) examples.

   Typical usage:

   ```bash
   z_pub
   ```

   or

   ```bash
   z_pub -k demo/example/test -v 'Hello World'
   ```

### z_sub

   Declares a key expression and a subscriber.
   The subscriber will be notified of each `put` or `delete` made on any key expression matching the subscriber key expression, and will print this notification.

   Typical usage:

   ```bash
   z_sub
   ```

   or

   ```bash
   z_sub -k 'demo/**'
   ```

### z_pull

   Declares a key expression and a pull subscriber.  
   On each pull, the pull subscriber will be notified of the last N `put` or `delete` made on each key expression matching the subscriber key expression, and will print this notification.

   Typical usage:

   ```bash
   z_pull
   ```

   or

   ```bash
   z_pull -k demo/** --size 3
   ```

### z_get

   Sends a query message for a selector.
   The queryables with a matching path or selector (for instance [z_queryable](#z_queryable) and [z_storage](#z_storage))
   will receive this query and reply with paths/values that will be received by the receiver stream.

   Typical usage:

   ```bash
   z_get
   ```

   or

   ```bash
   z_get -s 'demo/**'
   ```

### z_querier

   Continuously sends query messages for a selector.
   The queryables with a matching path or selector (for instance [z_queryable](#z_queryable) and [z_storage](#z_storage))
   will receive these queries and reply with paths/values that will be received by the querier.

   Typical usage:

   ```bash
   z_querier
   ```

   or

   ```bash
   z_querier -s 'demo/**'
   ```

### z_queryable

   Declares a queryable function with a path.
   This queryable function will be triggered by each call to get
   with a selector that matches the path, and will return a value to the querier.

   Typical usage:

   ```bash
   z_queryable
   ```

   or

   ```bash
   z_queryable -k demo/example/queryable -v 'This is the result'
   ```

### z_storage

   Trivial implementation of a storage in memory.
   This example declares a subscriber and a queryable on the same selector.
   The subscriber callback will store the received paths/values in a hashmap.
   The queryable callback will answer to queries with the paths/values stored in the hashmap
   and that match the queried selector.

   Typical usage:

   ```bash
   z_storage
   ```

   or

   ```bash
   z_storage -k 'demo/**'
   ```

### z_pub_shm & z_sub

   A pub/sub example involving the shared-memory feature.
   Note that on subscriber side, the same `z_sub` example than for non-shared-memory example is used.

   Typical Subscriber usage:

   ```bash
   z_sub
   ```

   Typical Publisher usage:

   ```bash
   z_pub_shm
   ```

### z_pub_thr & z_sub_thr

   Pub/Sub throughput test.
   This example allows performing throughput measurements between a publisher performing
   put operations and a subscriber receiving notifications of those puts.

   Typical Subscriber usage:

   ```bash
   z_sub_thr
   ```

   Typical Publisher usage:

   ```bash
   z_pub_thr 1024
   ```

### z_ping & z_pong

   Pub/Sub roundtrip time test.
   This example allows performing roundtrip time measurements. The z_ping example
   performs a put operation on a first key expression, waits for a reply from the pong
   example on a second key expression and measures the time between the two.
   The pong application waits for samples on the first key expression and replies by
   writing back the received data on the second key expression.

  :warning: z_pong needs to start first to avoid missing the kickoff from z_ping.

   Typical Pong usage:

   ```bash
   z_pong
   ```

   Typical Ping usage:

   ```bash
   z_ping 1024
   ```

### z_pub_shm_thr & z_sub_thr

   Pub/Sub throughput test involving the shared-memory feature.
   This example allows performing throughput measurements between a publisher performing
   put operations with the shared-memory feature and a subscriber receiving notifications
   of those puts.
   Note that on subscriber side, the same `z_sub_thr` example than for non-shared-memory example is used.

   Typical Subscriber usage:

   ```bash
   z_sub_thr
   ```

   Typical Publisher usage:

   ```bash
   z_pub_shm_thr
   ```

### z_bench_server & z_bench_client

   RTT/throughput benchmark harness, more configurable than [z_pub_thr / z_sub_thr](#z_pub_thr--z_sub_thr).
   `z_bench_server` declares the `bench/*` key expressions and answers back (with an ack `put`
   for the `pubsub` pattern, or a reply for the `query` pattern) so `z_bench_client` can measure
   round-trip latency and throughput. Payloads carry a 16-byte header (sequence number + send
   timestamp) that the client uses to compute per-message RTT; `--size` must be at least 16.

   `z_bench_client` supports two load-generation modes and two messaging patterns, independently:

   - `--load closed --window W --batch B`: closed-loop, keeps at most `W` messages in flight,
     sending `B` messages back-to-back whenever the window has room. Reports achieved rate and
     RTT percentiles.
   - `--load open --rate R --batch B`: open-loop, offers a fixed rate of `R` messages/second
     (sent in bursts of `B`), independent of how fast acks/replies come back. Useful for finding
     the rate at which latency starts to blow up.
   - `--pattern pubsub`: publish on `bench/data`, server acks on `bench/ack`.
   - `--pattern query`: `get` on `bench/query`, server replies inline.

   That gives four combinations: `pubsub`+`closed`, `pubsub`+`open`, `query`+`closed`,
   `query`+`open`. Add `--duration` (measured seconds), `--warmup` (seconds excluded from stats),
   and `--csv <path>` to append a row of knobs + measured metrics (throughput, RTT p50/p99/p999/max)
   to a CSV file for later comparison across runs.

   **TCP** — server and client, closed-loop pubsub:

   ```bash
   z_bench_server --pattern pubsub -l tcp/127.0.0.1:7447 --no-multicast-scouting &
   z_bench_client --pattern pubsub --load closed --window 64 --batch 8 --size 1024 \
     --duration 10 --csv bench.csv -e tcp/127.0.0.1:7447 --no-multicast-scouting
   ```

   **WebTransport** — same, over the `webtransport` link (requires building with
   `-F transport_webtransport`; see `io/zenoh-links/zenoh-link-webtransport/DEMO.md` for demo
   certificate generation):

   ```bash
   z_bench_server --pattern pubsub \
     -l 'webtransport/127.0.0.1:7447#listen_certificate_file=.demo-certs/cert.pem;listen_private_key_file=.demo-certs/key.pem' \
     --no-multicast-scouting &
   z_bench_client --pattern pubsub --load closed --window 64 --batch 8 --size 1024 \
     --duration 10 --csv bench-wt.csv \
     -e 'webtransport/localhost:7447#root_ca_certificate_file=.demo-certs/cert.pem' \
     --no-multicast-scouting
   ```

   Rate sweep (open loop, sweeping offered rate, appending each result to `sweep.csv`):

   ```bash
   for rate in 1000 10000 100000 1000000; do
     target/release/examples/z_bench_client --load open --rate $rate --batch 16 --size 256 \
       --duration 10 --csv sweep.csv -e tcp/127.0.0.1:7447 --no-multicast-scouting
   done
   ```

### z_liveliness

   Declares a liveliness token on a given key expression (`group1/zenoh-rs` by default).
   This token will be seen alive by the `z_get_liveliness` and `z_sub_liveliness` until
   user explicitly drops the token by pressing `'d'` or implicitly dropped by terminating
   or killing the `z_liveliness` example.

   Typical usage:

   ```bash
   z_liveliness
   ```

   or

   ```bash
   z_liveliness -k 'group1/member1'
   ```

### z_get_liveliness

   Queries all the currently alive liveliness tokens that match a given key expression
   (`group1/**` by default). Those tokens could be declared by the `z_liveliness` example.

   Typical usage:

   ```bash
   z_get_liveliness
   ```

   or

   ```bash
   z_get_liveliness -k 'group1/**'
   ```

### z_sub_liveliness

   Subscribe to all liveliness changes (liveliness tokens getting alive or
   liveliness tokens being dropped) that match a given key expression
   (`group1/**` by default). Those tokens could be declared by the `z_liveliness`
   example.
   Note: the `z_sub_liveliness` example will not receive information about
   matching liveliness tokens that were alive before it's start.

   Typical usage:

   ```bash
   z_sub_liveliness
   ```

   or

   ```bash
   z_sub_liveliness -k 'group1/**'
   ```

### z_bytes

   Show how to serialize different message types into ZBytes, and then deserialize from ZBytes to the original message types.

### z_bytes_shm

   Show how to work with SHM buffers: mut and const access, buffer ownership concepts

### z_alloc_shm

   Show how to allocate SHM buffers

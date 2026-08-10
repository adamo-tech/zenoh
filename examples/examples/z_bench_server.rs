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
                    if received % 100_000 == 0 {
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

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
            hist: Histogram::new_with_bounds(1, 3_600_000_000_000, 3)
                .expect("failed to create histogram"),
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

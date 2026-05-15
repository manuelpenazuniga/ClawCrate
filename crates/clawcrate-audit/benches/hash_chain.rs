#![forbid(unsafe_code)]

use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Utc;
use clawcrate_audit::{
    compute_event_hash, verify_audit_chain, ArtifactWriter, AUDIT_NDJSON, GENESIS_HASH,
};
use clawcrate_types::{AuditEvent, AuditEventKind};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn sample_event(index: u32) -> AuditEvent {
    AuditEvent {
        timestamp: chrono::DateTime::parse_from_rfc3339("2026-05-15T02:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc),
        event: AuditEventKind::ProcessStarted {
            pid: 10_000 + index,
            command: vec![
                "cargo".to_string(),
                "test".to_string(),
                "--workspace".to_string(),
            ],
        },
    }
}

fn bench_hash_chain_compute(c: &mut Criterion) {
    let event = sample_event(1);
    c.bench_function("hash_chain_compute_single_event", |b| {
        b.iter(|| compute_event_hash(black_box(&event), black_box(GENESIS_HASH)))
    });
}

fn bench_hash_chain_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_chain_append");
    group.throughput(Throughput::Elements(1));
    group.bench_function("single_event_new_file", |b| {
        b.iter_batched(
            || {
                let root = unique_tmp_dir("clawcrate_bench_append");
                let writer = ArtifactWriter::new(&root, "exec-bench").expect("create writer");
                let event = sample_event(1);
                (root, writer, event)
            },
            |(root, writer, event)| {
                with_hash_chain_enabled(|| writer.append_audit_event(black_box(&event)))
                    .expect("append audit event");
                fs::remove_dir_all(root).ok();
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_verify_throughput(c: &mut Criterion) {
    let events = 10_000usize;
    let root = unique_tmp_dir("clawcrate_bench_verify");
    let audit_path = generate_chained_audit_log(&root, events);

    let mut group = c.benchmark_group("verify_hash_chain");
    group.throughput(Throughput::Elements(events as u64));
    group.bench_with_input(
        BenchmarkId::from_parameter(format!("{events}_events")),
        &audit_path,
        |b, path| {
            b.iter(|| {
                let result = verify_audit_chain(black_box(path)).expect("verify chain");
                assert!(result.valid);
                black_box(result.events_checked);
            })
        },
    );
    group.finish();

    fs::remove_dir_all(root).ok();
}

fn generate_chained_audit_log(root: &Path, events: usize) -> PathBuf {
    let writer = ArtifactWriter::new(root, "exec-verify-bench").expect("create writer");
    with_hash_chain_enabled(|| {
        for index in 0..events {
            writer
                .append_audit_event(&sample_event(index as u32))
                .expect("append chained event");
        }
    });
    writer.artifacts_dir().join(AUDIT_NDJSON)
}

fn with_hash_chain_enabled<T>(f: impl FnOnce() -> T) -> T {
    let previous = std::env::var_os("CLAWCRATE_AUDIT_HASHCHAIN");
    std::env::set_var("CLAWCRATE_AUDIT_HASHCHAIN", "1");
    let result = f();
    match previous {
        Some(value) => std::env::set_var("CLAWCRATE_AUDIT_HASHCHAIN", value),
        None => std::env::remove_var("CLAWCRATE_AUDIT_HASHCHAIN"),
    }
    result
}

fn unique_tmp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp benchmark directory");
    dir
}

criterion_group!(
    benches,
    bench_hash_chain_compute,
    bench_hash_chain_append,
    bench_verify_throughput
);
criterion_main!(benches);

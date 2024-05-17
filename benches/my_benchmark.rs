use criterion::{criterion_group, criterion_main, Criterion};
use fault_simulator::prelude::*;
use std::env;

fn criterion_benchmark(c: &mut Criterion) -> Result<(), String> {
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("tests/bin/victim_4.elf"))?;
    // Set threads to one because of current MacOS problems
    env::set_var("RAYON_NUM_THREADS", "1");

    let mut group = c.benchmark_group("fault-attack_peformance");
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(50));
    group.sample_size(10);
    group.bench_function("single attack", |b| {
        b.iter(|| {
            let _ = attack.single_glitch(2000, false, false, 1..=2);
        })
    });
    group.bench_function("double attack", |b| {
        b.iter(|| {
            let _ = attack.double_glitch(2000, false, false, 1..=1);
        })
    });
    Ok(())
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

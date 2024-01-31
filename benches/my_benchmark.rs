use criterion::{criterion_group, criterion_main, Criterion};
use unicorn_1::FaultAttacks;
use std::env;

fn criterion_benchmark(c: &mut Criterion) {
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("benches/bin/aarch32/bl1.elf"));
    // Set threads to one because of current MacOS problems
    env::set_var("RAYON_NUM_THREADS", "1");

    c.warm_up_time(std::time::Duration::from_secs(10));
    c.measurement_time(std::time::Duration::from_secs(120));
    c.sample_size(20);
    c.bench_function("single attack", |b| {
        b.iter(|| {
            attack.single_glitch(false, 1..=10);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

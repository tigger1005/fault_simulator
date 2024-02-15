use criterion::{criterion_group, criterion_main, Criterion};
use fault_simulator::fault_attacks::FaultAttacks;
use std::env;

fn criterion_benchmark(c: &mut Criterion) {
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("benches/bin/aarch32/bl1.elf"));
    // Set threads to one because of current MacOS problems
    env::set_var("RAYON_NUM_THREADS", "1");

    let mut group = c.benchmark_group("unicorn_performance");
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(50));
    group.sample_size(10);
    group.bench_function("single attack", |b| {
        b.iter(|| {
            attack.single_glitch(false, 1..=2);
        })
    });
    group.bench_function("double attack", |b| {
        b.iter(|| {
            attack.double_glitch(false, 1..=1);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

use criterion::{criterion_group, criterion_main, Criterion};
use unicorn_1::FaultAttacks;

fn criterion_benchmark(c: &mut Criterion) {
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("Content/bin/aarch32/bl1.elf"));

    c.bench_function("single attack", |b| {
        b.iter(|| {
            attack.single_glitch(false, 1..=10);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

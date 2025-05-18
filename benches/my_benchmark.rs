use criterion::{criterion_group, criterion_main, Criterion};
use fault_simulator::prelude::*;

fn criterion_benchmark(c: &mut Criterion) {
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_4.elf"),
        2000,
        false,
        false,
        15,
    )
    .unwrap();

    let mut group = c.benchmark_group("fault-attack_peformance");
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(50));
    group.sample_size(10);
    group.bench_function("single attack", |b| {
        b.iter(|| {
            let _ = attack.single(&mut vec!["glitch".to_string()].iter());
            let _ = attack.single(&mut vec!["glitch".to_string()].iter());
        })
    });
    group.bench_function("double attack", |b| {
        b.iter(|| {
            let _ = attack.double(&mut vec!["glitch".to_string()].iter());
            let _ = attack.double(&mut vec!["glitch".to_string()].iter());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

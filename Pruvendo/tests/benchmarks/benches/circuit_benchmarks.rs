//! Criterion benchmarks for DarkDex circuit
//!
//! Run with: cargo bench --manifest-path Pruvendo/tests/benchmarks/Cargo.toml

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
use halo2_base::halo2_proofs::{
    dev::MockProver,
    halo2curves::{
        bn256::Fr,
        secp256k1::{Fq, Secp256k1Affine},
    },
};
use halo2_base::halo2_proofs::halo2curves::group::Curve;
use rand::Rng;

const K: u32 = 18;

/// Generate valid circuit inputs
fn generate_valid_inputs() -> (Fq, Secp256k1Affine, Secp256k1Affine, Fr, Fr) {
    let g = Secp256k1Affine::generator();
    let sk_val: u64 = rand::thread_rng().gen_range(1..1_000_000);
    let sk = Fq::from(sk_val);
    let pk = (g * sk).to_affine();
    let token_type = Fr::from(rand::thread_rng().gen_range(0u64..1000));
    let private_note_sum = Fr::from(rand::thread_rng().gen_range(0u64..1_000_000));
    (sk, pk, g, token_type, private_note_sum)
}

/// Benchmark circuit creation
fn bench_circuit_creation(c: &mut Criterion) {
    let (sk, pk, g, token_type, private_note_sum) = generate_valid_inputs();

    c.bench_function("circuit_creation", |b| {
        b.iter(|| {
            black_box(DarkDexCircuit::<Fr>::new(
                Some(token_type),
                Some(private_note_sum),
                Some(sk),
                Some(pk),
                Some(g),
            ))
        })
    });
}

/// Benchmark MockProver run (constraint satisfaction check)
fn bench_mock_prover(c: &mut Criterion) {
    let (sk, pk, g, token_type, private_note_sum) = generate_valid_inputs();
    let circuit = DarkDexCircuit::<Fr>::new(
        Some(token_type),
        Some(private_note_sum),
        Some(sk),
        Some(pk),
        Some(g),
    );
    // Public inputs: [token_type, private_note_sum]
    let public_inputs = vec![vec![token_type, private_note_sum]];

    let mut group = c.benchmark_group("mock_prover");
    group.sample_size(10); // Reduce sample size due to slow operation
    group.measurement_time(std::time::Duration::from_secs(60));

    group.bench_function("run", |b| {
        b.iter(|| {
            let prover = MockProver::run(K, black_box(&circuit), public_inputs.clone()).unwrap();
            black_box(prover.verify())
        })
    });

    group.finish();
}

/// Benchmark with different secret key sizes
fn bench_varying_sk(c: &mut Criterion) {
    let g = Secp256k1Affine::generator();
    let token_type = Fr::from(1u64);
    let private_note_sum = Fr::from(1000u64);

    let mut group = c.benchmark_group("varying_sk");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(30));

    for sk_val in [1u64, 1000, 1_000_000, u32::MAX as u64] {
        let sk = Fq::from(sk_val);
        let pk = (g * sk).to_affine();
        let circuit = DarkDexCircuit::<Fr>::new(
            Some(token_type),
            Some(private_note_sum),
            Some(sk),
            Some(pk),
            Some(g),
        );
        let public_inputs = vec![vec![token_type, private_note_sum]];

        group.bench_with_input(BenchmarkId::from_parameter(sk_val), &sk_val, |b, _| {
            b.iter(|| {
                let prover = MockProver::run(K, black_box(&circuit), public_inputs.clone()).unwrap();
                black_box(prover.verify())
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_circuit_creation,
    bench_mock_prover,
    bench_varying_sk,
);
criterion_main!(benches);


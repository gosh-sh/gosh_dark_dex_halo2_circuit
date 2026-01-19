//! Fuzz target: Proof Replay Attack
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Тестирует что proof привязан к конкретным public inputs:
//! - Один proof НЕ должен работать для разных public inputs
//! - Проверяет context binding
//!
//! КРИТИЧЕСКИЙ БАГ если proof можно использовать повторно!

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
use halo2_base::halo2_proofs::dev::MockProver;
use common::{ensure_working_directory, compute_sk_commitment, compute_digest, CIRCUIT_K};

#[derive(Arbitrary, Debug)]
struct ReplayInput {
    sk_seed: u64,
    token1: u64,
    sum1: u64,
    token2: u64,
    sum2: u64,
}

fuzz_target!(|input: ReplayInput| {
    ensure_working_directory();

    if input.sk_seed == 0 {
        return;
    }

    let token1 = input.token1 % 1_000_000;
    let sum1 = input.sum1 % 1_000_000_000;

    let token2 = input.token2 % 1_000_000;
    let sum2 = input.sum2 % 1_000_000_000;

    // Skip если оба набора одинаковы
    if token1 == token2 && sum1 == sum2 {
        return;
    }

    let sk = Fr::from(input.sk_seed);
    let sk_commitment = compute_sk_commitment(sk);

    let token1_fr = Fr::from(token1);
    let sum1_fr = Fr::from(sum1);

    let token2_fr = Fr::from(token2);
    let sum2_fr = Fr::from(sum2);

    // Создаём circuit с первым набором данных
    let circuit1 = DarkDexCircuit::new(
        Some(token1_fr),
        Some(sum1_fr),
        Some(sk),
        Some(sk_commitment),
    );

    // Вычисляем правильный digest для первого набора
    let digest1 = compute_digest(sk, token1_fr, sum1_fr);
    let pub_inputs1 = vec![sum1_fr, token1_fr, digest1];

    // Проверяем что первый набор работает
    let prover1 = MockProver::run(CIRCUIT_K, &circuit1, vec![pub_inputs1]);
    if prover1.is_err() || prover1.as_ref().unwrap().verify().is_err() {
        return; // Первый набор невалиден, пропускаем
    }

    // Теперь пробуем REPLAY атаку:
    // Используем circuit1 с public inputs от второго набора

    // Вычисляем digest для второго набора
    let digest2 = compute_digest(sk, token2_fr, sum2_fr);
    let pub_inputs2 = vec![sum2_fr, token2_fr, digest2];

    // Пробуем тот же circuit с другими public inputs
    let prover_replay = MockProver::run(CIRCUIT_K, &circuit1, vec![pub_inputs2]);

    if let Ok(prover) = prover_replay {
        // ASSERTION: Replay ДОЛЖЕН FAIL
        // Circuit содержит token1/sum1, а public inputs token2/sum2
        assert!(
            prover.verify().is_err(),
            "REPLAY ATTACK POSSIBLE!\n\
             Circuit witness: token={}, sum={}\n\
             Public inputs: token={}, sum={}\n\
             Same sk_seed={}",
            token1, sum1,
            token2, sum2,
            input.sk_seed
        );
    }
});


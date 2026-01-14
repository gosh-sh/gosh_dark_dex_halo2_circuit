//! Fuzz target: Proof Replay Attack
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
use halo2_base::halo2_proofs::halo2curves::{
    secp256k1::{Fq, Secp256k1Affine},
    bn256::Fr,
    ff::PrimeField,
    group::Curve,
};
use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
use halo2_base::halo2_proofs::dev::MockProver;
use common::{ensure_working_directory, generate_valid_keypair, poseidon_hash, CIRCUIT_K};
use gosh_dark_dex_halo2_circuit::utils::{consume_uint128_10, consume_uint128_11};

#[derive(Arbitrary, Debug)]
struct ReplayInput {
    /// Original sk
    sk_seed: u64,
    /// Original token
    token1: u64,
    /// Original sum
    sum1: u64,
    /// Original vault
    vault1: u64,
    /// Replay token
    token2: u64,
    /// Replay sum
    sum2: u64,
    /// Replay vault
    vault2: u64,
}

/// Вычисляет digest
fn compute_digest(sk_seed: u64, pk: &Secp256k1Affine, token: Fr, sum: Fr, vault: Fr) -> Fr {
    let deposit_sum = token + sum + vault;
    
    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes()[22..]);
    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes()[22..]);
    
    let key_sum = (sk_seed as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2 
                  + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2;
    let key_sum_fr = Fr::from_u128(key_sum);
    
    poseidon_hash([key_sum_fr, deposit_sum])
}

fuzz_target!(|input: ReplayInput| {
    ensure_working_directory();
    
    if input.sk_seed == 0 {
        return;
    }
    
    let token1 = input.token1 % 1_000_000;
    let sum1 = input.sum1 % 1_000_000_000;
    let vault1 = input.vault1 % 1_000_000;
    
    let token2 = input.token2 % 1_000_000;
    let sum2 = input.sum2 % 1_000_000_000;
    let vault2 = input.vault2 % 1_000_000;
    
    // Skip если оба набора одинаковы
    if token1 == token2 && sum1 == sum2 && vault1 == vault2 {
        return;
    }
    
    let (sk, pk, g) = generate_valid_keypair(input.sk_seed);
    
    let token1_fr = Fr::from(token1);
    let sum1_fr = Fr::from(sum1);
    let vault1_fr = Fr::from(vault1);
    
    let token2_fr = Fr::from(token2);
    let sum2_fr = Fr::from(sum2);
    let vault2_fr = Fr::from(vault2);
    
    // Создаём circuit с первым набором данных
    let circuit1 = DarkDexCircuit::new(
        Some(token1_fr),
        Some(sum1_fr),
        Some(vault1_fr),
        Some(sk),
        Some(pk),
        Some(g),
    );
    
    // Вычисляем правильный digest для первого набора
    let digest1 = compute_digest(input.sk_seed, &pk, token1_fr, sum1_fr, vault1_fr);
    let pub_inputs1 = vec![sum1_fr, token1_fr, digest1];
    
    // Проверяем что первый набор работает
    let prover1 = MockProver::run(CIRCUIT_K, &circuit1, vec![pub_inputs1]);
    if prover1.is_err() || prover1.as_ref().unwrap().verify().is_err() {
        return; // Первый набор невалиден, пропускаем
    }
    
    // Теперь пробуем REPLAY атаку:
    // Используем circuit1 с public inputs от второго набора
    
    // Вычисляем digest для второго набора
    let digest2 = compute_digest(input.sk_seed, &pk, token2_fr, sum2_fr, vault2_fr);
    let pub_inputs2 = vec![sum2_fr, token2_fr, digest2];
    
    // Пробуем тот же circuit с другими public inputs
    let prover_replay = MockProver::run(CIRCUIT_K, &circuit1, vec![pub_inputs2]);
    
    if let Ok(prover) = prover_replay {
        // ASSERTION: Replay ДОЛЖЕН FAIL
        // Circuit содержит token1/sum1/vault1, а public inputs token2/sum2
        assert!(
            prover.verify().is_err(),
            "REPLAY ATTACK POSSIBLE!\n\
             Circuit witness: token={}, sum={}, vault={}\n\
             Public inputs: token={}, sum={}, vault={}\n\
             Same sk_seed={}",
            token1, sum1, vault1,
            token2, sum2, vault2,
            input.sk_seed
        );
    }
});


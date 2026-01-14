//! Fuzz target: Vault Zero Binding
//!
//! Тестирует влияние vault_rand_val = 0 на binding properties:
//! - При vault=0 два разных (token, sum) могут дать одинаковый deposit_sum?
//! - Проверяет ослабление binding при нулевом vault
//!
//! КРИТИЧЕСКИЙ БАГ если binding ослаблен!

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
use common::{ensure_working_directory, poseidon_hash, CIRCUIT_K};
use gosh_dark_dex_halo2_circuit::utils::{consume_uint128_10, consume_uint128_11};

#[derive(Arbitrary, Debug)]
struct VaultZeroInput {
    /// SK seed
    sk_seed: u64,
    /// Первый token
    token1: u64,
    /// Первый sum
    sum1: u64,
    /// Второй token - для проверки sum manipulation
    token2: u64,
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

fuzz_target!(|input: VaultZeroInput| {
    ensure_working_directory();
    
    if input.sk_seed == 0 {
        return;
    }
    
    let token1 = input.token1 % 1_000_000;
    let sum1 = input.sum1 % 1_000_000_000;
    let token2 = input.token2 % 1_000_000;
    
    // Skip if same token
    if token1 == token2 {
        return;
    }
    
    // Ключевой тест: При vault=0 проверяем что (token1, sum1) и (token2, sum2)
    // где sum2 = sum1 + token1 - token2 дают РАЗНЫЕ digests
    // (потому что token/sum связаны отдельно в public inputs)
    
    // Вычисляем sum2 такой что token1 + sum1 = token2 + sum2
    // sum2 = sum1 + token1 - token2
    // Это может overflow/underflow - обрабатываем
    if token1 < token2 && sum1 < (token2 - token1) {
        return; // underflow
    }
    let sum2 = if token1 >= token2 {
        sum1 + (token1 - token2)
    } else {
        sum1 - (token2 - token1)
    };
    
    let vault = 0u64;  // КЛЮЧЕВОЕ: vault = 0
    
    let sk = Fq::from(input.sk_seed);
    let g = Secp256k1Affine::generator();
    let pk = Secp256k1Affine::from(g * sk);
    
    let token1_fr = Fr::from(token1);
    let sum1_fr = Fr::from(sum1);
    let token2_fr = Fr::from(token2);
    let sum2_fr = Fr::from(sum2);
    let vault_fr = Fr::from(vault);
    
    // deposit_sum должен быть одинаковым!
    let deposit_sum1 = token1_fr + sum1_fr + vault_fr;
    let deposit_sum2 = token2_fr + sum2_fr + vault_fr;
    
    // Проверяем что deposit_sum одинаковы (это атака)
    assert_eq!(deposit_sum1, deposit_sum2, "deposit_sums should match for this attack");
    
    // Digests тоже будут одинаковы (key_sum тот же)
    let digest1 = compute_digest(input.sk_seed, &pk, token1_fr, sum1_fr, vault_fr);
    let digest2 = compute_digest(input.sk_seed, &pk, token2_fr, sum2_fr, vault_fr);
    
    // Они ДОЛЖНЫ быть равны (это часть атаки)
    assert_eq!(digest1, digest2, "digests should match for collision attack");
    
    // Теперь пробуем схему с (token1, sum1) но digest от (token2, sum2)
    // Это должно FAIL потому что token/sum связаны как отдельные public inputs
    
    let circuit = DarkDexCircuit::new(
        Some(token1_fr),  // В схему идёт token1
        Some(sum1_fr),    // В схему идёт sum1
        Some(vault_fr),
        Some(sk),
        Some(pk),
        Some(g),
    );
    
    // Public inputs с token1, sum1 но digest (который одинаков)
    let pub_inputs = vec![sum1_fr, token1_fr, digest2];
    
    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![pub_inputs]);
    
    if let Ok(prover) = prover {
        // Это ДОЛЖНО работать - digest одинаков, token/sum совпадают с circuit
        let verify_result = prover.verify();
        assert!(
            verify_result.is_ok(),
            "Expected circuit to accept matching inputs with same digest"
        );
    }
    
    // Теперь главный тест: пробуем использовать (token2, sum2) c circuit (token1, sum1)
    let pub_inputs_attack = vec![sum2_fr, token2_fr, digest1];  // Используем token2/sum2 в public
    
    let prover = MockProver::run(CIRCUIT_K, &circuit, vec![pub_inputs_attack]);
    
    if let Ok(prover) = prover {
        // ASSERTION: Это ДОЛЖНО FAIL - token/sum в circuit не совпадают с public inputs
        assert!(
            prover.verify().is_err(),
            "BINDING BUG! Circuit accepted mismatched token/sum!\n\
             Circuit: token1={}, sum1={}\n\
             Public: token2={}, sum2={}\n\
             vault=0 (zero binding attack)",
            token1, sum1, token2, sum2
        );
    }
});


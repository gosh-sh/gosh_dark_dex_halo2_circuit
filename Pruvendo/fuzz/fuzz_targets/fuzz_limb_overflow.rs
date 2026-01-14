//! Fuzz target: Limb Overflow
//!
//! Тестирует граничные случаи в 88-bit limb decomposition:
//! - Координаты pk с максимальными limb значениями
//! - Проверка корректности суммирования limbs
//! - Overflow в key_data_sum
//!
//! БАГ если limb arithmetic даёт неверные результаты!

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
use common::{ensure_working_directory, generate_valid_keypair, check_circuit, poseidon_hash};
use gosh_dark_dex_halo2_circuit::utils::{consume_uint128_10, consume_uint128_11};

#[derive(Arbitrary, Debug)]
struct LimbInput {
    /// SK seed - выбираем так чтобы pk имел интересные координаты
    sk_seed: u64,
    /// Множитель для создания больших sk значений
    sk_multiplier: u64,
    /// Token
    token: u64,
    /// Sum
    sum: u64,
    /// Vault
    vault: u64,
}

/// Проверяет что limb decomposition и сумма корректны
fn verify_limb_decomposition(pk: &Secp256k1Affine, sk_raw: u64) -> (u128, bool) {
    let pk_x_bytes = pk.x.to_bytes();
    let pk_y_bytes = pk.y.to_bytes();
    
    // Извлекаем limbs
    let pk_x_limb_0 = consume_uint128_11(&pk_x_bytes[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk_x_bytes[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk_x_bytes[22..]);
    
    let pk_y_limb_0 = consume_uint128_11(&pk_y_bytes[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk_y_bytes[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk_y_bytes[22..]);
    
    // Проверяем что каждый limb помещается в 88 бит
    let max_88_bit = 1u128 << 88;
    let limbs_valid = pk_x_limb_0 < max_88_bit
        && pk_x_limb_1 < max_88_bit
        && pk_x_limb_2 < max_88_bit
        && pk_y_limb_0 < max_88_bit
        && pk_y_limb_1 < max_88_bit
        && pk_y_limb_2 < max_88_bit;
    
    // Вычисляем сумму
    let key_sum = (sk_raw as u128)
        .wrapping_add(pk_x_limb_0)
        .wrapping_add(pk_x_limb_1)
        .wrapping_add(pk_x_limb_2)
        .wrapping_add(pk_y_limb_0)
        .wrapping_add(pk_y_limb_1)
        .wrapping_add(pk_y_limb_2);
    
    (key_sum, limbs_valid)
}

fuzz_target!(|input: LimbInput| {
    ensure_working_directory();
    
    if input.sk_seed == 0 {
        return;
    }
    
    // Создаём sk с большими значениями
    let sk_val = if input.sk_multiplier > 0 {
        input.sk_seed.saturating_mul(input.sk_multiplier)
    } else {
        input.sk_seed
    };
    
    // Skip если overflow привёл к 0
    if sk_val == 0 {
        return;
    }
    
    let (sk, pk, g) = generate_valid_keypair(sk_val);
    
    // Проверяем limb decomposition
    let (key_sum, limbs_valid) = verify_limb_decomposition(&pk, sk_val);
    
    // ASSERTION: Limbs должны быть валидны
    assert!(
        limbs_valid,
        "LIMB OVERFLOW! Limb exceeds 88 bits for sk_val={}",
        sk_val
    );
    
    // Проверяем что key_sum помещается в Fr (254 бита - много больше u128)
    // Это должно быть ok, но проверим
    let key_sum_fr = Fr::from_u128(key_sum);
    
    // Проверяем что digest вычисляется корректно
    let token = input.token % 1_000_000;
    let sum = input.sum % 1_000_000_000;
    let vault = input.vault % 1_000_000;
    
    let token_fr = Fr::from(token);
    let sum_fr = Fr::from(sum);
    let vault_fr = Fr::from(vault);
    
    let deposit_sum = token_fr + sum_fr + vault_fr;
    let digest = poseidon_hash([key_sum_fr, deposit_sum]);
    
    // Проверяем что схема работает с этими значениями
    let result = check_circuit(sk, pk, g, token, sum, vault, sk_val);
    
    // ASSERTION: Валидные входы должны проходить
    assert!(
        result.is_ok(),
        "Circuit rejected valid inputs with large sk!\n\
         sk_val = {}, key_sum = {}\n\
         Result: {:?}",
        sk_val, key_sum, result
    );
});


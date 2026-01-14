//! Fuzz target: Digest Collision Search
//!
//! Ищет коллизии в Poseidon digest:
//! - Два разных набора (token, sum, vault, key) дают одинаковый digest
//! - Проверяет collision resistance хэша
//!
//! КРИТИЧЕСКИЙ БАГ если найдена коллизия!

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
use common::{ensure_working_directory, poseidon_hash};
use gosh_dark_dex_halo2_circuit::utils::{consume_uint128_10, consume_uint128_11};

#[derive(Arbitrary, Debug, Clone)]
struct DigestInput {
    sk_seed: u64,
    token: u64,
    sum: u64,
    vault: u64,
}

#[derive(Arbitrary, Debug)]
struct CollisionInput {
    /// Первый набор входных данных
    input1: DigestInput,
    /// Второй набор входных данных  
    input2: DigestInput,
}

/// Вычисляет digest для заданных параметров
fn compute_digest(sk_seed: u64, token: u64, sum: u64, vault: u64) -> Fr {
    if sk_seed == 0 {
        return Fr::zero();
    }
    
    let sk = Fq::from(sk_seed);
    let g = Secp256k1Affine::generator();
    let pk = Secp256k1Affine::from(g * sk);
    
    let token_fr = Fr::from(token);
    let sum_fr = Fr::from(sum);
    let vault_fr = Fr::from(vault);
    
    let deposit_sum = token_fr + sum_fr + vault_fr;
    
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

/// Проверяет идентичны ли два набора входов
fn inputs_equal(a: &DigestInput, b: &DigestInput) -> bool {
    a.sk_seed == b.sk_seed && a.token == b.token && a.sum == b.sum && a.vault == b.vault
}

fuzz_target!(|input: CollisionInput| {
    ensure_working_directory();
    
    // Фильтруем невалидные входы
    if input.input1.sk_seed == 0 || input.input2.sk_seed == 0 {
        return;
    }
    
    // Пропускаем идентичные входы
    if inputs_equal(&input.input1, &input.input2) {
        return;
    }
    
    // Ограничиваем значения
    let token1 = input.input1.token % 1_000_000;
    let sum1 = input.input1.sum % 1_000_000_000;
    let vault1 = input.input1.vault % 1_000_000;
    
    let token2 = input.input2.token % 1_000_000;
    let sum2 = input.input2.sum % 1_000_000_000;
    let vault2 = input.input2.vault % 1_000_000;
    
    // Вычисляем digests
    let digest1 = compute_digest(input.input1.sk_seed, token1, sum1, vault1);
    let digest2 = compute_digest(input.input2.sk_seed, token2, sum2, vault2);
    
    // ASSERTION: Разные входы должны давать разные digests
    assert!(
        digest1 != digest2,
        "COLLISION FOUND!\n\
         Input 1: sk={}, token={}, sum={}, vault={}\n\
         Input 2: sk={}, token={}, sum={}, vault={}\n\
         Digest: {:?}",
        input.input1.sk_seed, token1, sum1, vault1,
        input.input2.sk_seed, token2, sum2, vault2,
        digest1
    );
});


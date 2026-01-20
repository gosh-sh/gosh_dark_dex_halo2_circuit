//! Fuzz target: Digest Collision Search
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Ищет коллизии в Poseidon digest:
//! - Два разных набора (sk, token, sum) дают одинаковый digest
//! - Проверяет collision resistance хэша
//!
//! КРИТИЧЕСКИЙ БАГ если найдена коллизия!
//!
//! CROSS-VALIDATION: использует compute_digest_verified для
//! независимой верификации через reference implementation.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use common::{ensure_working_directory, compute_digest_verified};

#[derive(Arbitrary, Debug, Clone)]
struct DigestInput {
    sk_seed: u64,
    token: u64,
    sum: u64,
}

#[derive(Arbitrary, Debug)]
struct CollisionInput {
    input1: DigestInput,
    input2: DigestInput,
}

/// Проверяет идентичны ли два набора входов
fn inputs_equal(a: &DigestInput, b: &DigestInput) -> bool {
    a.sk_seed == b.sk_seed && a.token == b.token && a.sum == b.sum
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

    // Используем полный диапазон u64 для лучшего покрытия
    let token1 = input.input1.token;
    let sum1 = input.input1.sum;
    let token2 = input.input2.token;
    let sum2 = input.input2.sum;

    // Вычисляем digests с CROSS-VALIDATION
    // compute_digest_verified сравнивает library с reference implementation
    let sk1 = Fr::from(input.input1.sk_seed);
    let sk2 = Fr::from(input.input2.sk_seed);

    let digest1 = compute_digest_verified(sk1, Fr::from(token1), Fr::from(sum1));
    let digest2 = compute_digest_verified(sk2, Fr::from(token2), Fr::from(sum2));

    // ASSERTION: Разные входы должны давать разные digests
    assert!(
        digest1 != digest2,
        "COLLISION FOUND!\n\
         Input 1: sk={}, token={}, sum={}\n\
         Input 2: sk={}, token={}, sum={}\n\
         Digest: {:?}",
        input.input1.sk_seed, token1, sum1,
        input.input2.sk_seed, token2, sum2,
        digest1
    );
});


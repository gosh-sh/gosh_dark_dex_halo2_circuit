//! Fuzz target: Digest Preimage Attacks
//!
//! Версия: poseidon_instead_of_ecc
//!
//! Проверяет: можно ли найти разные (sk', token', sum')
//! которые дают тот же Poseidon digest?
//!
//! Новая формула: digest = poseidon(sk_commitment, sum, token, sk)
//!
//! Ожидание: Poseidon collision resistant, не должно быть найдено
//!
//! CROSS-VALIDATION: использует compute_digest_verified для
//! независимой верификации через reference implementation.
//!
//! ОТЛИЧИЕ от fuzz_digest_collision:
//! - fuzz_digest_collision: ищет любые коллизии между двумя наборами inputs
//! - fuzz_digest_preimage: дополнительно проверяет PARTIAL COLLISIONS:
//!   - Разные sk, одинаковые token/sum → должны давать разные digests
//!   - Одинаковый sk, разные token/sum → должны давать разные digests
//!
//! Это тестирует binding свойства каждого компонента отдельно.

#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};

mod common;
use common::*;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

/// Input for digest preimage attack fuzzing
#[derive(Debug)]
struct DigestPreimageInput {
    // Original values
    sk1: u64,
    token1: u64,
    sum1: u64,
    // Attack values
    sk2: u64,
    token2: u64,
    sum2: u64,
}

impl<'a> Arbitrary<'a> for DigestPreimageInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, libfuzzer_sys::arbitrary::Error> {
        Ok(DigestPreimageInput {
            sk1: u.int_in_range(1..=u64::MAX)?,
            token1: u.arbitrary()?,
            sum1: u.arbitrary()?,
            sk2: u.int_in_range(1..=u64::MAX)?,
            token2: u.arbitrary()?,
            sum2: u.arbitrary()?,
        })
    }
}

fuzz_target!(|input: DigestPreimageInput| {
    ensure_working_directory();

    let sk1 = Fr::from(input.sk1);
    let sk2 = Fr::from(input.sk2);

    let token1 = Fr::from(input.token1);
    let token2 = Fr::from(input.token2);

    let sum1 = Fr::from(input.sum1);
    let sum2 = Fr::from(input.sum2);

    // Вычисляем digests с CROSS-VALIDATION
    let digest1 = compute_digest_verified(sk1, token1, sum1);
    let digest2 = compute_digest_verified(sk2, token2, sum2);

    // Проверяем collision
    if digest1 == digest2 {
        // Collision найдена! Проверяем что это не тривиальная (одинаковые входы)
        let same_inputs = (sk1 == sk2) && (token1 == token2) && (sum1 == sum2);

        if !same_inputs {
            // НАСТОЯЩАЯ COLLISION В POSEIDON!
            panic!(
                "POSEIDON COLLISION FOUND!\n\
                sk1={:?}, token1={:?}, sum1={:?}\n\
                sk2={:?}, token2={:?}, sum2={:?}\n\
                digest={:?}",
                input.sk1, input.token1, input.sum1,
                input.sk2, input.token2, input.sum2,
                digest1
            );
        }
    }

    // Проверка: разные sk но одинаковые token и sum
    if sk1 != sk2 && token1 == token2 && sum1 == sum2 {
        assert!(
            digest1 != digest2,
            "PARTIAL COLLISION: Same token/sum, different sk, same digest!"
        );
    }

    // Проверка: одинаковый sk но разные token или sum
    if sk1 == sk2 && (token1 != token2 || sum1 != sum2) {
        assert!(
            digest1 != digest2,
            "PARTIAL COLLISION: Same sk, different token/sum, same digest!"
        );
    }
});


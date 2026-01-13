//! Fuzz target: Extended soundness testing
//!
//! Расширенная проверка soundness: разные комбинации неверных значений.
//! Покрывает: wrong pk, wrong generator, wrong token, wrong sum.
//!
//! Находит: нарушения soundness при комбинациях невалидных входов.
//!
//! Запуск: cargo +nightly fuzz run fuzz_soundness_extended

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

mod common;
use common::*;

use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Secp256k1Affine};
use halo2_base::halo2_proofs::arithmetic::CurveAffine;

/// Типы нарушений soundness
#[derive(Debug, Arbitrary, Clone, Copy)]
enum SoundnessViolationType {
    WrongPk,
    WrongGenerator,
    WrongToken,
    WrongSum,
    WrongPkAndToken,
    WrongPkAndSum,
    WrongGeneratorAndToken,
    AllWrong,
}

/// Входные данные для расширенного soundness теста
#[derive(Debug, Arbitrary)]
struct ExtendedSoundnessInput {
    /// Тип нарушения
    violation_type: SoundnessViolationType,
    /// Seed для sk
    sk_seed: u64,
    /// Seed для wrong_sk (если нужен)
    wrong_sk_seed: u64,
    /// Правильный token
    correct_token: u64,
    /// Правильный sum
    correct_sum: u64,
    /// Неправильный token
    wrong_token: u64,
    /// Неправильный sum
    wrong_sum: u64,
    /// Множитель для wrong generator
    gen_multiplier: u64,
}

fuzz_target!(|input: ExtendedSoundnessInput| {
    // Фильтры
    if input.sk_seed == 0 || input.wrong_sk_seed == 0 {
        return;
    }
    if input.sk_seed == input.wrong_sk_seed {
        return; // pk будет верным
    }
    if input.gen_multiplier == 0 || input.gen_multiplier == 1 {
        return; // генератор не изменится
    }

    let token = input.correct_token % 1_000_000;
    let sum = input.correct_sum % 1_000_000_000;
    let w_token = input.wrong_token % 1_000_000;
    let w_sum = input.wrong_sum % 1_000_000_000;

    // Избегаем случайных совпадений
    if token == w_token && matches!(input.violation_type, 
        SoundnessViolationType::WrongToken | 
        SoundnessViolationType::WrongPkAndToken |
        SoundnessViolationType::WrongGeneratorAndToken |
        SoundnessViolationType::AllWrong) {
        return;
    }
    if sum == w_sum && matches!(input.violation_type,
        SoundnessViolationType::WrongSum |
        SoundnessViolationType::WrongPkAndSum |
        SoundnessViolationType::AllWrong) {
        return;
    }

    let g = Secp256k1Affine::generator();
    let sk = Fq::from(input.sk_seed);
    let correct_pk = Secp256k1Affine::from(g * sk);
    let wrong_sk = Fq::from(input.wrong_sk_seed);
    let wrong_pk = Secp256k1Affine::from(g * wrong_sk);
    let wrong_g = Secp256k1Affine::from(g * Fq::from(input.gen_multiplier % 1000 + 2));

    // Выбираем параметры в зависимости от типа нарушения
    let (use_pk, use_g, pub_token, pub_sum) = match input.violation_type {
        SoundnessViolationType::WrongPk => (wrong_pk, g, token, sum),
        SoundnessViolationType::WrongGenerator => (correct_pk, wrong_g, token, sum),
        SoundnessViolationType::WrongToken => (correct_pk, g, w_token, sum),
        SoundnessViolationType::WrongSum => (correct_pk, g, token, w_sum),
        SoundnessViolationType::WrongPkAndToken => (wrong_pk, g, w_token, sum),
        SoundnessViolationType::WrongPkAndSum => (wrong_pk, g, token, w_sum),
        SoundnessViolationType::WrongGeneratorAndToken => (correct_pk, wrong_g, w_token, sum),
        SoundnessViolationType::AllWrong => (wrong_pk, wrong_g, w_token, w_sum),
    };

    let result = check_circuit(
        sk, use_pk, use_g,
        token, sum,        // witness values
        pub_token, pub_sum // public inputs
    );

    // ASSERTION: Любое нарушение ДОЛЖНО быть отклонено
    assert!(
        result.is_err(),
        "SOUNDNESS VIOLATION! {:?} was accepted!\n\
         sk={}, wrong_sk={}, gen_mult={}\n\
         tokens: correct={}, wrong={}, used={}\n\
         sums: correct={}, wrong={}, used={}",
        input.violation_type,
        input.sk_seed, input.wrong_sk_seed, input.gen_multiplier,
        token, w_token, pub_token,
        sum, w_sum, pub_sum
    );
});

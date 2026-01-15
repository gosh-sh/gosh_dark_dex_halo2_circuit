//! Fuzz target: Constraint bypass attacks
//!
//! Проверяет: можно ли обойти проверку pk = sk * g разными способами?
//!
//! Покрывает сценарии:
//! - pk "близкий" к sk * g (off-by-one координаты)
//! - pk с частично верными координатами (x верный, y неверный)
//! - pk = sk * g' где g' ≠ g но близко к g
//!
//! Ожидание: scheme должна ОТКЛОНИТЬ все попытки
#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};

mod common;
use common::*;

use halo2_base::halo2_proofs::halo2curves::{
    bn256::Fr,
    secp256k1::{Fp, Fq, Secp256k1Affine},
    ff::{PrimeField, Field},
    CurveAffine,
};

/// Input for constraint bypass fuzzing
#[derive(Debug)]
struct ConstraintBypassInput {
    sk: u64,
    attack_type: u8,
    perturbation: u64,
}

impl<'a> Arbitrary<'a> for ConstraintBypassInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, libfuzzer_sys::arbitrary::Error> {
        Ok(ConstraintBypassInput {
            sk: u.int_in_range(1..=u64::MAX)?,
            attack_type: u.int_in_range(0..=5)?,
            perturbation: u.arbitrary()?,
        })
    }
}

fuzz_target!(|input: ConstraintBypassInput| {
    ensure_working_directory();
    
    // Генерируем валидную пару ключей
    let (sk, valid_pk, g) = generate_valid_keypair(input.sk);
    
    // Применяем разные атаки на pk
    let attack_pk = match input.attack_type {
        0 => {
            // Attack 0: Меняем x координату на 1 бит
            let mut x_bytes = valid_pk.x.to_bytes();
            let byte_idx = (input.perturbation as usize) % 32;
            let bit_idx = (input.perturbation as usize / 32) % 8;
            x_bytes[byte_idx] ^= 1 << bit_idx;
            // Пытаемся создать точку с изменённым x (может быть не на кривой)
            match Fp::from_repr(x_bytes).into_option() {
                Some(new_x) => {
                    // Вычисляем y^2 = x^3 + 7 и проверяем квадратность
                    let y_squared = new_x * new_x * new_x + Fp::from(7u64);
                    match y_squared.sqrt().into_option() {
                        Some(new_y) => Secp256k1Affine::from_xy(new_x, new_y).unwrap_or(valid_pk),
                        None => return, // Точка не на кривой, skip
                    }
                }
                None => return,
            }
        },
        1 => {
            // Attack 1: Меняем y координату на 1 бит (нарушаем уравнение кривой)
            let mut y_bytes = valid_pk.y.to_bytes();
            let byte_idx = (input.perturbation as usize) % 32;
            y_bytes[byte_idx] ^= 1;
            match Fp::from_repr(y_bytes).into_option() {
                Some(new_y) => Secp256k1Affine::from_xy(valid_pk.x, new_y).unwrap_or(valid_pk),
                None => return,
            }
        },
        2 => {
            // Attack 2: Используем -pk (negated point)
            let neg_y = -valid_pk.y;
            Secp256k1Affine::from_xy(valid_pk.x, neg_y).unwrap_or(valid_pk)
        },
        3 => {
            // Attack 3: pk = (sk+1) * g (off by one в sk)
            let sk_plus_one = Fq::from(input.sk.saturating_add(1));
            Secp256k1Affine::from(g * sk_plus_one)
        },
        4 => {
            // Attack 4: pk = sk * g' где g' = 2*g
            let g_doubled = Secp256k1Affine::from(g + g);
            Secp256k1Affine::from(g_doubled * sk)
        },
        _ => {
            // Attack 5: Random pk не связанный с sk
            let random_sk = Fq::from(input.perturbation);
            Secp256k1Affine::from(g * random_sk)
        },
    };
    
    // Если pk не изменился, skip
    if attack_pk == valid_pk {
        return;
    }
    
    // Проверяем что scheme отклоняет атаку
    let result = check_circuit(
        sk,
        attack_pk,  // Используем атакованный pk
        g,
        1,      // token
        1000,   // sum
        111,    // vault
        input.sk,
    );
    
    // Инвариант: с неверным pk scheme должна FAIL
    assert!(
        result.is_err(),
        "SOUNDNESS VIOLATION: Circuit accepted pk != sk * g! attack_type={}, sk={}, perturbation={}",
        input.attack_type,
        input.sk,
        input.perturbation
    );
});


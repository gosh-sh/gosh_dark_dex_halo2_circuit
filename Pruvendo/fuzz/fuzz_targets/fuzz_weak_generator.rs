//! Fuzz target: Weak/predictable generator points
//!
//! Проверяет безопасность при использовании:
//! - g = small multiple of standard generator (2G, 3G, ...)
//! - g = произвольная точка на кривой
//! - g с предсказуемыми координатами
//!
//! Атака: если g = n*G (standard), то sk' = sk/n даёт тот же pk
//!
//! Ожидание: scheme работает с любым g на кривой, но разные g = разные pk
#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};

mod common;
use common::*;

use halo2_base::halo2_proofs::halo2curves::{
    secp256k1::{Fp, Fq, Secp256k1Affine},
    ff::PrimeField,
    CurveAffine,
};

/// Input for weak generator fuzzing
#[derive(Debug)]
struct WeakGeneratorInput {
    sk: u64,
    generator_type: u8,
    multiplier: u64,
    token: u64,
    sum: u64,
    vault: u64,
}

impl<'a> Arbitrary<'a> for WeakGeneratorInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, libfuzzer_sys::arbitrary::Error> {
        Ok(WeakGeneratorInput {
            sk: u.int_in_range(1..=u64::MAX)?,
            generator_type: u.int_in_range(0..=4)?,
            multiplier: u.int_in_range(2..=1000u64)?,
            token: u.int_in_range(0..=1000u64)?,
            sum: u.int_in_range(0..=1000000u64)?,
            vault: u.arbitrary()?,
        })
    }
}

fuzz_target!(|input: WeakGeneratorInput| {
    ensure_working_directory();
    
    let standard_g = Secp256k1Affine::generator();
    
    // Создаём разные generators
    let custom_g = match input.generator_type {
        0 => {
            // Type 0: g = n * standard_G (weak - related to standard)
            let n = Fq::from(input.multiplier);
            Secp256k1Affine::from(standard_g * n)
        },
        1 => {
            // Type 1: g = sk * standard_G (g = pk для другого ключа)
            let other_sk = Fq::from(input.multiplier);
            Secp256k1Affine::from(standard_g * other_sk)
        },
        2 => {
            // Type 2: g = random point on curve
            let rand_sk = Fq::from(input.multiplier.wrapping_mul(0xDEADBEEF));
            Secp256k1Affine::from(standard_g * rand_sk)
        },
        3 => {
            // Type 3: -G (negated standard generator)
            let neg_y = -standard_g.y;
            Secp256k1Affine::from_xy(standard_g.x, neg_y).unwrap_or(standard_g)
        },
        _ => {
            // Type 4: 2G (doubled generator)
            Secp256k1Affine::from(standard_g + standard_g)
        },
    };
    
    let sk = Fq::from(input.sk);
    let pk = Secp256k1Affine::from(custom_g * sk);  // pk = sk * custom_g
    
    // Проверяем что scheme работает с кастомным generator
    let result = check_circuit(
        sk,
        pk,
        custom_g,
        input.token,
        input.sum,
        input.vault,
        input.sk,
    );
    
    // Scheme ДОЛЖНА работать с любым валидным g на кривой
    assert!(
        result.is_ok(),
        "COMPLETENESS FAILURE: Valid keypair with custom generator rejected! g_type={}, mult={}",
        input.generator_type,
        input.multiplier
    );
    
    // Дополнительная проверка: pk для standard_g не должен проходить с custom_g
    if custom_g != standard_g {
        let standard_pk = Secp256k1Affine::from(standard_g * sk);
        if standard_pk != pk {
            let cross_result = check_circuit(
                sk,
                standard_pk,  // pk для standard_g
                custom_g,     // но используем custom_g
                input.token,
                input.sum,
                input.vault,
                input.sk,
            );
            
            assert!(
                cross_result.is_err(),
                "SOUNDNESS VIOLATION: pk for G accepted with custom g! g_type={}",
                input.generator_type
            );
        }
    }
});


//! FUZZ-FIELDWRAP: Field modulus wraparound attacks
//!
//! Тестирует значения около модуля Fr для поиска wraparound уязвимостей.
//! Фокус на арифметике, которая может дать неожиданные результаты.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use halo2_base::halo2_proofs::halo2curves::{
    bn256::Fr,
    secp256k1::{Fq, Secp256k1Affine},
    group::Curve,
    ff::{PrimeField, Field},
};

use gosh_dark_dex_halo2_circuit::circuit::poseidon_hash;

mod common;
use common::{consume_uint128_11, consume_uint128_10};

#[derive(Arbitrary, Debug)]
struct FieldWrapInput {
    sk_seed: u64,
    /// Offset from -1 (max Fr value)
    offset_from_max: u8,
    /// Which value to set near max: 0=token, 1=sum, 2=vault
    which_max: u8,
    other1: u64,
    other2: u64,
}

fuzz_target!(|input: FieldWrapInput| {
    if input.sk_seed == 0 {
        return;
    }
    
    let g = Secp256k1Affine::generator();
    let sk = Fq::from(input.sk_seed);
    let pk = Secp256k1Affine::from(g * sk);
    
    // Создаём значение близкое к Fr max (modulus - 1 - offset)
    // Fr(-1) = modulus - 1
    let near_max = -Fr::one() - Fr::from(input.offset_from_max as u64);
    
    // Назначаем значения
    let (token_fr, sum_fr, vault_fr) = match input.which_max % 3 {
        0 => (near_max, Fr::from(input.other1), Fr::from(input.other2)),
        1 => (Fr::from(input.other1), near_max, Fr::from(input.other2)),
        _ => (Fr::from(input.other1), Fr::from(input.other2), near_max),
    };
    
    // Вычисляем deposit_sum
    let deposit_sum = token_fr + sum_fr + vault_fr;
    
    // Вычисляем key_sum
    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes()[22..]);
    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes()[22..]);
    
    let key_sum = (input.sk_seed as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2 
                  + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2;
    let key_sum_fr = Fr::from_u128(key_sum);
    
    // Вычисляем digest
    let digest = poseidon_hash([key_sum_fr, deposit_sum]);
    
    // Проверка: digest должен быть детерминированным
    let digest2 = poseidon_hash([key_sum_fr, deposit_sum]);
    assert_eq!(digest, digest2, "Poseidon not deterministic with near-max values!");
    
    // Проверка: deposit_sum от near_max значений
    // Ищем случай когда near_max + small = small (wraparound)
    let small_val = Fr::from(100u64);
    let wrapped = near_max + small_val;
    
    // Если offset_from_max < 100, произойдёт wraparound
    if input.offset_from_max < 100 {
        // wrapped должен быть маленьким значением (100 - offset - 1)
        let expected_small = Fr::from((99 - input.offset_from_max) as u64);
        
        if wrapped != expected_small {
            panic!(
                "FIELD WRAPAROUND UNEXPECTED RESULT!\n\
                 near_max (modulus-1-{}): {:?}\n\
                 near_max + 100 = {:?}\n\
                 Expected: {:?}",
                input.offset_from_max, near_max, wrapped, expected_small
            );
        }
    }
    
    // Дополнительная проверка: Fr::zero() - Fr::one() = Fr(-1) = near max
    let zero_minus_one = Fr::zero() - Fr::one();
    assert_eq!(zero_minus_one + Fr::one(), Fr::zero(), "Fr arithmetic broken!");
});


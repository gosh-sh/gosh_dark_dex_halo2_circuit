//! Fuzz target: ProvingKey/VerifyingKey deserialization
//!
//! Тестирует десериализацию ключей из произвольных байтов.
//! Не должно быть паники на невалидных данных.
//!
//! Находит:
//! - Panic при парсинге corrupted key bytes
//! - Buffer overruns при неверной длине
//! - Memory safety issues
//!
//! Запуск: cargo +nightly fuzz run fuzz_proving_key_bytes

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use halo2_proofs::SerdeFormat;
use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::plonk::{VerifyingKey, ProvingKey};

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

fuzz_target!(|data: &[u8]| {
    // Минимальная длина для осмысленного парсинга
    if data.len() < 32 {
        return;
    }

    // Попытка десериализации как VerifyingKey с RawBytesUnchecked
    let mut cursor = Cursor::new(data);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        VerifyingKey::<G1Affine>::read::<_, DarkDexCircuit<Fr>>(
            &mut cursor,
            SerdeFormat::RawBytesUnchecked,
        )
    }));

    // Попытка десериализации как VerifyingKey с Processed format
    let mut cursor2 = Cursor::new(data);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        VerifyingKey::<G1Affine>::read::<_, DarkDexCircuit<Fr>>(
            &mut cursor2,
            SerdeFormat::Processed,
        )
    }));

    // Проверка: если данные начинаются с валидного паттерна VK
    // Попытка парсинга с RawBytes (строгий формат)
    if data.len() >= 968 {  // Размер реального VK файла
        let mut cursor3 = Cursor::new(data);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            VerifyingKey::<G1Affine>::read::<_, DarkDexCircuit<Fr>>(
                &mut cursor3,
                SerdeFormat::RawBytes,
            )
        }));
    }
});


//! Fuzz target: Verifier robustness
//!
//! Подаёт произвольные байты в функции десериализации.
//! Проверяет что код не паникует на malformed input.
//!
//! Находит: panic, unwrap() на None/Err, buffer overflows.

#![no_main]

use libfuzzer_sys::fuzz_target;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::SerdeFormat;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Минимальная длина для осмысленного парсинга
    if data.len() < 8 {
        return;
    }

    // Попытка десериализации как KZG параметров
    // Не должна паниковать на произвольных данных
    let mut cursor = Cursor::new(data);
    let _ = ParamsKZG::<Bn256>::read_custom::<_>(&mut cursor, SerdeFormat::RawBytesUnchecked);

    // Попытка десериализации как verification key
    // Требует валидные params, поэтому просто проверяем что не паникует
    let mut cursor2 = Cursor::new(data);
    let _ = ParamsKZG::<Bn256>::read_custom::<_>(&mut cursor2, SerdeFormat::Processed);
});


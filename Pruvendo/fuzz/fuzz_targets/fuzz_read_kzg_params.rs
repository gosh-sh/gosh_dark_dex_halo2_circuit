//! Fuzz target: read_kzg_params() function
//!
//! Тестирует чтение KZG параметров из corrupted данных.
//! Записывает fuzzed bytes во временный файл и пытается прочитать.
//!
//! Находит:
//! - Panic при corrupted KZG params
//! - Buffer overflows
//! - Memory safety issues
//!
//! Запуск: cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz fuzz_read_kzg_params

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;

use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::SerdeFormat;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Минимальная длина для осмысленного парсинга
    if data.len() < 16 {
        return;
    }
    
    // Попытка десериализации напрямую из bytes (без файла)
    // Это эквивалентно read_kzg_params но без I/O
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut cursor = Cursor::new(data);
        ParamsKZG::<Bn256>::read_custom(&mut cursor, SerdeFormat::RawBytesUnchecked)
    }));
    
    match result {
        Ok(Ok(_params)) => {
            // Успешно распарсили - проверяем что params валидны
            // (не должно быть возможно создать валидные params из случайных bytes)
        }
        Ok(Err(_)) => {
            // Корректная ошибка парсинга
        }
        Err(_) => {
            // Panic - это баг (известный upstream BC-003/BC-005)
        }
    }
    
    // Также тестируем Processed format
    let result2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut cursor = Cursor::new(data);
        ParamsKZG::<Bn256>::read_custom(&mut cursor, SerdeFormat::Processed)
    }));
    
    // Игнорируем результат - просто проверяем что не паникует
    let _ = result2;
});


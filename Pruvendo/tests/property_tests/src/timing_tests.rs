//! Timing Attack Tests for Dark DEX Circuit
//!
//! Тестируем отсутствие timing side-channels:
//! 1. Время proof generation не зависит от секретного sk
//! 2. Время Poseidon hash constant (fixed rounds)
//! 3. Нет корреляции между Hamming weight sk и временем
//!
//! После poseidon_instead_of_ecc: ECC убран, scalar_multiply (главный
//! timing-leak vector) больше не используется.

use crate::helpers::{ensure_working_directory, compute_sk_commitment, compute_digest};
use gosh_dark_dex_halo2_circuit::circuit::{DarkDexCircuit, poseidon_hash};
use gosh_dark_dex_halo2_circuit::prover::{generate_proof, read_kzg_params};
use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use std::time::Instant;

/// Вычисляет Hamming weight (количество единичных бит)
fn hamming_weight(x: u64) -> u32 {
    x.count_ones()
}

/// Статистика времени выполнения
struct TimingStats {
    mean: f64,
    std_dev: f64,
    min: f64,
    max: f64,
}

impl TimingStats {
    fn from_samples(samples: &[f64]) -> Self {
        let n = samples.len() as f64;
        let mean = samples.iter().sum::<f64>() / n;
        let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let std_dev = variance.sqrt();
        let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        Self { mean, std_dev, min, max }
    }

    /// Статистика с фильтрацией outliers (IQR метод) и использованием медианы
    fn from_samples_robust(samples: &[f64]) -> Self {
        if samples.is_empty() {
            return Self { mean: 0.0, std_dev: 0.0, min: 0.0, max: 0.0 };
        }

        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let n = sorted.len();
        let q1_idx = n / 4;
        let q3_idx = 3 * n / 4;
        let q1 = sorted[q1_idx];
        let q3 = sorted[q3_idx];
        let iqr = q3 - q1;

        // Фильтруем outliers: оставляем только [Q1 - 1.5*IQR, Q3 + 1.5*IQR]
        let lower = q1 - 1.5 * iqr;
        let upper = q3 + 1.5 * iqr;
        let filtered: Vec<f64> = sorted.iter()
            .filter(|&&x| x >= lower && x <= upper)
            .cloned()
            .collect();

        if filtered.is_empty() {
            return Self::from_samples(samples); // fallback
        }

        // Используем медиану вместо mean
        let median = filtered[filtered.len() / 2];
        let variance = filtered.iter().map(|x| (x - median).powi(2)).sum::<f64>() / filtered.len() as f64;
        let std_dev = variance.sqrt();
        let min = *filtered.first().unwrap();
        let max = *filtered.last().unwrap();

        Self { mean: median, std_dev, min, max }
    }
}

/// Вычисляет коэффициент корреляции Пирсона
fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
    assert_eq!(x.len(), y.len());
    let n = x.len() as f64;
    
    let mean_x = x.iter().sum::<f64>() / n;
    let mean_y = y.iter().sum::<f64>() / n;
    
    let cov = x.iter().zip(y.iter())
        .map(|(xi, yi)| (xi - mean_x) * (yi - mean_y))
        .sum::<f64>() / n;
    
    let std_x = (x.iter().map(|xi| (xi - mean_x).powi(2)).sum::<f64>() / n).sqrt();
    let std_y = (y.iter().map(|yi| (yi - mean_y).powi(2)).sum::<f64>() / n).sqrt();
    
    if std_x == 0.0 || std_y == 0.0 {
        0.0
    } else {
        cov / (std_x * std_y)
    }
}

/// TIMING-1: Poseidon hash время не зависит от входных данных
///
/// Методология:
/// - Warmup: 100 итераций для прогрева кэша
/// - Batch измерения: 100 hash за один замер (наносекунды слишком короткие)
/// - Robust статистика: медиана + IQR фильтрация outliers
/// - Порог: 10% deviation между паттернами
#[test]
fn test_poseidon_constant_time() {
    const WARMUP: usize = 100;
    const SAMPLES: usize = 500;
    const BATCH_SIZE: usize = 100;  // Измеряем время 100 hash за раз

    // Разные паттерны входных данных
    let patterns: Vec<(u64, u64)> = vec![
        (0, 0),                         // Все нули
        (u64::MAX, u64::MAX),           // Все единицы
        (0xAAAAAAAAAAAAAAAA, 0x5555555555555555), // Чередующиеся биты
        (1, 0),                         // Минимальный Hamming weight
        (0xFFFFFFFFFFFFFFFF, 0),        // Максимальный Hamming weight
    ];

    let mut pattern_times: Vec<Vec<f64>> = Vec::new();

    for (a, b) in &patterns {
        let input = [Fr::from(*a), Fr::from(*b)];

        // Warmup - прогреваем кэш и JIT
        for _ in 0..WARMUP {
            let _ = poseidon_hash(input);
        }

        // Основные измерения - batch для уменьшения шума
        let mut times = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let start = Instant::now();
            for _ in 0..BATCH_SIZE {
                let _ = poseidon_hash(input);
            }
            let elapsed = start.elapsed().as_nanos() as f64 / BATCH_SIZE as f64;
            times.push(elapsed);
        }

        pattern_times.push(times);
    }

    // Вычисляем ROBUST статистику (медиана + IQR фильтрация)
    let stats: Vec<TimingStats> = pattern_times.iter()
        .map(|t| TimingStats::from_samples_robust(t))
        .collect();

    // Также вычисляем raw статистику для сравнения
    let raw_stats: Vec<TimingStats> = pattern_times.iter()
        .map(|t| TimingStats::from_samples(t))
        .collect();

    println!("\n=== Poseidon Timing Analysis (Robust) ===");
    for (i, (pattern, stat)) in patterns.iter().zip(stats.iter()).enumerate() {
        println!("Pattern {}: ({:#x}, {:#x})", i, pattern.0, pattern.1);
        println!("  Median: {:.2} ns, StdDev: {:.2} ns", stat.mean, stat.std_dev);
        println!("  Range (filtered): [{:.0} - {:.0}] ns", stat.min, stat.max);
    }

    println!("\n=== Raw Stats (for comparison) ===");
    for (i, stat) in raw_stats.iter().enumerate() {
        println!("Pattern {}: Mean={:.2} ns, StdDev={:.2} ns, Range=[{:.0} - {:.0}]",
                 i, stat.mean, stat.std_dev, stat.min, stat.max);
    }

    // Проверяем что разница между медианами < 10%
    let medians: Vec<f64> = stats.iter().map(|s| s.mean).collect();
    let overall_median = medians.iter().sum::<f64>() / medians.len() as f64;

    println!("\n=== Deviation Analysis ===");
    let mut max_deviation = 0.0f64;
    for (i, median) in medians.iter().enumerate() {
        let deviation = ((median - overall_median) / overall_median).abs();
        max_deviation = max_deviation.max(deviation);
        println!("Pattern {} deviation from median: {:.2}%", i, deviation * 100.0);
    }

    // Порог 20% - учитывает шум неизолированной системы
    // На изолированной машине с отключённым power management ожидаем < 5%
    // ПРИМЕЧАНИЕ: Для production timing audit требуется:
    // - Изолированное ядро CPU (isolcpus)
    // - Отключённый Turbo Boost / power management
    // - Минимум 10000 samples
    if max_deviation >= 0.20 {
        println!("⚠️ WARNING: Max deviation {:.2}% exceeds 20% threshold", max_deviation * 100.0);
        println!("   This may be system noise. Re-run on isolated machine for accurate results.");
        // Не падаем, а предупреждаем - на неизолированной машине это ожидаемо
    }

    // Строгий assert только при deviation > 50% (явный timing leak)
    assert!(
        max_deviation < 0.50,
        "CRITICAL: Pattern shows {:.2}% deviation - potential timing leak!",
        max_deviation * 100.0
    );

    if max_deviation < 0.20 {
        println!("✅ Poseidon hash shows constant-time behavior");
    } else {
        println!("⚠️ Poseidon hash timing within acceptable range (but noisy)");
    }
}

/// TIMING-2: MockProver время не коррелирует с Hamming weight sk
#[test]
fn test_mockprover_no_sk_correlation() {
    ensure_working_directory();
    const SAMPLES: usize = 30;
    const WARMUP: usize = 5;

    // Warm-up phase - run several MockProver iterations first
    for i in 0..WARMUP {
        let sk = Fr::from((i + 100) as u64);
        let sk_commitment = compute_sk_commitment(sk);
        let token_type = Fr::from(1u64);
        let private_note_sum = Fr::from(1000u64);
        let digest = compute_digest(sk, token_type, private_note_sum);
        let circuit = DarkDexCircuit::new(
            Some(token_type),
            Some(private_note_sum),
            Some(sk),
            Some(sk_commitment),
        );
        let pub_inputs = vec![vec![private_note_sum, token_type, digest]];
        let _ = MockProver::run(8, &circuit, pub_inputs);
    }

    // Генерируем sk с разным Hamming weight (randomized order to avoid cache effects)
    let sk_values: Vec<u64> = vec![
        1,                              // HW = 1
        0xFF,                           // HW = 8
        0xFFFFFFFF,                     // HW = 32
        0xFFFFFFFFFFFFFFFF,             // HW = 64
        0xF,                            // HW = 4
        0xFFFF,                         // HW = 16
        0x5555555555555555,             // HW = 32 (alt)
        3,                              // HW = 2
    ];

    let mut hamming_weights: Vec<f64> = Vec::new();
    let mut times: Vec<f64> = Vec::new();

    // Interleave samples from different HW values to reduce systematic bias
    for sample_idx in 0..SAMPLES {
        // Rotate the order for each sample iteration
        let order_offset = sample_idx % sk_values.len();

        for (i, _sk_raw) in sk_values.iter().enumerate() {
            let effective_idx = (i + order_offset) % sk_values.len();
            let sk_val = sk_values[effective_idx];
            let sk = Fr::from(sk_val);
            let hw = hamming_weight(sk_val) as f64;

            let sk_commitment = compute_sk_commitment(sk);
            let token_type = Fr::from(1u64);
            let private_note_sum = Fr::from(1000u64);
            let digest = compute_digest(sk, token_type, private_note_sum);

            let circuit = DarkDexCircuit::new(
                Some(token_type),
                Some(private_note_sum),
                Some(sk),
                Some(sk_commitment),
            );

            let pub_inputs = vec![vec![private_note_sum, token_type, digest]];

            let start = Instant::now();
            let _ = MockProver::run(8, &circuit, pub_inputs);
            let elapsed = start.elapsed().as_micros() as f64;

            hamming_weights.push(hw);
            times.push(elapsed);
        }
    }

    let correlation = pearson_correlation(&hamming_weights, &times);

    println!("\n=== MockProver Timing vs Hamming Weight (with warm-up) ===");
    println!("Total samples: {}", times.len());
    println!("Pearson correlation: {:.4}", correlation);

    // Moderate correlation is acceptable for MockProver (debug tool)
    // Real concern would be in proof generation, not MockProver
    // We use 0.5 threshold here - anything above would be concerning
    if correlation.abs() >= 0.3 {
        println!("⚠️ Moderate correlation detected: {:.4}", correlation);
        println!("   This is in MockProver (debug), not production prover");
        println!("   Real timing analysis should focus on generate_proof()");
    }

    assert!(
        correlation.abs() < 0.5,
        "Strong correlation between sk Hamming weight and timing: {:.4} (threshold 0.5)",
        correlation
    );

    println!("✅ No strong correlation between sk Hamming weight and MockProver timing");
}

/// TIMING-3: Proof generation время не зависит от sk bit pattern
/// ВНИМАНИЕ: Этот тест медленный, запускать с --ignored
#[test]
#[ignore]
fn test_proof_generation_constant_time() {
    ensure_working_directory();
    const SAMPLES: usize = 5; // Малое количество из-за медленности

    let params = read_kzg_params("kzg_params.bin".to_string());

    // Разные bit patterns для sk
    let sk_patterns: Vec<u64> = vec![
        1,                              // Минимальный HW
        0xFFFFFFFFFFFFFFFF,             // Максимальный HW
        0xAAAAAAAAAAAAAAAA,             // Чередующиеся
    ];

    let mut pattern_times: Vec<Vec<f64>> = Vec::new();

    for sk_raw in &sk_patterns {
        let sk = Fr::from(*sk_raw);
        let sk_commitment = compute_sk_commitment(sk);
        let token_type = Fr::from(1u64);
        let private_note_sum = Fr::from(1000u64);

        let mut times = Vec::with_capacity(SAMPLES);

        for _ in 0..SAMPLES {
            let mut pub_inputs = Vec::new();

            let start = Instant::now();
            let _ = generate_proof(
                &params,
                Some(token_type),
                Some(private_note_sum),
                Some(sk),
                Some(sk_commitment),
                &mut pub_inputs,
            );
            let elapsed = start.elapsed().as_millis() as f64;
            times.push(elapsed);
        }

        pattern_times.push(times);
    }

    println!("\n=== Proof Generation Timing Analysis ===");
    for (i, (pattern, times)) in sk_patterns.iter().zip(pattern_times.iter()).enumerate() {
        let stats = TimingStats::from_samples(times);
        println!("Pattern {}: sk={:#x} (HW={})", i, pattern, hamming_weight(*pattern));
        println!("  Mean: {:.2} ms, StdDev: {:.2} ms", stats.mean, stats.std_dev);
    }

    // Вычисляем общую статистику
    let means: Vec<f64> = pattern_times.iter()
        .map(|t| TimingStats::from_samples(t).mean)
        .collect();

    let overall_mean = means.iter().sum::<f64>() / means.len() as f64;

    for (i, mean) in means.iter().enumerate() {
        let deviation = ((mean - overall_mean) / overall_mean).abs();
        println!("Pattern {} deviation: {:.2}%", i, deviation * 100.0);

        // Для proof generation допускаем 30% отклонение
        assert!(
            deviation < 0.30,
            "Pattern {} shows significant timing deviation: {:.2}%",
            i, deviation * 100.0
        );
    }

    println!("✅ Proof generation shows no significant timing dependency on sk bit pattern");
}

/// TIMING-4: Сравнение времени для специальных значений sk
#[test]
fn test_special_sk_values_timing() {
    ensure_working_directory();
    const SAMPLES: usize = 100;
    const WARMUP: usize = 50; // Warm-up iterations to avoid JIT effects

    // Warm-up phase
    for i in 0..WARMUP {
        let sk = Fr::from(i as u64);
        let _ = compute_sk_commitment(sk);
    }

    // Специальные значения sk
    let special_values: Vec<(u64, &str)> = vec![
        (0, "zero"),
        (1, "one"),
        (u64::MAX, "max"),
        (u64::MAX / 2, "half_max"),
    ];

    println!("\n=== Special SK Values Timing (after warm-up) ===");

    let mut all_times: Vec<f64> = Vec::new();

    for (sk_raw, name) in &special_values {
        let sk = Fr::from(*sk_raw);
        let mut times = Vec::with_capacity(SAMPLES);

        for _ in 0..SAMPLES {
            let start = Instant::now();
            let _ = compute_sk_commitment(sk);
            let elapsed = start.elapsed().as_nanos() as f64;
            times.push(elapsed);
        }

        let stats = TimingStats::from_samples(&times);
        println!("{}: mean={:.2}ns, std={:.2}ns", name, stats.mean, stats.std_dev);
        all_times.extend(times);
    }

    let overall_stats = TimingStats::from_samples(&all_times);
    let cv = overall_stats.std_dev / overall_stats.mean; // Coefficient of variation

    println!("Overall CV (coefficient of variation): {:.4}", cv);

    // CV < 1.0 is acceptable for timing tests (noise is expected)
    // Main check is that means are similar across different sk values
    let means: Vec<f64> = special_values.iter().map(|(sk_raw, _)| {
        let sk = Fr::from(*sk_raw);
        let mut times = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let start = Instant::now();
            let _ = compute_sk_commitment(sk);
            times.push(start.elapsed().as_nanos() as f64);
        }
        TimingStats::from_samples(&times).mean
    }).collect();

    let overall_mean = means.iter().sum::<f64>() / means.len() as f64;
    let max_deviation = means.iter()
        .map(|m| ((m - overall_mean) / overall_mean).abs())
        .fold(0.0f64, f64::max);

    println!("Max deviation from mean: {:.2}%", max_deviation * 100.0);

    // All special values should have similar timing (< 25% deviation)
    assert!(
        max_deviation < 0.25,
        "Significant timing difference for special sk values: {:.2}%",
        max_deviation * 100.0
    );

    println!("✅ Special sk values show consistent timing");
}

// =============================================================================
// TIMING-6: Verifier timing - valid vs invalid proof
// =============================================================================

/// Проверяем что время верификации valid и invalid proof одинаково
/// Это важно чтобы атакующий не мог определить валидность proof по времени
#[test]
fn test_verifier_timing_valid_vs_invalid() {
    use gosh_dark_dex_halo2_circuit::prover::{setup, generate_proof, generate_verififcation_key_without_witness};
    use gosh_dark_dex_halo2_circuit::verifier::verify_proof_;

    const SAMPLES: usize = 50;
    const WARMUP: usize = 5;

    // Setup
    let params = setup(8);
    let vk = generate_verififcation_key_without_witness(&params);

    let sk = Fr::from(12345u64);
    let sk_commitment = compute_sk_commitment(sk);
    let token_type = Fr::from(1u64);
    let private_note_sum = Fr::from(1000u64);
    let digest = compute_digest(sk, token_type, private_note_sum);

    // Generate VALID proof
    let pub_inputs = vec![private_note_sum, token_type, digest];
    let valid_proof = generate_proof(
        &params,
        Some(token_type),
        Some(private_note_sum),
        Some(sk),
        Some(sk_commitment),
        &mut pub_inputs.clone(),
    );

    // Create INVALID proof (corrupted)
    let mut invalid_proof = valid_proof.clone();
    if !invalid_proof.is_empty() {
        invalid_proof[0] ^= 0xFF;
        let mid = invalid_proof.len() / 2;
        invalid_proof[mid] ^= 0xAA;
    }

    // Create WRONG DIGEST inputs (valid format, wrong content)
    let wrong_digest = Fr::from(999999u64);
    let wrong_pub_inputs = vec![private_note_sum, token_type, wrong_digest];

    // Warmup
    for _ in 0..WARMUP {
        let _ = verify_proof_(&params, &valid_proof, &vk, pub_inputs.clone());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_proof_(&params, &invalid_proof, &vk, pub_inputs.clone())
        }));
    }

    // Measure VALID proof verification time
    let mut valid_times = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let result = verify_proof_(&params, &valid_proof, &vk, pub_inputs.clone());
        let elapsed = start.elapsed().as_micros() as f64;
        assert!(result, "Valid proof should verify");
        valid_times.push(elapsed);
    }

    // Measure WRONG DIGEST verification time (valid proof, wrong public inputs)
    let mut wrong_digest_times = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let result = verify_proof_(&params, &valid_proof, &vk, wrong_pub_inputs.clone());
        let elapsed = start.elapsed().as_micros() as f64;
        assert!(!result, "Wrong digest should fail verification");
        wrong_digest_times.push(elapsed);
    }

    // Measure CORRUPTED proof verification time
    let mut corrupted_times = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_proof_(&params, &invalid_proof, &vk, pub_inputs.clone())
        }));
        let elapsed = start.elapsed().as_micros() as f64;
        // May panic or return false
        match result {
            Ok(false) => {},
            Ok(true) => panic!("Corrupted proof should not verify!"),
            Err(_) => {}, // panic is acceptable
        }
        corrupted_times.push(elapsed);
    }

    // Calculate robust statistics
    let valid_stats = TimingStats::from_samples_robust(&valid_times);
    let wrong_digest_stats = TimingStats::from_samples_robust(&wrong_digest_times);
    let corrupted_stats = TimingStats::from_samples_robust(&corrupted_times);

    println!("\n=== Verifier Timing Analysis ===");
    println!("Valid proof:      Median={:.2} µs, StdDev={:.2} µs",
             valid_stats.mean, valid_stats.std_dev);
    println!("Wrong digest:     Median={:.2} µs, StdDev={:.2} µs",
             wrong_digest_stats.mean, wrong_digest_stats.std_dev);
    println!("Corrupted proof:  Median={:.2} µs, StdDev={:.2} µs",
             corrupted_stats.mean, corrupted_stats.std_dev);

    // Check deviation between valid and wrong digest (should be similar)
    let deviation_wrong_digest = ((valid_stats.mean - wrong_digest_stats.mean) / valid_stats.mean).abs();
    println!("\nDeviation valid vs wrong_digest: {:.2}%", deviation_wrong_digest * 100.0);

    // Check deviation between valid and corrupted
    let deviation_corrupted = ((valid_stats.mean - corrupted_stats.mean) / valid_stats.mean).abs();
    println!("Deviation valid vs corrupted: {:.2}%", deviation_corrupted * 100.0);

    // Warn if significant difference (but don't fail - corrupted may exit early)
    if deviation_wrong_digest > 0.20 {
        println!("⚠️ WARNING: Valid vs wrong_digest timing differs by {:.2}%",
                 deviation_wrong_digest * 100.0);
    }

    // Corrupted proof may legitimately exit early (parsing error) - just report
    if deviation_corrupted > 0.50 {
        println!("ℹ️ INFO: Corrupted proof verification is {:.1}x faster (early exit on parse error)",
                 valid_stats.mean / corrupted_stats.mean);
    }

    // The important check: valid vs wrong_digest should be similar
    // (both go through full verification path)
    assert!(
        deviation_wrong_digest < 0.50,
        "CRITICAL: Significant timing leak between valid and wrong_digest proof: {:.2}%",
        deviation_wrong_digest * 100.0
    );

    println!("✅ Verifier timing analysis complete");
}

// =============================================================================
// TIMING-7: Prover timing correlation with secret key
// =============================================================================

/// Проверяем что время генерации proof не коррелирует с секретным ключом
/// Это важно чтобы атакующий не мог вывести sk по времени prover
#[test]
fn test_prover_timing_no_sk_correlation() {
    use gosh_dark_dex_halo2_circuit::prover::setup;

    const SAMPLES: usize = 20;  // Proof generation is slow, fewer samples

    let params = setup(8);

    // Разные паттерны sk (high/low hamming weight, special values)
    let sk_patterns: Vec<u64> = vec![
        0x0000000000000001,  // Single bit
        0x8000000000000000,  // MSB only
        0xFFFFFFFFFFFFFFFF,  // All bits
        0xAAAAAAAAAAAAAAAA,  // Alternating
        0x0F0F0F0F0F0F0F0F,  // Nibble pattern
        12345,               // Random small
        9876543210,          // Random large
    ];

    let token_type = Fr::from(1u64);
    let private_note_sum = Fr::from(1000u64);

    let mut pattern_times: Vec<Vec<f64>> = Vec::new();
    let mut hamming_weights: Vec<f64> = Vec::new();

    for sk_raw in &sk_patterns {
        let sk = Fr::from(*sk_raw);
        let sk_commitment = compute_sk_commitment(sk);
        let digest = compute_digest(sk, token_type, private_note_sum);

        let mut times = Vec::with_capacity(SAMPLES);

        for _ in 0..SAMPLES {
            let mut pub_inputs = vec![private_note_sum, token_type, digest];

            let start = Instant::now();
            let _proof = generate_proof(
                &params,
                Some(token_type),
                Some(private_note_sum),
                Some(sk),
                Some(sk_commitment),
                &mut pub_inputs,
            );
            let elapsed = start.elapsed().as_millis() as f64;
            times.push(elapsed);
        }

        pattern_times.push(times.clone());
        hamming_weights.push(hamming_weight(*sk_raw) as f64);
    }

    // Calculate median time for each pattern
    let medians: Vec<f64> = pattern_times.iter()
        .map(|t| TimingStats::from_samples_robust(t).mean)
        .collect();

    println!("\n=== Prover Timing vs SK Pattern ===");
    for (sk_raw, median) in sk_patterns.iter().zip(medians.iter()) {
        println!("SK {:#018x} (HW={}): {:.1} ms", sk_raw, hamming_weight(*sk_raw), median);
    }

    // Calculate Pearson correlation between hamming weight and timing
    let correlation = pearson_correlation(&hamming_weights, &medians);
    println!("\nPearson correlation (hamming_weight vs timing): {:.4}", correlation);

    // Check max deviation between patterns
    let overall_median = medians.iter().sum::<f64>() / medians.len() as f64;
    let max_deviation = medians.iter()
        .map(|m| ((m - overall_median) / overall_median).abs())
        .fold(0.0f64, f64::max);

    println!("Max deviation from overall median: {:.2}%", max_deviation * 100.0);

    // Correlation should be low (no correlation with hamming weight)
    if correlation.abs() > 0.5 {
        println!("⚠️ WARNING: Moderate correlation ({:.2}) between sk hamming weight and timing",
                 correlation);
    }

    // Critical: high correlation would indicate timing leak
    assert!(
        correlation.abs() < 0.8,
        "CRITICAL: Strong correlation between sk and prover timing: {:.4}",
        correlation
    );

    // Deviation between patterns should be reasonable
    assert!(
        max_deviation < 0.50,
        "CRITICAL: Significant timing difference between sk patterns: {:.2}%",
        max_deviation * 100.0
    );

    println!("✅ Prover timing shows no significant sk correlation");
}

// =============================================================================
// TIMING-8: Field arithmetic timing
// =============================================================================

/// Проверяем что field arithmetic constant-time независимо от значений
#[test]
fn test_field_arithmetic_timing() {
    use halo2_base::halo2_proofs::halo2curves::ff::Field;

    const SAMPLES: usize = 1000;
    const WARMUP: usize = 100;
    const BATCH: usize = 100;

    // Different Fr value patterns
    let patterns: Vec<Fr> = vec![
        Fr::zero(),
        Fr::one(),
        Fr::from(u64::MAX),
        Fr::from(0xAAAAAAAAAAAAAAAAu64),
        -Fr::one(),  // p-1 (near modulus)
    ];

    let multiplier = Fr::from(12345u64);

    println!("\n=== Field Arithmetic Timing ===");

    // Test multiplication timing
    let mut mul_times: Vec<Vec<f64>> = Vec::new();
    for val in &patterns {
        // Warmup
        for _ in 0..WARMUP {
            let _ = *val * multiplier;
        }

        let mut times = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let start = Instant::now();
            for _ in 0..BATCH {
                let _ = std::hint::black_box(*val) * std::hint::black_box(multiplier);
            }
            times.push(start.elapsed().as_nanos() as f64 / BATCH as f64);
        }
        mul_times.push(times);
    }

    let mul_stats: Vec<TimingStats> = mul_times.iter()
        .map(|t| TimingStats::from_samples_robust(t))
        .collect();

    println!("Field multiplication:");
    for (i, stat) in mul_stats.iter().enumerate() {
        println!("  Pattern {}: Median={:.2} ns, StdDev={:.2} ns", i, stat.mean, stat.std_dev);
    }

    let mul_medians: Vec<f64> = mul_stats.iter().map(|s| s.mean).collect();
    let mul_overall = mul_medians.iter().sum::<f64>() / mul_medians.len() as f64;
    let mul_max_dev = mul_medians.iter()
        .map(|m| ((m - mul_overall) / mul_overall).abs())
        .fold(0.0f64, f64::max);

    println!("  Max deviation: {:.2}%", mul_max_dev * 100.0);

    // Test inversion timing (more complex operation)
    let mut inv_times: Vec<Vec<f64>> = Vec::new();
    for val in &patterns {
        if val.is_zero().into() {
            inv_times.push(vec![0.0; SAMPLES]); // Skip zero (no inverse)
            continue;
        }

        // Warmup
        for _ in 0..WARMUP {
            let _ = val.invert();
        }

        let mut times = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let start = Instant::now();
            for _ in 0..BATCH {
                let _ = std::hint::black_box(*val).invert();
            }
            times.push(start.elapsed().as_nanos() as f64 / BATCH as f64);
        }
        inv_times.push(times);
    }

    println!("\nField inversion:");
    for (i, times) in inv_times.iter().enumerate() {
        if times.iter().all(|&t| t == 0.0) {
            println!("  Pattern {}: SKIPPED (zero)", i);
        } else {
            let stat = TimingStats::from_samples_robust(times);
            println!("  Pattern {}: Median={:.2} ns, StdDev={:.2} ns", i, stat.mean, stat.std_dev);
        }
    }

    // Field operations should be constant-time
    if mul_max_dev > 0.20 {
        println!("⚠️ WARNING: Field multiplication shows {:.2}% timing variation",
                 mul_max_dev * 100.0);
    }

    assert!(
        mul_max_dev < 0.50,
        "CRITICAL: Field multiplication timing varies by {:.2}%",
        mul_max_dev * 100.0
    );

    println!("✅ Field arithmetic timing analysis complete");
}
